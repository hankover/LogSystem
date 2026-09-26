using System;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace AuditSDK
{
    /// <summary>
    /// 简单的审计写入客户端（针对 SQL Server + usp_InsertAuditLog 存储过程）
    /// .NET Framework 4.5 兼容
    /// </summary>
    public class AuditClient
    {
        private readonly string _connectionString;

        public AuditClient(string connectionString)
        {
            if (string.IsNullOrEmpty(connectionString)) throw new ArgumentNullException("connectionString");
            _connectionString = connectionString;
        }

        /// <summary>
        /// 将审计事件写入数据库（通过存储过程，数据库端负责原子地读取上条哈希并写入新哈希）
        /// 此方法不在业务事务中执行，调用方应在业务逻辑完成后另起线程或直接调用（确保业务回滚不会回滚审计）
        /// </summary>
        public void WriteEvent(AuditEvent ev)
        {
            if (ev == null) throw new ArgumentNullException("ev");

            using (var conn = new SqlConnection(_connectionString))
            using (var cmd = new SqlCommand("dbo.usp_InsertAuditLog", conn))
            {
                cmd.CommandType = CommandType.StoredProcedure;
                // 参数与 SQL 存储过程一致
                cmd.Parameters.AddWithValue("@ActorAccount", (object)ev.ActorAccount ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@ActorName", (object)ev.ActorName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@ActorIp", (object)ev.ActorIp ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@TargetAccount", (object)ev.TargetAccount ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@OperationType", (object)ev.OperationType ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@Description", (object)ev.Description ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@OldValue", (object)ev.OldValue ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@NewValue", (object)ev.NewValue ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@EventTime", ev.EventTime == default(DateTime) ? (object)DBNull.Value : ev.EventTime);
                cmd.Parameters.AddWithValue("@Result", (object)ev.Result ?? DBNull.Value);
                cmd.Parameters.AddWithValue("@SourceSystem", (object)ev.SourceSystem ?? DBNull.Value);

                // 输出参数
                var pSeq = new SqlParameter("@OutEventSequence", SqlDbType.BigInt) { Direction = ParameterDirection.Output };
                cmd.Parameters.Add(pSeq);
                var pEventId = new SqlParameter("@OutEventId", SqlDbType.UniqueIdentifier) { Direction = ParameterDirection.Output };
                cmd.Parameters.Add(pEventId);
                var pHash = new SqlParameter("@OutLogHash", SqlDbType.VarBinary, 32) { Direction = ParameterDirection.Output };
                cmd.Parameters.Add(pHash);

                conn.Open();
                cmd.ExecuteNonQuery();

                // 读取返回值
                ev.EventSequence = pSeq.Value == DBNull.Value ? 0 : Convert.ToInt64(pSeq.Value);
                ev.EventId = pEventId.Value == DBNull.Value ? Guid.Empty : (Guid)pEventId.Value;
                ev.LogHash = pHash.Value == DBNull.Value ? null : (byte[])pHash.Value;
                // PrevHash 在此调用中不返回，若需要可在存储过程中返回 PrevHash 作为输出参数
            }
        }

        /// <summary>
        /// 本地计算事件哈希（用于校验或用于非原子写场景）。顺序必须与数据库端拼接顺序严格一致。
        /// 返回 32 字节 SHA256 哈希
        /// </summary>
        public static byte[] ComputeHashLocal(AuditEvent ev, byte[] prevHash)
        {
            // 字段顺序须与存储过程中的拼接一致：
            // EventId | ActorAccount | ActorName | ActorIp | TargetAccount | OperationType |
            // Description | OldValue | NewValue | EventTime (121 格式) | Result | SourceSystem | PrevHash(hex)
            var sb = new StringBuilder();
            var eventId = ev.EventId == Guid.Empty ? Guid.NewGuid() : ev.EventId;
            sb.Append(eventId.ToString().ToLower()).Append("|");
            sb.Append(ev.ActorAccount ?? "").Append("|");
            sb.Append(ev.ActorName ?? "").Append("|");
            sb.Append(ev.ActorIp ?? "").Append("|");
            sb.Append(ev.TargetAccount ?? "").Append("|");
            sb.Append(ev.OperationType ?? "").Append("|");
            sb.Append(ev.Description ?? "").Append("|");
            sb.Append(ev.OldValue ?? "").Append("|");
            sb.Append(ev.NewValue ?? "").Append("|");
            sb.Append(ev.EventTime.ToString("yyyy-MM-dd HH:mm:ss.fff")).Append("|");
            sb.Append(ev.Result ?? "").Append("|");
            sb.Append(ev.SourceSystem ?? "").Append("|");

            if (prevHash != null && prevHash.Length > 0)
            {
                sb.Append(ByteArrayToHexString(prevHash));
            }

            var raw = Encoding.Unicode.GetBytes(sb.ToString()); // 与 SQL NVARCHAR 的二进制编码一致（Unicode）
            using (var sha = new SHA256Managed())
            {
                return sha.ComputeHash(raw);
            }
        }

        private static string ByteArrayToHexString(byte[] arr)
        {
            var sb = new StringBuilder(arr.Length * 2);
            foreach (var b in arr) sb.AppendFormat("{0:x2}", b);
            return sb.ToString();
        }
    }
}
