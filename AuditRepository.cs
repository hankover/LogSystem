using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AuditSDK
{
    public class AuditRepository
    {
        private readonly string _connectionString;
        public AuditRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        /// <summary>
        /// 根据多条件查询审计日志（分页）
        /// </summary>
        public List<AuditEvent> Query(DateTime? from, DateTime? to, string actorAccount, string operationType, int pageIndex, int pageSize, out int total)
        {
            var list = new List<AuditEvent>();
            total = 0;
            using (var conn = new SqlConnection(_connectionString))
            using (var cmd = new SqlCommand())
            {
                cmd.Connection = conn;
                // 简单分页与过滤示例（你可以换成存储过程或更复杂的条件）
                var where = new StringBuilder(" WHERE 1=1 ");
                if (from.HasValue) { where.Append(" AND EventTime >= @From "); cmd.Parameters.AddWithValue("@From", from.Value); }
                if (to.HasValue) { where.Append(" AND EventTime <= @To "); cmd.Parameters.AddWithValue("@To", to.Value); }
                if (!string.IsNullOrEmpty(actorAccount)) { where.Append(" AND ActorAccount = @ActorAccount "); cmd.Parameters.AddWithValue("@ActorAccount", actorAccount); }
                if (!string.IsNullOrEmpty(operationType)) { where.Append(" AND OperationType = @OperationType "); cmd.Parameters.AddWithValue("@OperationType", operationType); }

                // 获取总数
                cmd.CommandText = "SELECT COUNT(1) FROM dbo.AuditLogs " + where.ToString();
                conn.Open();
                total = Convert.ToInt32(cmd.ExecuteScalar());

                // 分页：使用 ROW_NUMBER
                int start = (pageIndex - 1) * pageSize + 1;
                int end = pageIndex * pageSize;
                cmd.Parameters.Clear();
                if (from.HasValue) cmd.Parameters.AddWithValue("@From", from.Value);
                if (to.HasValue) cmd.Parameters.AddWithValue("@To", to.Value);
                if (!string.IsNullOrEmpty(actorAccount)) cmd.Parameters.AddWithValue("@ActorAccount", actorAccount);
                if (!string.IsNullOrEmpty(operationType)) cmd.Parameters.AddWithValue("@OperationType", operationType);

                cmd.CommandText = $@"
                    WITH T AS (
                        SELECT *, ROW_NUMBER() OVER (ORDER BY EventSequence DESC) RN
                        FROM dbo.AuditLogs {where}
                    )
                    SELECT EventSequence, EventId, ActorAccount, ActorName, ActorIp, TargetAccount, OperationType, Description,
                           OldValue, NewValue, EventTime, Result, SourceSystem, LogHash, PrevLogHash
                    FROM T WHERE RN BETWEEN @Start AND @End
                    ORDER BY EventSequence DESC;
                ";
                cmd.Parameters.AddWithValue("@Start", start);
                cmd.Parameters.AddWithValue("@End", end);

                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var ev = new AuditEvent
                        {
                            EventSequence = reader.GetInt64(reader.GetOrdinal("EventSequence")),
                            EventId = reader.GetGuid(reader.GetOrdinal("EventId")),
                            ActorAccount = reader["ActorAccount"] as string,
                            ActorName = reader["ActorName"] as string,
                            ActorIp = reader["ActorIp"] as string,
                            TargetAccount = reader["TargetAccount"] as string,
                            OperationType = reader["OperationType"] as string,
                            Description = reader["Description"] as string,
                            OldValue = reader["OldValue"] as string,
                            NewValue = reader["NewValue"] as string,
                            EventTime = reader.GetDateTime(reader.GetOrdinal("EventTime")),
                            Result = reader["Result"] as string,
                            SourceSystem = reader["SourceSystem"] as string,
                            LogHash = reader["LogHash"] == DBNull.Value ? null : (byte[])reader["LogHash"],
                            PrevLogHash = reader["PrevLogHash"] == DBNull.Value ? null : (byte[])reader["PrevLogHash"]
                        };
                        list.Add(ev);
                    }
                }
            }
            return list;
        }

        /// <summary>
        /// 导出到 CSV（Excel 可打开），stream 写出
        /// </summary>
        public void ExportToCsv(IEnumerable<AuditEvent> events, Stream outputStream)
        {
            using (var sw = new StreamWriter(outputStream, Encoding.UTF8))
            {
                // 表头
                sw.WriteLine("EventSequence,EventId,EventTime,ActorAccount,ActorName,ActorIp,TargetAccount,OperationType,Result,Description,OldValue,NewValue,SourceSystem,LogHash,PrevLogHash");
                foreach (var ev in events)
                {
                    string logHashHex = ev.LogHash != null ? ByteArrayToHexString(ev.LogHash) : "";
                    string prevHashHex = ev.PrevLogHash != null ? ByteArrayToHexString(ev.PrevLogHash) : "";
                    // 简单 CSV 转义
                    string esc(string s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";

                    var line = string.Join(",",
                        ev.EventSequence,
                        esc(ev.EventId.ToString()),
                        esc(ev.EventTime.ToString("yyyy-MM-dd HH:mm:ss")),
                        esc(ev.ActorAccount),
                        esc(ev.ActorName),
                        esc(ev.ActorIp),
                        esc(ev.TargetAccount),
                        esc(ev.OperationType),
                        esc(ev.Result),
                        esc(ev.Description),
                        esc(ev.OldValue),
                        esc(ev.NewValue),
                        esc(ev.SourceSystem),
                        esc(logHashHex),
                        esc(prevHashHex)
                    );
                    sw.WriteLine(line);
                }
                sw.Flush();
            }
        }

        private static string ByteArrayToHexString(byte[] arr)
        {
            var sb = new StringBuilder(arr.Length * 2);
            foreach (var b in arr) sb.AppendFormat("{0:x2}", b);
            return sb.ToString();
        }

        /// <summary>
        /// 哈希链完整性校验：从某个时间范围按 EventSequence 升序读取并验证每条记录的 PrevLogHash/LogHash 连续性及数据哈希一致性
        /// 返回错误列表（若为空则链在该范围内一致）
        /// </summary>
        public List<string> VerifyChain(DateTime from, DateTime to)
        {
            var errors = new List<string>();

            var events = new List<AuditEvent>();
            using (var conn = new SqlConnection(_connectionString))
            using (var cmd = new SqlCommand("SELECT EventSequence, EventId, ActorAccount, ActorName, ActorIp, TargetAccount, OperationType, Description, OldValue, NewValue, EventTime, Result, SourceSystem, LogHash, PrevLogHash FROM dbo.AuditLogs WHERE EventTime >= @From AND EventTime <= @To ORDER BY EventSequence ASC", conn))
            {
                cmd.Parameters.AddWithValue("@From", from);
                cmd.Parameters.AddWithValue("@To", to);
                conn.Open();
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        events.Add(new AuditEvent
                        {
                            EventSequence = reader.GetInt64(reader.GetOrdinal("EventSequence")),
                            EventId = reader.GetGuid(reader.GetOrdinal("EventId")),
                            ActorAccount = reader["ActorAccount"] as string,
                            ActorName = reader["ActorName"] as string,
                            ActorIp = reader["ActorIp"] as string,
                            TargetAccount = reader["TargetAccount"] as string,
                            OperationType = reader["OperationType"] as string,
                            Description = reader["Description"] as string,
                            OldValue = reader["OldValue"] as string,
                            NewValue = reader["NewValue"] as string,
                            EventTime = reader.GetDateTime(reader.GetOrdinal("EventTime")),
                            Result = reader["Result"] as string,
                            SourceSystem = reader["SourceSystem"] as string,
                            LogHash = reader["LogHash"] == DBNull.Value ? null : (byte[])reader["LogHash"],
                            PrevLogHash = reader["PrevLogHash"] == DBNull.Value ? null : (byte[])reader["PrevLogHash"]
                        });
                    }
                }
            }

            byte[] prev = null;
            foreach (var ev in events)
            {
                // 1) 检查 PrevLogHash 是否等于当前 prev (从上次循环得到)
                if (ev.PrevLogHash != null && prev == null)
                {
                    errors.Add(string.Format("EventSeq {0}: PrevLogHash not null but no previous hash available.", ev.EventSequence));
                }
                if (ev.PrevLogHash == null && prev != null)
                {
                    errors.Add(string.Format("EventSeq {0}: PrevLogHash is null but previous hash exists (expected).", ev.EventSequence));
                }
                if (ev.PrevLogHash != null && prev != null)
                {
                    if (!AreEqual(ev.PrevLogHash, prev))
                    {
                        errors.Add(string.Format("EventSeq {0}: PrevHash mismatch.", ev.EventSequence));
                    }
                }

                // 2) 重新计算当前记录的哈希并与存储的 LogHash 比对
                var recomputed = ComputeHashForVerify(ev, ev.PrevLogHash);
                if (!AreEqual(recomputed, ev.LogHash))
                {
                    errors.Add(string.Format("EventSeq {0}: LogHash mismatch (data may be tampered).", ev.EventSequence));
                }

                prev = ev.LogHash;
            }

            return errors;
        }

        private static byte[] ComputeHashForVerify(AuditEvent ev, byte[] prevHash)
        {
            // 本方法的拼接规则须与存储过程相同
            var sb = new StringBuilder();
            sb.Append(ev.EventId.ToString().ToLower()).Append("|");
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
            if (prevHash != null && prevHash.Length > 0) sb.Append(ByteArrayToHexString(prevHash));
            var raw = Encoding.Unicode.GetBytes(sb.ToString());
            using (var sha = new SHA256Managed())
            {
                return sha.ComputeHash(raw);
            }
        }

        private static bool AreEqual(byte[] a, byte[] b)
        {
            if (ReferenceEquals(a, b)) return true;
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }
    }
}
