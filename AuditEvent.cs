using System;

namespace AuditSDK
{
    /// <summary>
    /// 审计事件实体
    /// </summary>
    public class AuditEvent
    {
        // 由数据库生成 EventId 可选地在客户端生成
        public Guid EventId { get; set; }

        // 操作人
        public string ActorAccount { get; set; }
        public string ActorName { get; set; }
        public string ActorIp { get; set; }

        // 被操作目标
        public string TargetAccount { get; set; }

        // 操作类型、描述、旧/新值
        public string OperationType { get; set; }
        public string Description { get; set; }
        public string OldValue { get; set; }
        public string NewValue { get; set; }

        // 事件时间（客户端可传，或让 DB 使用 GETDATE()）
        public DateTime EventTime { get; set; }

        // 操作结果：Success/Failure 等
        public string Result { get; set; }

        // 来源系统
        public string SourceSystem { get; set; }

        // 写入后由 DB 填充
        public long EventSequence { get; set; }
        public byte[] LogHash { get; set; }
        public byte[] PrevLogHash { get; set; }

        public AuditEvent()
        {
            EventId = Guid.Empty;
            EventTime = DateTime.UtcNow;
        }
    }
}
