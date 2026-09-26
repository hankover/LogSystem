等保合规审计日志系统 - 部署与使用说明（概览）

1. 部署顺序（严格顺序，便于权限配置）
   1) 在目标 SQL Server 上执行 sql_create_audit_db_and_objects.sql（创建 AuditDB、表、分区方案、存储过程、触发器）。
   2) 修改脚本中默认登录密码（audit_writer_login / audit_reader_login）为强密码，或替换为域登录。
   3) 根据生产磁盘/留存策略，调整分区函数 pf_Audit_EventTime 的分区边界并为每个分区创建对应文件组（提高性能/便于分区切换归档）。
   4) 若需要长期归档老分区，请使用 SWITCH 分区到归档库，然后备份并删除分区（遵循等保留存策略至少6个月，此示例支持按月分区便于清理）。

2. 业务系统接入（使用 C# SDK）
   - 将 AuditSDK 项目编译为类库 (.NET Framework 4.5) 并引用到用户中心/运维系统。
   - 在业务完成关键运维操作后，独立于业务事务调用 AuditClient.WriteEvent(...) 上报审计。
     示例：
       var client = new AuditClient(connStrForAuditWriter);
       var ev = new AuditEvent {
           ActorAccount = "ops1",
           ActorName = "Ops 张三",
           ActorIp = "10.0.0.5",
           TargetAccount = "user123",
           OperationType = "EnableMFA",
           Description = "运维开启用户双因子",
           OldValue = "MFA=Off",
           NewValue = "MFA=On",
           EventTime = DateTime.UtcNow,
           Result = "Success",
           SourceSystem = "UserCenter"
       };
       client.WriteEvent(ev);

   - 推荐：业务在写审计时使用专用的审计写入连接字符串（audit_writer），该账号仅拥有 INSERT + EXECUTE(usp_InsertAuditLog) 权限。

3. 审计人员访问（只读）
   - 管理后台使用 audit_reader 登录库（只读账号）进行查询、导出、完整性校验。
   - 审计人员切勿使用写入账号；写权限仅给能写入审计的服务器/服务账号（例如专门调用的中间件）。

4. 哈希链说明与完整性校验
   - 每条记录记录 PrevLogHash（前一条记录的 LogHash）与自身的 LogHash（SHA-256）。
   - 存储过程在插入时以表级锁读取上条 LogHash 并在同一事务内计算新哈希并写入，保证链的连续性。
   - 管理后台提供 VerifyChain 示例：按时间区间顺序读取记录并逐条使用相同拼接规则计算哈希并比对；若发现任何差异则认为链被篡改。
   - 推荐做法：定期（例如每小时或每天）在 AuditHashSnapshot 表中记录当前最后一条 EventSequence 与 LastHash，为离线签名或外部证据保全（可导出并用 HSM/CA 签名）。

5. 额外注意（安全与合规）
   - 审计写入不能与业务操作在同一事务中执行（否则业务回滚会影响审计或反之）。建议业务执行完成后再写审计。
   - 为防止管理员误操作，DB 层用触发器阻止 UPDATE/DELETE；但超级管理员仍可通过权限绕过，故应同时保留审计日志备份、日志快照与外部签名策略。
   - 日志导出/查看功能应做访问控制（审计人员角色），并做好操作审计（谁导出、何时导出也应记录到审计系统或独立审计表）。
   - 日志留存：等保三级至少6个月；建议在分区策略中保留至少6个月分区并定期备份到只读/冷存储供留证。

6. 建议改进（可选）
   - 在 AuditHashSnapshot 表对快照做数字签名（私钥签名）并外部保管公钥以便独立验证。
   - 将导出改为 XLSX（使用 ClosedXML 或 EPPlus），并对导出操作也写审计记录（谁导出）。
   - 可将审计写入接口放到独立服务（中间件）并限制网络/认证，仅允许业务系统调用该服务；该服务使用 audit_writer 登录 DB。

结束语
- 上述脚本与代码均兼容 .NET Framework 4.5 与 SQL Server 2012（注意 HASHBYTES('SHA2_256') 在部分 2012 版本需要补丁支持，脚本中已做好兼容回退说明）。部署时请根据实际环境做文件组/分区/账号/密码安全调整。
