-- 1) 创建审计数据库（示例名 AuditDB）
IF DB_ID(N'AuditDB') IS NULL
BEGIN
    CREATE DATABASE AuditDB;
    -- 若需要分表文件组，请在这里创建文件组并文件（建议：按月/季度增加文件组）
END
GO

USE AuditDB;
GO

-- 2) 分区函数与方案（示例：按月分区，初始给出未来12个月边界）
-- 注意：部署时根据实际需要调整VALUES并为每个分区创建文件组
IF NOT EXISTS (SELECT * FROM sys.partition_functions WHERE name = 'pf_Audit_EventTime')
BEGIN
    CREATE PARTITION FUNCTION pf_Audit_EventTime (DATETIME)
    AS RANGE RIGHT FOR VALUES (
        '2026-10-01', '2026-11-01', '2026-12-01', '2027-01-01', '2027-02-01', '2027-03-01',
        '2027-04-01', '2027-05-01', '2027-06-01', '2027-07-01', '2027-08-01', '2027-09-01'
    );
END
GO

IF NOT EXISTS (SELECT * FROM sys.partition_schemes WHERE name = 'ps_Audit_EventTime')
BEGIN
    CREATE PARTITION SCHEME ps_Audit_EventTime
    AS PARTITION pf_Audit_EventTime
    ALL TO ([PRIMARY]); -- 生产建议映射到多个文件组
END
GO

-- 3) 审计主表（追加写入）
IF OBJECT_ID('dbo.AuditLogs') IS NULL
BEGIN
    CREATE TABLE dbo.AuditLogs
    (
        EventSequence BIGINT IDENTITY(1,1) NOT NULL, -- 用于保证顺序与分区索引
        EventId UNIQUEIDENTIFIER NOT NULL DEFAULT NEWID(), -- 唯一事件ID
        ActorAccount NVARCHAR(100) NOT NULL,
        ActorName NVARCHAR(200) NULL,
        ActorIp NVARCHAR(50) NULL,
        TargetAccount NVARCHAR(200) NULL,
        OperationType NVARCHAR(100) NOT NULL, -- 如 CreateAccount/DeleteAccount/EnableMFA...
        Description NVARCHAR(1000) NULL,
        OldValue NVARCHAR(MAX) NULL,
        NewValue NVARCHAR(MAX) NULL,
        EventTime DATETIME NOT NULL DEFAULT GETDATE(),
        Result NVARCHAR(50) NOT NULL, -- Success/Failure (可按组织要求扩展)
        SourceSystem NVARCHAR(200) NULL,
        LogHash VARBINARY(32) NOT NULL, -- SHA256
        PrevLogHash VARBINARY(32) NULL, -- SHA256 of previous row
        CONSTRAINT PK_AuditLogs_EventSequence PRIMARY KEY CLUSTERED (EventSequence, EventTime)
            ON ps_Audit_EventTime(EventTime) -- 将聚簇索引放到分区方案上
    );
END
GO

-- 4) 审计哈希校验/快照表（用于周期性快照或外部签名）
IF OBJECT_ID('dbo.AuditHashSnapshot') IS NULL
BEGIN
    CREATE TABLE dbo.AuditHashSnapshot
    (
        SnapshotId INT IDENTITY(1,1) PRIMARY KEY,
        SnapshotTime DATETIME NOT NULL DEFAULT GETDATE(),
        LastEventSequence BIGINT NOT NULL,
        LastEventId UNIQUEIDENTIFIER NOT NULL,
        LastHash VARBINARY(32) NOT NULL,
        Notes NVARCHAR(500) NULL
    );
END
GO

-- 5) 防止 UPDATE/DELETE 的触发器（在 DB 层阻止修改）
IF OBJECT_ID('dbo.trg_AuditLogs_PreventMod', 'TR') IS NULL
BEGIN
    CREATE TRIGGER dbo.trg_AuditLogs_PreventMod
    ON dbo.AuditLogs
    INSTEAD OF UPDATE, DELETE
    AS
    BEGIN
        RAISERROR('AuditLogs is append-only; UPDATE/DELETE are forbidden.', 16, 1);
        ROLLBACK TRANSACTION;
    END
END
GO

-- 6) 插入存储过程：在单事务内获取上条哈希，计算新哈希并插入 (使用表锁以保证链的一致性)
--    注意：HASHBYTES('SHA2_256', ...) 在 SQL Server 2012 可用；若不可用请改用 'SHA1'（安全性较弱）
IF OBJECT_ID('dbo.usp_InsertAuditLog', 'P') IS NOT NULL
    DROP PROCEDURE dbo.usp_InsertAuditLog;
GO

CREATE PROCEDURE dbo.usp_InsertAuditLog
    @ActorAccount NVARCHAR(100),
    @ActorName NVARCHAR(200),
    @ActorIp NVARCHAR(50),
    @TargetAccount NVARCHAR(200),
    @OperationType NVARCHAR(100),
    @Description NVARCHAR(1000),
    @OldValue NVARCHAR(MAX),
    @NewValue NVARCHAR(MAX),
    @EventTime DATETIME,
    @Result NVARCHAR(50),
    @SourceSystem NVARCHAR(200),
    @OutEventSequence BIGINT OUTPUT,
    @OutEventId UNIQUEIDENTIFIER OUTPUT,
    @OutLogHash VARBINARY(32) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @PrevHash VARBINARY(32);
    DECLARE @Concat NVARCHAR(MAX);
    DECLARE @NewHash VARBINARY(32);

    BEGIN TRANSACTION;
    -- 1) 锁表并读取最后一条哈希，保证链的连续性（TABLOCKX+HOLDLOCK）
    SELECT TOP 1 @PrevHash = LogHash
    FROM dbo.AuditLogs WITH (TABLOCKX, HOLDLOCK)
    ORDER BY EventSequence DESC;

    -- 2) 当 EventTime 为 NULL 时使用 GETDATE()
    IF @EventTime IS NULL SET @EventTime = GETDATE();

    -- 3) 拼接字段顺序必须与 C# 端一致：EventId(将在插入时生成)/ActorAccount/ActorName/ActorIp/TargetAccount/OperationType/Description/OldValue/NewValue/EventTime/Result/SourceSystem/PrevHash
    -- 先生成一个 EventId
    SET @OutEventId = NEWID();

    SET @Concat = 
        LOWER(CONVERT(NVARCHAR(36), @OutEventId)) + N'|' +
        ISNULL(@ActorAccount, N'') + N'|' + ISNULL(@ActorName, N'') + N'|' + ISNULL(@ActorIp, N'') + N'|' +
        ISNULL(@TargetAccount, N'') + N'|' + ISNULL(@OperationType, N'') + N'|' +
        ISNULL(@Description, N'') + N'|' + ISNULL(@OldValue, N'') + N'|' + ISNULL(@NewValue, N'') + N'|' +
        CONVERT(NVARCHAR(30), @EventTime, 121) + N'|' + ISNULL(@Result, N'') + N'|' + ISNULL(@SourceSystem, N'') + N'|';

    -- 将 PrevHash 转为十六进制字符串并拼入（或将二进制直接拼接）
    -- 为保证与 C# 端一致性，这里把 PrevHash 转为十六进制小写字符串（若 NULL 则空）
    IF @PrevHash IS NOT NULL
        SET @Concat = @Concat + LOWER(master.dbo.fn_varbintohexstr(@PrevHash));
    ELSE
        SET @Concat = @Concat + N'';

    -- 4) 计算 SHA256
    -- 如果 HASHBYTES 支持 SHA2_256 则使用它
    BEGIN TRY
        SET @NewHash = HASHBYTES('SHA2_256', @Concat);
    END TRY
    BEGIN CATCH
        -- 如果不支持 SHA2_256（极少数 2012 环境），退回到 SHA1（这里仅作兼容，建议运行环境支持 SHA2_256）
        SET @NewHash = HASHBYTES('SHA1', @Concat);
    END CATCH

    -- 5) 插入并返回新的 EventSequence / LogHash
    INSERT INTO dbo.AuditLogs
    (
        EventId, ActorAccount, ActorName, ActorIp, TargetAccount, OperationType, Description,
        OldValue, NewValue, EventTime, Result, SourceSystem, LogHash, PrevLogHash
    )
    VALUES
    (
        @OutEventId, @ActorAccount, @ActorName, @ActorIp, @TargetAccount, @OperationType, @Description,
        @OldValue, @NewValue, @EventTime, @Result, @SourceSystem, @NewHash, @PrevHash
    );

    SET @OutEventSequence = SCOPE_IDENTITY();
    SET @OutLogHash = @NewHash;

    COMMIT TRANSACTION;
END
GO

-- 7) 权限脚本：创建写入账号 (audit_writer) 与只读审计账号 (audit_reader)
-- 注意：部署时请修改密码并使用更严格的账号管理策略（建议使用域账号或证书/托管身份）
-- 创建登录与用户（示例使用 SQL 认证，生产请使用更安全的认证）
IF NOT EXISTS (SELECT * FROM sys.sql_logins WHERE name = 'audit_writer_login')
BEGIN
    CREATE LOGIN audit_writer_login WITH PASSWORD = 'Ch@ngeMe!2026';
END
GO
USE AuditDB;
GO
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'audit_writer')
BEGIN
    CREATE USER audit_writer FOR LOGIN audit_writer_login;
    -- 仅授予 INSERT 权限 和 执行插入存储过程的权限（如果使用存储过程）
    GRANT INSERT ON dbo.AuditLogs TO audit_writer;
    GRANT EXECUTE ON dbo.usp_InsertAuditLog TO audit_writer;
    DENY UPDATE ON dbo.AuditLogs TO audit_writer;
    DENY DELETE ON dbo.AuditLogs TO audit_writer;
END
GO

IF NOT EXISTS (SELECT * FROM sys.sql_logins WHERE name = 'audit_reader_login')
BEGIN
    CREATE LOGIN audit_reader_login WITH PASSWORD = 'ReadOnly!2026';
END
GO
USE AuditDB;
GO
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = 'audit_reader')
BEGIN
    CREATE USER audit_reader FOR LOGIN audit_reader_login;
    GRANT SELECT ON dbo.AuditLogs TO audit_reader;
    -- 禁止写入权限
    DENY INSERT ON dbo.AuditLogs TO audit_reader;
    DENY UPDATE ON dbo.AuditLogs TO audit_reader;
    DENY DELETE ON dbo.AuditLogs TO audit_reader;
END
GO

-- 8) （可选）为审计内部使用创建一个用于快照签名的执行账号（例如用于只执行 AuditHashSnapshot 的插入）
-- 根据安全策略再做细粒度授权
