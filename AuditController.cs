using System;
using System.IO;
using System.Web.Mvc;
using AuditSDK;

public class AuditController : Controller
{
    private readonly AuditRepository _repo;

    public AuditController()
    {
        // 从配置读取连接字符串（建议使用 audit_reader_login）
        var conn = System.Configuration.ConfigurationManager.ConnectionStrings["AuditDB"].ConnectionString;
        _repo = new AuditRepository(conn);
    }

    // 查询页面（返回分页数据）
    public ActionResult Index(DateTime? from, DateTime? to, string actorAccount, string operationType, int page = 1)
    {
        int total;
        var data = _repo.Query(from, to, actorAccount, operationType, page, 50, out total);
        ViewBag.Total = total;
        return View(data);
    }

    // 导出：将当前查询条件导出为 CSV
    public ActionResult Export(DateTime? from, DateTime? to, string actorAccount, string operationType)
    {
        int total;
        var data = _repo.Query(from, to, actorAccount, operationType, 1, 1000000, out total); // 注意：防止导出太多，生产应分页流式导出
        var ms = new MemoryStream();
        _repo.ExportToCsv(data, ms);
        ms.Position = 0;
        return File(ms, "text/csv", "AuditExport.csv");
    }

    // 完整性校验
    public ActionResult Verify(DateTime? from, DateTime? to)
    {
        if (!from.HasValue || !to.HasValue) return Content("请指定起始和结束时间");
        var errors = _repo.VerifyChain(from.Value, to.Value);
        if (errors.Count == 0) return Content("指定时间段内哈希链校验通过（未发现不一致）。");
        return Content("校验发现问题：\n" + string.Join("\n", errors));
    }
}
