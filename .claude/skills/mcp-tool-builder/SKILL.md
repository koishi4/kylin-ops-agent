---
name: mcp-tool-builder
description: 在为运维 Agent 新增或封装一个 MCP 工具（OS 感知、指标采集、运维动作）时使用。涵盖工具命名、参数 schema、只读/写分级、与护栏的对接方式、返回结构、测试要求。当任务涉及 lsof/netstat/journalctl/psutil/df/ss 等系统命令的工具化封装时触发。
---

# MCP 运维工具封装规范

## 何时用
要把一个系统能力（看进程、查端口、读日志、查磁盘、清理文件…）变成 Agent 能调用的 MCP Tool 时。

## 工具分级（必须标注）
每个工具用装饰器或元数据标注读写级别，护栏据此决定是否需要二次确认：
- `READONLY`：只读，不改变系统状态（如 list_processes、disk_usage）。默认放行。
- `MUTATING`：会改变系统状态（如 kill_process、clean_file）。必须经过护栏校验。
- `PRIVILEGED`：需要提权。默认拒绝，仅在显式授权 + 护栏放行后执行。

## 标准结构（每个工具一个文件，放 `backend/app/mcp_server/tools/`）

```python
from mcp.server.fastmcp import FastMCP
import psutil, subprocess, shlex

# 工具元数据：名称用动词_名词，snake_case
@mcp.tool()
def disk_usage(path: str = "/") -> dict:
    """查询指定路径的磁盘使用情况。READONLY。
    Args:
        path: 要查询的挂载点路径，默认根目录
    Returns:
        含 total/used/free/percent 的字典
    """
    u = psutil.disk_usage(path)
    return {
        "level": "READONLY",
        "path": path,
        "total_gb": round(u.total / 1e9, 2),
        "used_gb": round(u.used / 1e9, 2),
        "free_gb": round(u.free / 1e9, 2),
        "percent": u.percent,
    }
```

## 封装外部命令的安全方式
绝不用字符串拼接 + `shell=True`。用 `shlex` 拆分参数列表：

```python
def run_cmd(args: list[str], timeout: int = 10) -> dict:
    """所有外部命令必须经此函数，禁止裸 subprocess。"""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                            timeout=timeout, shell=False)  # shell=False 是底线
        return {"ok": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
```

## 必须封装的工具清单（对应评分①，越全分越高）
- 进程：list_processes（按 CPU/内存排序）、find_zombie_processes、process_detail(pid)
- 网络：list_connections（封装 ss/netstat）、check_port(port)、list_listening_ports
- 磁盘：disk_usage、find_large_files(path, top_n)、dir_size(path)
- 日志：query_journal（封装 journalctl，支持 unit/since/priority）、tail_log(path, lines)
- 文件句柄：list_open_files（封装 lsof，定位谁占用了文件/端口）
- 系统：system_load、memory_info、uptime_info、service_status(name)

## 返回结构统一
所有工具返回 dict，必含 `level` 字段。失败时返回 `{"ok": false, "error": "..."}`。
不要直接抛异常给 Agent，要返回结构化错误，便于 LLM 理解和根因分析。

## 与护栏对接
- READONLY 工具：注册时标记 auto_approve=True
- MUTATING/PRIVILEGED 工具：调用前必须经 `guardrail.check()`，返回放行才执行
- 工具被护栏拦截时，返回 `{"ok": false, "blocked": true, "reason": "..."}`

## 测试要求（直接进课程报告测试章节）
每个工具配 `tests/test_<tool>.py`：
- 正常路径：给合法参数，断言返回结构正确
- 边界：不存在的路径/pid，断言优雅返回错误而非崩溃
- 只读工具断言不产生副作用
用 pytest 参数化覆盖多个用例，测试用例表可直接导出到报告第5章。
