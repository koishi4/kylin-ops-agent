import axios from 'axios'

// 经 vite 代理 /api → 后端；生产可改为完整后端地址
const http = axios.create({ baseURL: '/api', timeout: 60000 })

// P0-4 受控动作鉴权：若构建时注入了 VITE_OPERATOR_TOKEN，则给每个请求带上
// Authorization: Bearer <token>（后端 /action/execute 校验）。未注入则不带，走演示模式。
const OPERATOR_TOKEN = import.meta.env.VITE_OPERATOR_TOKEN || ''
if (OPERATOR_TOKEN) {
  http.interceptors.request.use((config) => {
    config.headers.Authorization = `Bearer ${OPERATOR_TOKEN}`
    return config
  })
}

export async function getHealth() {
  const { data } = await http.get('/health')
  return data
}

export async function listTools() {
  const { data } = await http.get('/tools')
  return data.tools
}

export async function chat(message) {
  const { data } = await http.post('/chat', { message })
  return data // { trace_id, answer, blocked, intent, trace, tool_calls }
}

// 执行链回放：列出历史会话
export async function listTraces(limit = 50) {
  const { data } = await http.get('/traces', { params: { limit } })
  return data.traces
}

// 执行链回放：按 trace_id 取完整五段
export async function getTrace(traceId) {
  const { data } = await http.get(`/traces/${traceId}`)
  return data
}

// 审计防篡改：校验哈希链完整性（P1-3）
export async function verifyTrace(traceId) {
  const { data } = await http.get(`/traces/${traceId}/verify`)
  return data // { valid, steps, broken_at, reason, head_hash }
}

// 智能根因分析（评分④）
export async function diagnose(topic = 'all', path = '/') {
  const { data } = await http.get('/diagnose', { params: { topic, path } })
  return data
}

// 受控 MUTATING 动作（P0-3）：白名单动作 → 语义校验 → 护栏 → 执行。
// 默认 dry_run/未确认时只返回护栏裁决预览，绝不真正执行。
export async function executeAction(action, params, { confirmed = false, authorized = false, dryRun = true } = {}) {
  const { data } = await http.post('/action/execute', {
    action, params, confirmed, authorized, dry_run: dryRun,
  })
  return data // { ok, executed, blocked, require_confirm, command, guard, precheck, reason, trace_id, ... }
}

// 护栏规则库（P2-1 可配置化）：列出当前规则 + 来源/校验状态
export async function getRules() {
  const { data } = await http.get('/guardrail/rules')
  return data // { count, source, errors, rules }
}

// 护栏规则库热加载：从 rules.yaml 重新读取并校验（不重启进程即生效）
export async function reloadRules() {
  const { data } = await http.post('/guardrail/rules/reload')
  return data // { ok, source, count, applied, errors, rules }
}

// 致命三要素 / Rule of Two 能力面板（P3-2）：每个工具/动作的三腿能力标签 + 结构性安全不变量
export async function getTrifecta() {
  const { data } = await http.get('/guardrail/trifecta')
  return data // { legend, tools:[{name, level, untrusted, sensitive, state_change, leg_count, legs}], invariant }
}

// MCP 工具供应链扫描（P3-4）：静态检测工具元数据里的投毒/影子/隐形载荷（不上传文件/凭据）
export async function getToolScan() {
  const { data } = await http.get('/guardrail/tool-scan')
  return data // { ok, scanned, flagged, tools:[{name, suspicious, max_severity, findings}], note }
}

// 命令护栏检测（P4-2）：对一条命令做「正则 + 路径 + AST 结构分析」三重裁决，只校验绝不执行。
// 用于前端「护栏检测台」做正则判定 / AST 结构分析两栏对比。
export async function checkCommand(command, { authorized = false, confirmed = false } = {}) {
  const { data } = await http.post('/guardrail/check', { command, authorized, confirmed })
  return data // { allowed, action, matched_rules, risk, reason, require_confirm, ast_findings }
}

// 执行沙箱演示（P4-3）：跑服务端预定义的无害吃资源命令，看「失控进程被沙箱掐死」。
export async function sandboxDemo(scenario = 'cpu') {
  const { data } = await http.get('/guardrail/sandbox-demo', { params: { scenario } })
  return data // { scenario, description, command, backend, limits, ok, sandbox_killed, limit_hit, ... }
}

// 漏洞情报检索（P1-1）：本地优先、可联网增强；把内核新漏洞的时效从训练问题变检索问题。
export async function vulnIntel({ component, cve, live = false } = {}) {
  const { data } = await http.get('/vuln-intel', { params: { component, cve, live } })
  return data // { feed_version, source, live, count, advisories:[{cve, aliases, modules, mitigations, ...}] }
}

// 内核 / 主机安全姿态检查（P1-2）：本机内核+已加载模块比对情报，命中给缓解建议（不自动执行）。
export async function checkPosture(live = false) {
  const { data } = await http.get('/posture', { params: { live } })
  return data // { severity, kernel, matches:[{cve, status, loaded_modules_hit, mitigations}], scope_note, ... }
}
