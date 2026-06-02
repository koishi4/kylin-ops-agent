import axios from 'axios'

// 经 vite 代理 /api → 后端；生产可改为完整后端地址
const http = axios.create({ baseURL: '/api', timeout: 60000 })

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

// 思维链回放：列出历史会话
export async function listTraces(limit = 50) {
  const { data } = await http.get('/traces', { params: { limit } })
  return data.traces
}

// 思维链回放：按 trace_id 取完整五段
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
