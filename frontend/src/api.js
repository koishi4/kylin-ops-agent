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

// 智能根因分析（评分④）
export async function diagnose(topic = 'all', path = '/') {
  const { data } = await http.get('/diagnose', { params: { topic, path } })
  return data
}
