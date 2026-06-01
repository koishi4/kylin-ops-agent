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
  return data // { answer, trace, tool_calls }
}
