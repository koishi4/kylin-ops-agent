<script setup>
import { ref, onMounted, nextTick } from 'vue'
import { chat, getHealth, listTools } from './api.js'

const provider = ref('-')
const tools = ref([])
const input = ref('')
const loading = ref(false)
const messages = ref([
  { role: 'assistant', answer: '你好，我是麒麟安全智能运维助手。试试问我：磁盘还剩多少 / 内存占用 / 哪个进程最吃 CPU。', trace: [] },
])
const scroller = ref(null)

// trace 阶段 → Element Plus timeline 颜色，呼应「五段思维链」
const stageColor = {
  接收指令: '#909399',
  感知环境: '#409EFF',
  推理决策: '#E6A23C',
  安全校验: '#F56C6C',
  执行结果: '#67C23A',
}

onMounted(async () => {
  try {
    provider.value = (await getHealth()).llm_provider
    tools.value = await listTools()
  } catch (e) {
    provider.value = '后端未连接'
  }
})

function pretty(detail) {
  return typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2)
}

async function scrollBottom() {
  await nextTick()
  if (scroller.value) scroller.value.scrollTop = scroller.value.scrollHeight
}

async function send() {
  const text = input.value.trim()
  if (!text || loading.value) return
  messages.value.push({ role: 'user', answer: text })
  input.value = ''
  loading.value = true
  await scrollBottom()
  try {
    const data = await chat(text)
    messages.value.push({ role: 'assistant', answer: data.answer, trace: data.trace || [] })
  } catch (e) {
    messages.value.push({ role: 'assistant', answer: '请求失败：' + (e.message || e), trace: [] })
  } finally {
    loading.value = false
    await scrollBottom()
  }
}
</script>

<template>
  <el-container class="app">
    <el-header class="header">
      <div class="title">🐉 麒麟安全智能运维 Agent</div>
      <div class="meta">
        <el-tag size="small" type="success">LLM: {{ provider }}</el-tag>
        <el-tag size="small" type="info">工具: {{ tools.length }}</el-tag>
      </div>
    </el-header>

    <el-main class="main">
      <div ref="scroller" class="stream">
        <div v-for="(m, i) in messages" :key="i" :class="['row', m.role]">
          <div class="bubble">
            <div class="text">{{ m.answer }}</div>
            <el-collapse v-if="m.trace && m.trace.length" class="trace">
              <el-collapse-item :title="`🔍 思维链回放（${m.trace.length} 步）`" name="t">
                <el-timeline>
                  <el-timeline-item
                    v-for="(s, j) in m.trace"
                    :key="j"
                    :color="stageColor[s.stage] || '#909399'"
                  >
                    <span class="stage">{{ s.stage }}</span>
                    <pre class="detail">{{ pretty(s.detail) }}</pre>
                  </el-timeline-item>
                </el-timeline>
              </el-collapse-item>
            </el-collapse>
          </div>
        </div>
      </div>

      <div class="composer">
        <el-input
          v-model="input"
          type="textarea"
          :rows="2"
          resize="none"
          placeholder="用自然语言描述运维需求，回车发送（Shift+回车换行）"
          @keydown.enter.exact.prevent="send"
        />
        <el-button type="primary" :loading="loading" @click="send">发送</el-button>
      </div>
    </el-main>
  </el-container>
</template>

<style>
html, body, #app { height: 100%; margin: 0; }
.app { height: 100vh; }
.header {
  display: flex; align-items: center; justify-content: space-between;
  background: #1f2d3d; color: #fff;
}
.title { font-weight: 600; }
.meta { display: flex; gap: 8px; }
.main { display: flex; flex-direction: column; background: #f5f7fa; padding: 16px; }
.stream { flex: 1; overflow-y: auto; padding-right: 8px; }
.row { display: flex; margin-bottom: 14px; }
.row.user { justify-content: flex-end; }
.bubble {
  max-width: 75%; background: #fff; border-radius: 10px; padding: 12px 14px;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
}
.row.user .bubble { background: #ecf5ff; }
.text { white-space: pre-wrap; line-height: 1.6; }
.trace { margin-top: 8px; }
.stage { font-weight: 600; }
.detail {
  margin: 4px 0 0; padding: 8px; background: #f5f7fa; border-radius: 6px;
  font-size: 12px; white-space: pre-wrap; word-break: break-all;
}
.composer { display: flex; gap: 8px; margin-top: 12px; align-items: flex-end; }
.composer .el-textarea { flex: 1; }
</style>
