<script setup>
import { ref, onMounted, nextTick } from 'vue'
import { chat, getHealth, listTools, listTraces, getTrace, diagnose } from './api.js'

const provider = ref('-')
const tools = ref([])
const input = ref('')
const loading = ref(false)
const messages = ref([
  { role: 'assistant', answer: '你好，我是麒麟安全智能运维助手。试试问我：磁盘还剩多少 / 内存占用 / 哪个进程最吃 CPU。也可以点右上角「一键体检」做根因分析。', trace: [] },
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
// 意图分类 → 标签类型
const intentTag = { white: 'success', gray: 'warning', black: 'danger' }
const intentText = { white: '白·只读放行', gray: '灰·需校验', black: '黑·已拦截' }

// ---- 思维链回放抽屉 ----
const replayOpen = ref(false)
const traceList = ref([])
const replayLoading = ref(false)
const activeTrace = ref(null)

// ---- 根因分析抽屉 ----
const diagOpen = ref(false)
const diagLoading = ref(false)
const diagReport = ref(null)

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
function fmtTime(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : ''
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
    messages.value.push({
      role: 'assistant', answer: data.answer, trace: data.trace || [],
      intent: data.intent, blocked: data.blocked, trace_id: data.trace_id,
    })
  } catch (e) {
    messages.value.push({ role: 'assistant', answer: '请求失败：' + (e.message || e), trace: [] })
  } finally {
    loading.value = false
    await scrollBottom()
  }
}

// 打开回放抽屉并拉取历史
async function openReplay() {
  replayOpen.value = true
  activeTrace.value = null
  replayLoading.value = true
  try {
    traceList.value = await listTraces(50)
  } finally {
    replayLoading.value = false
  }
}
async function loadTrace(id) {
  replayLoading.value = true
  try {
    activeTrace.value = await getTrace(id)
  } finally {
    replayLoading.value = false
  }
}

// 一键体检（根因分析）
async function runDiagnose() {
  diagOpen.value = true
  diagLoading.value = true
  diagReport.value = null
  try {
    diagReport.value = await diagnose('all', '/')
  } finally {
    diagLoading.value = false
  }
}
const sevType = { ok: 'success', warning: 'warning', critical: 'danger', unknown: 'info' }
</script>

<template>
  <el-container class="app">
    <el-header class="header">
      <div class="title">🐉 麒麟安全智能运维 Agent</div>
      <div class="meta">
        <el-tag size="small" type="success">LLM: {{ provider }}</el-tag>
        <el-tag size="small" type="info">工具: {{ tools.length }}</el-tag>
        <el-button size="small" @click="runDiagnose">🩺 一键体检</el-button>
        <el-button size="small" @click="openReplay">🔍 思维链回放</el-button>
      </div>
    </el-header>

    <el-main class="main">
      <div ref="scroller" class="stream">
        <div v-for="(m, i) in messages" :key="i" :class="['row', m.role]">
          <div class="bubble">
            <div v-if="m.role === 'assistant' && m.intent" class="tags">
              <el-tag size="small" :type="intentTag[m.intent] || 'info'">
                {{ intentText[m.intent] || m.intent }}
              </el-tag>
              <el-tag v-if="m.blocked" size="small" type="danger" effect="dark">护栏拦截</el-tag>
            </div>
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

    <!-- 思维链回放抽屉：左侧历史列表，右侧整条五段时间线 -->
    <el-drawer v-model="replayOpen" title="🔍 思维链回放（可追溯审计）" size="60%" direction="rtl">
      <div v-loading="replayLoading" class="replay">
        <div class="trace-list">
          <el-empty v-if="!traceList.length" description="暂无历史会话" />
          <div
            v-for="t in traceList"
            :key="t.trace_id"
            :class="['trace-item', { active: activeTrace && activeTrace.trace_id === t.trace_id }]"
            @click="loadTrace(t.trace_id)"
          >
            <div class="ti-head">
              <el-tag size="small" :type="intentTag[t.intent] || 'info'">{{ t.intent || '-' }}</el-tag>
              <el-tag v-if="t.blocked" size="small" type="danger">拦截</el-tag>
              <span class="ti-time">{{ fmtTime(t.created_at) }}</span>
            </div>
            <div class="ti-input">{{ t.user_input }}</div>
          </div>
        </div>
        <div class="trace-detail">
          <el-empty v-if="!activeTrace" description="点击左侧会话回放整条思维链" />
          <template v-else>
            <div class="td-meta">
              <b>trace_id：</b><code>{{ activeTrace.trace_id }}</code>
              <el-tag size="small" type="info" style="margin-left:8px">{{ activeTrace.llm_provider }}</el-tag>
            </div>
            <el-timeline>
              <el-timeline-item
                v-for="(s, j) in activeTrace.steps"
                :key="j"
                :color="stageColor[s.stage] || '#909399'"
                :timestamp="fmtTime(s.ts)"
              >
                <span class="stage">{{ s.stage }}</span>
                <pre class="detail">{{ pretty(s.detail) }}</pre>
              </el-timeline-item>
            </el-timeline>
          </template>
        </div>
      </div>
    </el-drawer>

    <!-- 根因分析抽屉 -->
    <el-drawer v-model="diagOpen" title="🩺 智能根因分析" size="50%" direction="rtl">
      <div v-loading="diagLoading">
        <el-alert v-if="diagReport" :title="diagReport.summary" type="info" :closable="false" style="margin-bottom:12px" />
        <el-card v-for="(r, i) in (diagReport ? diagReport.reports : [])" :key="i" class="diag-card" shadow="never">
          <template #header>
            <b>{{ r.topic }}</b>
            <el-tag size="small" :type="sevType[r.severity] || 'info'" style="margin-left:8px">{{ r.severity }}</el-tag>
          </template>
          <div v-for="(f, k) in r.findings" :key="'f'+k" class="diag-finding">· {{ f }}</div>
          <div v-if="r.large_files && r.large_files.length" class="diag-files">
            <div v-for="(lf, k) in r.large_files" :key="'lf'+k" class="diag-file">
              <el-tag size="small" :type="lf.class === 'critical' ? 'danger' : lf.class === 'cleanable' ? 'success' : 'info'">
                {{ lf.class }}
              </el-tag>
              <span class="lf-path">{{ lf.path }}</span>
              <span class="lf-size">{{ lf.size_mb }}MB</span>
            </div>
          </div>
          <div v-if="r.suggestions && r.suggestions.length" class="diag-sugg">
            <div v-for="(s, k) in r.suggestions" :key="'s'+k">{{ s }}</div>
          </div>
        </el-card>
      </div>
    </el-drawer>
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
.meta { display: flex; gap: 8px; align-items: center; }
.main { display: flex; flex-direction: column; background: #f5f7fa; padding: 16px; }
.stream { flex: 1; overflow-y: auto; padding-right: 8px; }
.row { display: flex; margin-bottom: 14px; }
.row.user { justify-content: flex-end; }
.bubble {
  max-width: 75%; background: #fff; border-radius: 10px; padding: 12px 14px;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
}
.row.user .bubble { background: #ecf5ff; }
.tags { display: flex; gap: 6px; margin-bottom: 6px; }
.text { white-space: pre-wrap; line-height: 1.6; }
.trace { margin-top: 8px; }
.stage { font-weight: 600; }
.detail {
  margin: 4px 0 0; padding: 8px; background: #f5f7fa; border-radius: 6px;
  font-size: 12px; white-space: pre-wrap; word-break: break-all;
}
.composer { display: flex; gap: 8px; margin-top: 12px; align-items: flex-end; }
.composer .el-textarea { flex: 1; }

/* 回放抽屉 */
.replay { display: flex; gap: 12px; height: 100%; }
.trace-list { width: 38%; overflow-y: auto; border-right: 1px solid #ebeef5; padding-right: 8px; }
.trace-item { padding: 8px; border-radius: 6px; cursor: pointer; margin-bottom: 6px; border: 1px solid #ebeef5; }
.trace-item:hover { background: #f5f7fa; }
.trace-item.active { background: #ecf5ff; border-color: #409EFF; }
.ti-head { display: flex; gap: 6px; align-items: center; }
.ti-time { font-size: 12px; color: #909399; margin-left: auto; }
.ti-input { margin-top: 4px; font-size: 13px; word-break: break-all; }
.trace-detail { flex: 1; overflow-y: auto; }
.td-meta { margin-bottom: 10px; font-size: 13px; }

/* 诊断抽屉 */
.diag-card { margin-bottom: 12px; }
.diag-finding { line-height: 1.7; }
.diag-files { margin: 8px 0; }
.diag-file { display: flex; gap: 8px; align-items: center; font-size: 13px; padding: 2px 0; }
.lf-path { word-break: break-all; }
.lf-size { color: #909399; margin-left: auto; white-space: nowrap; }
.diag-sugg { margin-top: 8px; padding: 8px; background: #f5f7fa; border-radius: 6px; font-size: 13px; white-space: pre-wrap; line-height: 1.7; }
</style>
