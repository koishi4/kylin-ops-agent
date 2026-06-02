<script setup>
import { ref, computed, onMounted, nextTick } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { chat, getHealth, listTools, listTraces, getTrace, verifyTrace, diagnose, executeAction, getRules, reloadRules } from './api.js'

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
const intentTag = { white: 'success', gray: 'warning', black: 'danger', action: 'primary' }
const intentText = { white: '白·只读放行', gray: '灰·需校验', black: '黑·已拦截', action: '动作执行' }

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
  verifyResult.value = null   // 切换会话时清空上一条的校验结果
  try {
    activeTrace.value = await getTrace(id)
  } finally {
    replayLoading.value = false
  }
}
// 审计防篡改：校验当前回放会话的哈希链完整性（P1-3 可信审计 demo）
const verifyResult = ref(null)
const verifying = ref(false)
async function doVerify() {
  if (!activeTrace.value) return
  verifying.value = true
  try {
    verifyResult.value = await verifyTrace(activeTrace.value.trace_id)
  } finally {
    verifying.value = false
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

// ---- 受控安全清理（P0-3）：根因分析判定「可清理」的文件，用户点按 → 二次确认 → 经护栏执行 ----
const cleaning = ref('')  // 正在清理的路径，用于按钮 loading

// 日志类用 truncate（保留句柄），其余可清理文件用 rm
function actionFor(path) {
  return /\.log($|\.)/i.test(path) ? 'truncate_log' : 'clean_path'
}

async function safeClean(file) {
  const path = file.path
  const action = actionFor(path)
  cleaning.value = path
  try {
    // 第一步：dry_run 预览，拿到护栏裁决（绝不执行）
    const preview = await executeAction(action, { path }, { dryRun: true })
    if (preview.blocked) {
      // 即便根因分析判「可清理」，命令层护栏仍可能独立拦截（如 rm 落在 /var）——展示纵深防御
      await ElMessageBox.alert(
        `护栏拦截，未执行。\n命令：${preview.command || '-'}\n原因：${preview.reason}`,
        '⛔ 被安全护栏拦截', { type: 'error' })
      return
    }
    // 第二步：二次确认（展示将执行的命令与护栏放行结论）
    await ElMessageBox.confirm(
      `将执行：${preview.command}\n护栏结论：${preview.reason}\n确认安全清理？`,
      '⚠️ 二次确认', { type: 'warning', confirmedButtonText: '确认执行', cancelButtonText: '取消' })
    // 第三步：确认后真正执行（confirmed + 非 dry_run），全程记入思维链
    const res = await executeAction(action, { path }, { confirmed: true, dryRun: false })
    if (res.executed && res.ok) {
      ElMessage.success(`已安全清理：${path}（已记入思维链 ${res.trace_id?.slice(0, 8)}）`)
      await runDiagnose()  // 刷新报告，清理后大文件应消失/缩小
    } else if (res.blocked) {
      ElMessage.error(`护栏拦截：${res.reason}`)
    } else {
      ElMessage.warning(res.reason || '未执行')
    }
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') ElMessage.info('已取消')
  } finally {
    cleaning.value = ''
  }
}

// ---- 护栏规则库（P2-1 可配置化/热加载）----
const rulesOpen = ref(false)
const rulesLoading = ref(false)
const rulesReloading = ref(false)
const rulesData = ref(null)  // { count, source, errors, rules }
const riskType = { critical: 'danger', high: 'warning', medium: '', low: 'info' }
const actionType = { deny: 'danger', confirm: 'warning', allow: 'success' }
const catText = {
  delete: '删除', permission: '权限', disk: '磁盘',
  privilege: '提权', config: '配置', inject: '注入',
}

// ---- P2-4 规则可视化：分类筛选 + 风险筛选 + 关键词搜索 ----
const ruleCat = ref('all')     // all / delete / permission / disk / privilege / config / inject
const ruleRisk = ref('all')    // all / critical / high / medium / low
const ruleSearch = ref('')
const CATS = ['delete', 'permission', 'disk', 'privilege', 'config', 'inject']

// 每个分类的规则条数，做成带计数的筛选标签（答辩时「25 条规则一目了然」）
const catCounts = computed(() => {
  const all = (rulesData.value && rulesData.value.rules) || []
  const m = { all: all.length }
  for (const c of CATS) m[c] = all.filter(r => r.category === c).length
  return m
})

const filteredRules = computed(() => {
  const all = (rulesData.value && rulesData.value.rules) || []
  const kw = ruleSearch.value.trim().toLowerCase()
  return all.filter(r =>
    (ruleCat.value === 'all' || r.category === ruleCat.value) &&
    (ruleRisk.value === 'all' || r.risk === ruleRisk.value) &&
    (!kw || r.id.toLowerCase().includes(kw) || (r.description || '').toLowerCase().includes(kw)),
  )
})

async function openRules() {
  rulesOpen.value = true
  rulesLoading.value = true
  try {
    rulesData.value = await getRules()
  } finally {
    rulesLoading.value = false
  }
}

// 热加载：改完 rules.yaml 后点此即生效，无需重启后端（展示「插件化/可扩展」）
async function doReloadRules() {
  rulesReloading.value = true
  try {
    const res = await reloadRules()
    rulesData.value = res
    if (res.ok) {
      ElMessage.success(`规则已热加载：共 ${res.count} 条（来源 ${res.source}）`)
    } else {
      // 故障安全：坏配置不换入、维持原规则，把错误明确告知用户
      ElMessage.error(`配置校验未通过，已维持原规则（${res.count} 条）`)
    }
  } catch (e) {
    ElMessage.error('热加载失败：' + (e.message || e))
  } finally {
    rulesReloading.value = false
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
        <el-button size="small" @click="runDiagnose">🩺 一键体检</el-button>
        <el-button size="small" @click="openReplay">🔍 思维链回放</el-button>
        <el-button size="small" @click="openRules">🛡️ 规则库</el-button>
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
              <el-button size="small" :loading="verifying" style="margin-left:8px" @click="doVerify">🔒 校验完整性</el-button>
              <el-tag
                v-if="verifyResult"
                size="small"
                :type="verifyResult.valid ? 'success' : 'danger'"
                style="margin-left:8px"
              >
                {{ verifyResult.valid
                    ? `✓ 哈希链完整（${verifyResult.steps} 段）`
                    : `✗ 检测到篡改${verifyResult.broken_at != null ? '（断链于第 ' + verifyResult.broken_at + ' 段）' : ''}` }}
              </el-tag>
            </div>
            <div v-if="verifyResult" class="verify-reason">{{ verifyResult.reason }}</div>
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
              <!-- 仅「可清理」类给出安全清理入口，点按必经二次确认 + 护栏 -->
              <el-button
                v-if="lf.class === 'cleanable'"
                size="small" type="success" plain
                :loading="cleaning === lf.path"
                @click="safeClean(lf)"
              >安全清理</el-button>
            </div>
          </div>
          <div v-if="r.suggestions && r.suggestions.length" class="diag-sugg">
            <div v-for="(s, k) in r.suggestions" :key="'s'+k">{{ s }}</div>
          </div>
        </el-card>
      </div>
    </el-drawer>

    <!-- 护栏规则库抽屉（P2-1 可配置化/热加载）：规则即配置，改 rules.yaml → 热加载即生效 -->
    <el-drawer v-model="rulesOpen" title="🛡️ 安全护栏规则库（可配置 / 热加载）" size="58%" direction="rtl">
      <div v-loading="rulesLoading">
        <div class="rules-bar">
          <el-tag size="small" :type="rulesData && rulesData.source === 'yaml' ? 'success' : 'danger'">
            {{ rulesData && rulesData.source === 'yaml' ? '来源：rules.yaml' : '来源：红线兜底集（配置异常）' }}
          </el-tag>
          <el-tag size="small" type="info">共 {{ rulesData ? rulesData.count : 0 }} 条</el-tag>
          <el-button size="small" type="primary" plain :loading="rulesReloading" @click="doReloadRules">
            ♻️ 重新加载规则库
          </el-button>
          <span class="rules-hint">改 rules.yaml 后点此热加载，无需重启后端</span>
        </div>
        <el-alert
          v-if="rulesData && rulesData.errors && rulesData.errors.length"
          type="error" :closable="false" style="margin-bottom:10px"
          title="配置校验未通过——已维持原规则（故障安全，护栏不空窗）">
          <div v-for="(e, i) in rulesData.errors" :key="i" class="rules-err">· {{ e }}</div>
        </el-alert>

        <!-- P2-4 筛选：分类（带计数）+ 风险 + 关键词搜索 -->
        <div v-if="rulesData" class="rules-filter">
          <el-radio-group v-model="ruleCat" size="small">
            <el-radio-button value="all">全部 {{ catCounts.all }}</el-radio-button>
            <el-radio-button v-for="c in CATS" :key="c" :value="c">
              {{ catText[c] }} {{ catCounts[c] }}
            </el-radio-button>
          </el-radio-group>
          <div class="rules-filter2">
            <el-select v-model="ruleRisk" size="small" style="width:130px">
              <el-option label="全部风险" value="all" />
              <el-option label="critical" value="critical" />
              <el-option label="high" value="high" />
              <el-option label="medium" value="medium" />
              <el-option label="low" value="low" />
            </el-select>
            <el-input
              v-model="ruleSearch" size="small" clearable style="width:240px"
              placeholder="搜索规则 ID 或说明" />
            <span class="rules-hint">命中 {{ filteredRules.length }} 条</span>
          </div>
        </div>

        <el-table v-if="rulesData" :data="filteredRules" size="small" stripe height="calc(100vh - 240px)">
          <el-table-column prop="id" label="ID" width="92" />
          <el-table-column label="分类" width="72">
            <template #default="{ row }">{{ catText[row.category] || row.category }}</template>
          </el-table-column>
          <el-table-column label="风险" width="84" sortable :sort-by="row => ({critical:3,high:2,medium:1,low:0})[row.risk]">
            <template #default="{ row }">
              <el-tag size="small" :type="riskType[row.risk]">{{ row.risk }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="动作" width="84">
            <template #default="{ row }">
              <el-tag size="small" effect="plain" :type="actionType[row.action]">{{ row.action }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="description" label="说明" min-width="220" show-overflow-tooltip />
          <el-table-column prop="pattern" label="匹配正则" min-width="200" show-overflow-tooltip />
        </el-table>
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
.verify-reason { margin: -2px 0 10px; color: #909399; font-size: 12px; }

/* 诊断抽屉 */
.diag-card { margin-bottom: 12px; }
.diag-finding { line-height: 1.7; }
.diag-files { margin: 8px 0; }
.diag-file { display: flex; gap: 8px; align-items: center; font-size: 13px; padding: 2px 0; }
.lf-path { word-break: break-all; }
.lf-size { color: #909399; margin-left: auto; white-space: nowrap; }
.diag-sugg { margin-top: 8px; padding: 8px; background: #f5f7fa; border-radius: 6px; font-size: 13px; white-space: pre-wrap; line-height: 1.7; }

/* 规则库抽屉 */
.rules-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }
.rules-hint { font-size: 12px; color: #909399; }
.rules-err { font-size: 12px; line-height: 1.6; }
.rules-filter { margin-bottom: 10px; }
.rules-filter2 { display: flex; gap: 8px; align-items: center; margin-top: 8px; flex-wrap: wrap; }
</style>
