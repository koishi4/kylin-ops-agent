<script setup>
/**
 * 智能对话视图（评分①②）：自然语言运维主入口。
 * 一句话 → 意图分类 → 选 MCP 工具 → 中文作答，每条回复内联可展开的五段执行链。
 * 空态给「按场景分组」的引导问句，覆盖只读感知 / 危险命令拦截 / 根因三类，便于现场演示。
 */
import { ref, nextTick, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { chat, executeAction } from '../api.js'
import Icon from '../Icon.vue'
import TraceTimeline from '../TraceTimeline.vue'

const props = defineProps({ provider: { type: String, default: '-' } })

const input = ref('')
const loading = ref(false)
const messages = ref([])
const scroller = ref(null)
const openTrace = ref({})   // index -> 是否展开 trace
// 深度思考开关：on → 后端编排改用 DeepSeek 推理模型，把模型「思维链」入执行链回放，更慢但更可解释；
// off（默认）→ 用快速模型，秒级响应。把「是否深度思考」交给用户/评委按场景自选。
const deepThinking = ref(false)

// 意图 → 语义化样式
const INTENT = {
  white: { cls: 'ok', text: '只读放行' },
  gray: { cls: 'warn', text: '需安全校验' },
  black: { cls: 'bad', text: '已拦截' },
  action: { cls: 'info', text: '动作执行' },
}

// 引导问句（分组）：现场可一键发起，覆盖三类典型链路
const SUGGESTS = [
  { g: '只读感知', items: ['磁盘还剩多少空间？', '哪个进程最吃 CPU？', '当前内存占用情况'] },
  { g: '安全护栏', items: ['帮我执行 rm -rf /var/lib/mysql', '把 /etc/shadow 权限改成 777'] },
  { g: '根因分析', items: ['系统为什么这么卡？帮我定位根因'] },
]

const hasMsg = computed(() => messages.value.length > 0)

async function scrollBottom() {
  await nextTick()
  if (scroller.value) scroller.value.scrollTop = scroller.value.scrollHeight
}

async function send(text) {
  const msg = (text ?? input.value).trim()
  if (!msg || loading.value) return
  messages.value.push({ role: 'user', answer: msg })
  input.value = ''
  loading.value = true
  await scrollBottom()
  try {
    const data = await chat(msg, { deepThinking: deepThinking.value })
    messages.value.push({
      role: 'assistant', answer: data.answer, trace: data.trace || [],
      intent: data.intent, blocked: data.blocked, tainted: data.tainted,
      deep_thinking: data.deep_thinking, trace_id: data.trace_id, tool_calls: data.tool_calls || [],
    })
  } catch (e) {
    messages.value.push({ role: 'assistant', answer: '请求失败：' + (e.message || e), trace: [], error: true })
  } finally {
    loading.value = false
    await scrollBottom()
  }
}

// ── 受控动作面板（评分③）：把「白名单参数化动作」做成可操作演示 ──────────────────
// 流程：dry-run 预览护栏裁决 → 二次确认 → 经护栏执行 → 五段 trace 推回对话流留痕。
// 关键演示点：needAuth 动作未授权时，预览即被防线4 拦下；打开「授权」开关再预览即放行——
// 把「核心运维动作需显式授权运行」演成可交互的因果，而非口头保证。
const ACTIONS = [
  { key: 'restart_service', label: '重启服务', ic: 'refresh', group: '服务处置', auth: true,
    fields: [{ k: 'unit', label: '服务名 unit', ph: 'nginx', req: true }],
    hint: 'systemctl restart；关键单元(sshd/systemd/网络…)拒，且需显式授权(防线4)' },
  { key: 'reload_config', label: '重载配置', ic: 'refresh', group: '服务处置', auth: true,
    fields: [{ k: 'unit', label: '服务名 unit', ph: 'nginx', req: true }],
    hint: 'systemctl reload，不中断服务；关键单元拒，需授权' },
  { key: 'block_ip', label: '封禁来源 IP', ic: 'lock', group: '安全封禁', auth: true,
    fields: [{ k: 'ip', label: 'IP 地址', ph: '203.0.113.45', req: true }],
    hint: 'iptables DROP；拒网段/回环/当前 SSH 来源(防自锁)，需授权' },
  { key: 'clean_journal', label: '回收 journal 日志', ic: 'layers', group: '清理回收', auth: false,
    fields: [{ k: 'size', label: '按大小（如 200M）', ph: '200M' },
             { k: 'time', label: '或按时间（如 7d）', ph: '7d' }],
    hint: 'journalctl --vacuum；size/time 二选一，只删已轮转的旧日志' },
  { key: 'truncate_log', label: '清空日志文件', ic: 'layers', group: '清理回收', auth: false,
    fields: [{ k: 'path', label: '日志路径', ph: '/var/log/app/x.log', req: true }],
    hint: '仅「可清理」类日志，fd-safe 截断；关键/未知一律拒' },
  { key: 'clean_path', label: '清理单个文件', ic: 'search', group: '清理回收', auth: false,
    fields: [{ k: 'path', label: '文件路径', ph: '/tmp/junk.tmp', req: true }],
    hint: '仅单个可清理文件；命令仍过护栏（rm 落 /var 仍被 PATH-001 拦）' },
  { key: 'kill_process', label: '结束进程', ic: 'bolt', group: '进程', auth: true,
    fields: [{ k: 'pid', label: 'PID', ph: '12345', req: true },
             { k: 'signal', label: '信号（默认 SIGTERM）', ph: 'SIGTERM' }],
    hint: '禁 init/自身/关键服务；root 进程需授权' },
]
const ACTION_GROUPS = ['服务处置', '安全封禁', '清理回收', '进程']
const RISK_CLS = { critical: 'bad', high: 'warn', medium: 'warn', low: 'info' }

const drawer = ref(false)
const sel = ref(null)            // 选中的动作 meta
const form = ref({})             // 字段值
const authorized = ref(false)    // 显式授权（防线4）
const busy = ref(false)
const result = ref(null)         // 最近一次裁决 / 执行结果
const phase = ref('idle')        // idle | blocked | previewed | done

const actionsByGroup = (g) => ACTIONS.filter((a) => a.group === g)
const canPreview = computed(() => {
  if (!sel.value) return false
  if (sel.value.key === 'clean_journal') return !!(form.value.size || form.value.time)
  return sel.value.fields.filter((f) => f.req)
    .every((f) => (form.value[f.k] ?? '').toString().trim())
})
const verdict = computed(() => {
  const r = result.value
  if (!r) return null
  if (r.blocked) return { cls: 'bad', text: '⛔ 已拦截' }
  if (phase.value === 'done') return r.executed ? { cls: 'ok', text: '✓ 已执行' } : { cls: 'warn', text: '· 未执行' }
  return { cls: 'warn', text: '⚠ 待确认（dry-run 已通过护栏）' }
})

function openActions() { drawer.value = true }
function pickAction(a) {
  sel.value = a; form.value = {}; authorized.value = a.auth
  result.value = null; phase.value = 'idle'
}
function buildParams() {
  const p = {}
  for (const f of sel.value.fields) {
    const v = (form.value[f.k] ?? '').toString().trim()
    if (v) p[f.k] = v
  }
  return p
}
function errText(e) { return e?.response?.data?.detail || e?.message || String(e) }

async function preview() {
  if (!canPreview.value || busy.value) return
  busy.value = true; result.value = null
  try {
    const r = await executeAction(sel.value.key, buildParams(),
      { authorized: authorized.value, dryRun: true })
    result.value = r
    phase.value = r.blocked ? 'blocked' : 'previewed'
  } catch (e) { ElMessage.error('预览失败：' + errText(e)) }
  finally { busy.value = false }
}

async function confirmExec() {
  if (!sel.value || busy.value) return
  busy.value = true
  try {
    const r = await executeAction(sel.value.key, buildParams(),
      { confirmed: true, authorized: authorized.value, dryRun: false })
    result.value = r; phase.value = 'done'
    // 把动作的五段 trace 推回对话流——与对话留痕统一，复用 TraceTimeline 回放（评分⑤可追溯）
    messages.value.push({
      role: 'assistant', answer: r.reason || (r.executed ? '动作已执行。' : '未执行。'),
      trace: r.trace || [], intent: 'action', blocked: r.blocked,
      trace_id: r.trace_id, tool_calls: [],
    })
    if (r.executed && r.ok) ElMessage.success('已执行 · 链 ' + (r.trace_id || '').slice(0, 8))
    else if (r.blocked) ElMessage.error('护栏拦截：' + r.reason)
    else ElMessage.warning(r.reason || '未执行')
    drawer.value = false
    await scrollBottom()
  } catch (e) { ElMessage.error('执行失败：' + errText(e)) }
  finally { busy.value = false }
}
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="console" :size="20" /> 智能对话</div>
        <div class="view-sub">用自然语言运维 Linux：感知 → 推理 → 安全校验 → 留痕，每条回复可展开完整执行链。</div>
      </div>
      <div class="view-actions">
        <button class="btn-actions" @click="openActions">
          <Icon name="bolt" :size="15" /> 受控动作
        </button>
      </div>
    </div>

    <div ref="scroller" class="stream">
      <!-- 空态：引导问句 -->
      <div v-if="!hasMsg" class="welcome">
        <div class="wc-mark"><Icon name="console" :size="30" /></div>
        <div class="wc-title">你好，我是麒麟安全智能运维助手</div>
        <div class="wc-sub">说人话即可。我会选对工具拿真实数据，遇到危险操作会当场拦下并解释原因。</div>
        <div class="wc-groups">
          <div v-for="grp in SUGGESTS" :key="grp.g" class="wc-group">
            <div class="wc-glabel">{{ grp.g }}</div>
            <div class="wc-chips">
              <button v-for="q in grp.items" :key="q" class="wc-chip" @click="send(q)">{{ q }}</button>
            </div>
          </div>
        </div>
      </div>

      <!-- 对话流 -->
      <div v-for="(m, i) in messages" :key="i" :class="['row', m.role]">
        <div v-if="m.role === 'assistant'" class="avatar"><Icon name="guardrail" :size="16" /></div>
        <div class="bubble" :class="{ err: m.error }">
          <div v-if="m.role === 'assistant' && (m.intent || m.blocked || m.deep_thinking)" class="bubble-tags">
            <span v-if="m.intent" class="ichip" :class="(INTENT[m.intent] || {}).cls">
              {{ (INTENT[m.intent] || {}).text || m.intent }}
            </span>
            <span v-if="m.deep_thinking" class="ichip think">
              <Icon name="judge" :size="11" /> 深度思考
            </span>
            <span v-if="m.blocked" class="ichip bad solid">护栏拦截</span>
            <span v-if="m.tainted" class="ichip warn">☣ 污点输入·已隔离</span>
            <span v-for="t in m.tool_calls" :key="t.tool || t.name || t" class="ichip tool">
              <Icon name="bolt" :size="11" /> {{ t.tool || t.name || t }}
            </span>
          </div>
          <div class="text">{{ m.answer }}</div>
          <div v-if="m.trace && m.trace.length" class="trace-toggle">
            <button class="tt-btn" @click="openTrace[i] = !openTrace[i]">
              <Icon name="audit" :size="13" />
              {{ openTrace[i] ? '收起' : '展开' }}执行链 · {{ m.trace.length }} 段
              <code v-if="m.trace_id" class="tt-id">{{ m.trace_id.slice(0, 8) }}</code>
            </button>
            <div v-if="openTrace[i]" class="trace-wrap">
              <TraceTimeline :steps="m.trace" />
            </div>
          </div>
        </div>
      </div>

      <div v-if="loading" class="row assistant">
        <div class="avatar"><Icon name="guardrail" :size="16" /></div>
        <div class="bubble thinking"><span /><span /><span /></div>
      </div>
    </div>

    <div class="composer">
      <div class="composer-bar">
        <button class="think-toggle" :class="{ on: deepThinking }"
                @click="deepThinking = !deepThinking"
                :title="deepThinking ? '点击关闭：改用快速模型' : '点击开启：用推理模型并展示思维链'">
          <Icon name="judge" :size="14" />
          深度思考
          <span class="tg-state" :class="{ on: deepThinking }">{{ deepThinking ? 'ON' : 'OFF' }}</span>
        </button>
        <span class="think-hint">{{ deepThinking
          ? 'DeepSeek 推理模型 · 执行链回放展示完整思维链，响应更慢'
          : 'DeepSeek 快速模型 · 低延迟秒级响应' }}</span>
      </div>
      <div class="composer-row">
        <el-input
          v-model="input" type="textarea" :rows="2" resize="none"
          placeholder="用自然语言描述运维需求，回车发送（Shift+回车换行）"
          @keydown.enter.exact.prevent="send()" />
        <button class="send-btn" :disabled="loading || !input.trim()" @click="send()">
          <Icon name="send" :size="18" />
        </button>
      </div>
    </div>

    <!-- 受控动作面板：白名单参数化处置 → dry-run 预览裁决 → 二次确认 → 经护栏执行 → 留痕 -->
    <el-drawer v-model="drawer" title="受控动作 · 白名单参数化处置" size="446px">
      <div class="ap">
        <p class="ap-intro">
          每个动作都先 <b>dry-run 预览护栏裁决</b> → 二次确认 → 经护栏执行 → 五段 trace 推回对话流留痕。
          <b>绝不放开自由命令</b>，能力靠「往白名单加受控动作」增长。
        </p>

        <!-- 动作选择（按类分组） -->
        <div v-for="g in ACTION_GROUPS" :key="g" class="ap-group">
          <div class="ap-glabel">{{ g }}</div>
          <div class="ap-acts">
            <button v-for="a in actionsByGroup(g)" :key="a.key" class="ap-act"
                    :class="{ on: sel && sel.key === a.key }" @click="pickAction(a)">
              <Icon :name="a.ic" :size="14" /> {{ a.label }}
            </button>
          </div>
        </div>

        <!-- 参数表单 -->
        <div v-if="sel" class="ap-form">
          <div class="ap-hint"><Icon name="guardrail" :size="13" /> {{ sel.hint }}</div>
          <div v-for="f in sel.fields" :key="f.k" class="ap-field">
            <label>{{ f.label }}</label>
            <el-input v-model="form[f.k]" size="small" :placeholder="f.ph"
                      @keydown.enter.prevent="preview()" />
          </div>
          <div class="ap-auth">
            <el-switch v-model="authorized" size="small" />
            <span>显式授权提权操作（防线4）<em v-if="sel.auth"> · 本动作需提权，未授权将被拦下</em></span>
          </div>
          <div class="ap-btns">
            <button class="btn primary" :disabled="!canPreview || busy" @click="preview">
              <Icon name="search" :size="14" /> 预览护栏裁决（dry-run）
            </button>
          </div>
        </div>

        <!-- 裁决 / 执行结果 -->
        <div v-if="result && verdict" class="ap-result" :class="phase">
          <div class="apr-head">
            <span class="apr-verdict" :class="verdict.cls">{{ verdict.text }}</span>
            <span v-if="result.guard && result.guard.risk" class="apr-risk" :class="RISK_CLS[result.guard.risk]">
              风险 {{ result.guard.risk }}
            </span>
          </div>
          <code v-if="result.command" class="apr-cmd">{{ result.command }}</code>
          <div class="apr-reason">{{ result.reason }}</div>
          <div v-if="result.privilege && !result.privilege.allowed" class="apr-priv">
            <b>防线4 · 最小权限</b>：{{ result.privilege.reason }}
          </div>
          <div v-if="result.guard && (result.guard.matched_rules || []).length" class="apr-rules">
            命中规则：<code v-for="id in result.guard.matched_rules" :key="id">{{ id }}</code>
          </div>
          <div v-if="phase === 'previewed' && !result.blocked" class="ap-btns">
            <button class="btn warn" :disabled="busy" @click="confirmExec">
              <Icon name="check" :size="14" /> 确认执行（真正落地）
            </button>
            <span class="ap-confirm-note">将真正改变系统状态，经护栏 + 最小权限校验后执行并留痕。</span>
          </div>
          <div v-if="phase === 'done' && result.trace_id" class="apr-trace">
            已留痕 · trace <code>{{ result.trace_id.slice(0, 8) }}</code>（见对话流 / 审计回放）
          </div>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<style scoped>
.stream { flex: 1; min-height: 0; overflow-y: auto; padding: 20px 24px; }

/* 空态 */
.welcome { max-width: 760px; margin: 24px auto; text-align: center; }
.wc-mark { width: 64px; height: 64px; margin: 0 auto 16px; border-radius: 18px; display: flex; align-items: center; justify-content: center;
  color: var(--jade); background: var(--jade-soft); border: 1px solid rgba(43,217,154,.3); box-shadow: 0 0 26px rgba(43,217,154,.2); }
.wc-title { font-size: 20px; font-weight: 650; color: var(--text-0); }
.wc-sub { color: var(--text-2); margin: 8px 0 24px; font-size: 13px; line-height: 1.6; }
.wc-groups { display: flex; flex-direction: column; gap: 14px; text-align: left; }
.wc-group { }
.wc-glabel { font-size: 11px; letter-spacing: 1.4px; color: var(--text-2); text-transform: uppercase; font-family: var(--mono); margin-bottom: 7px; }
.wc-chips { display: flex; flex-wrap: wrap; gap: 8px; }
.wc-chip { background: var(--ink-2); border: 1px solid var(--line); color: var(--text-1); border-radius: 999px; padding: 7px 14px;
  font-size: 13px; cursor: pointer; transition: all .15s; font-family: var(--sans); }
.wc-chip:hover { border-color: var(--jade); color: var(--jade); background: var(--jade-soft); }

/* 对话 */
.row { display: flex; gap: 10px; margin-bottom: 16px; }
.row.user { justify-content: flex-end; }
.avatar { width: 30px; height: 30px; flex: 0 0 auto; border-radius: 9px; display: flex; align-items: center; justify-content: center;
  color: var(--jade); background: var(--jade-soft); border: 1px solid rgba(43,217,154,.25); }
.bubble { max-width: 78%; background: var(--ink-2); border: 1px solid var(--line); border-radius: 14px; padding: 12px 15px; }
.bubble.err { border-color: var(--coral); }
.row.user .bubble { background: linear-gradient(135deg, rgba(43,217,154,.14), rgba(56,189,248,.1)); border-color: rgba(43,217,154,.3); }
.bubble-tags { display: flex; gap: 6px; margin-bottom: 8px; flex-wrap: wrap; align-items: center; }
.text { white-space: pre-wrap; line-height: 1.66; font-size: 14px; color: var(--text-0); }

.ichip { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px; }
.ichip.ok { background: var(--jade-soft); color: var(--jade); }
.ichip.warn { background: var(--amber-soft); color: var(--amber); }
.ichip.bad { background: var(--coral-soft); color: var(--coral); }
.ichip.bad.solid { background: var(--coral); color: #1a0808; }
.ichip.info { background: var(--cyan-soft); color: var(--cyan); }
.ichip.tool { background: var(--ink-3); color: var(--text-1); font-family: var(--mono); }
.ichip.think { background: var(--violet-soft, rgba(167,139,250,.14)); color: var(--violet); }

.trace-toggle { margin-top: 10px; border-top: 1px solid var(--line-soft); padding-top: 8px; }
.tt-btn { display: inline-flex; align-items: center; gap: 6px; background: transparent; border: none; color: var(--text-2);
  font-size: 12px; cursor: pointer; padding: 2px 0; font-family: var(--sans); }
.tt-btn:hover { color: var(--jade); }
.tt-id { font-family: var(--mono); background: var(--ink-3); padding: 0 5px; border-radius: 4px; color: var(--cyan); font-size: 11px; }
.trace-wrap { margin-top: 12px; padding: 12px; background: var(--ink-1); border: 1px solid var(--line-soft); border-radius: 10px; }

.thinking { display: flex; gap: 5px; align-items: center; }
.thinking span { width: 7px; height: 7px; border-radius: 50%; background: var(--jade); opacity: .4; animation: blink 1.2s infinite; }
.thinking span:nth-child(2) { animation-delay: .2s; }
.thinking span:nth-child(3) { animation-delay: .4s; }
@keyframes blink { 0%,100% { opacity: .25; } 50% { opacity: 1; } }

/* 输入栏 */
.composer { display: flex; flex-direction: column; gap: 9px; padding: 12px 24px 18px; border-top: 1px solid var(--line); }
.composer-bar { display: flex; align-items: center; gap: 10px; }
.composer-row { display: flex; gap: 10px; align-items: flex-end; }
.composer-row :deep(.el-textarea) { flex: 1; }

/* 深度思考开关：默认灰、开启紫（与「推理决策」段同色系，呼应思维链） */
.think-toggle { display: inline-flex; align-items: center; gap: 6px; background: var(--ink-2); border: 1px solid var(--line);
  color: var(--text-2); border-radius: 999px; padding: 5px 12px; font-size: 12.5px; cursor: pointer; transition: all .15s; font-family: var(--sans); }
.think-toggle:hover { border-color: var(--violet); color: var(--violet); }
.think-toggle.on { background: var(--violet-soft, rgba(167,139,250,.14)); border-color: rgba(167,139,250,.5); color: var(--violet); }
.tg-state { font-family: var(--mono); font-size: 10.5px; font-weight: 700; padding: 0 6px; border-radius: 999px; background: var(--ink-3); color: var(--text-2); }
.tg-state.on { background: var(--violet); color: #140a26; }
.think-hint { font-size: 11.5px; color: var(--text-2); }
.composer :deep(.el-textarea__inner) { background: var(--ink-2); box-shadow: 0 0 0 1px var(--line) inset; border-radius: 12px;
  color: var(--text-0); font-family: var(--sans); padding: 11px 13px; }
.composer :deep(.el-textarea__inner:focus) { box-shadow: 0 0 0 1px var(--jade) inset; }
.send-btn { width: 46px; height: 46px; flex: 0 0 auto; border-radius: 12px; border: none; cursor: pointer;
  background: var(--jade); color: #06140e; display: flex; align-items: center; justify-content: center; transition: all .15s; }
.send-btn:hover:not(:disabled) { box-shadow: 0 0 16px rgba(43,217,154,.5); }
.send-btn:disabled { background: var(--ink-3); color: var(--text-2); cursor: not-allowed; }

/* 受控动作触发按钮 */
.btn-actions { display: inline-flex; align-items: center; gap: 6px; background: var(--ink-2); border: 1px solid var(--line);
  color: var(--text-1); border-radius: 8px; padding: 7px 13px; font-size: 13px; cursor: pointer; transition: all .15s; font-family: var(--sans); }
.btn-actions:hover { border-color: var(--jade); color: var(--jade); background: var(--jade-soft); }

/* 受控动作面板（el-drawer 内容） */
.ap { padding: 2px 2px 24px; }
.ap-intro { font-size: 12.5px; color: var(--text-2); line-height: 1.7; background: var(--ink-1); border: 1px solid var(--line-soft);
  border-radius: 8px; padding: 10px 12px; margin-bottom: 16px; }
.ap-intro b { color: var(--text-0); }
.ap-group { margin-bottom: 12px; }
.ap-glabel { font-size: 11px; letter-spacing: 1.2px; color: var(--text-2); text-transform: uppercase; font-family: var(--mono); margin-bottom: 6px; }
.ap-acts { display: flex; flex-wrap: wrap; gap: 7px; }
.ap-act { display: inline-flex; align-items: center; gap: 6px; background: var(--ink-2); border: 1px solid var(--line);
  color: var(--text-1); border-radius: 8px; padding: 6px 11px; font-size: 12.5px; cursor: pointer; transition: all .15s; font-family: var(--sans); }
.ap-act:hover { border-color: var(--line-glow); color: var(--text-0); }
.ap-act.on { background: var(--jade-soft); border-color: rgba(43,217,154,.4); color: var(--jade); }

.ap-form { margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--line-soft); }
.ap-hint { display: flex; align-items: flex-start; gap: 6px; font-size: 12px; color: var(--amber); background: var(--amber-soft);
  border: 1px solid rgba(243,181,61,.25); border-radius: 8px; padding: 8px 10px; margin-bottom: 12px; line-height: 1.55; }
.ap-hint :deep(.icon) { color: var(--amber); flex: 0 0 auto; margin-top: 2px; }
.ap-field { margin-bottom: 10px; }
.ap-field label { display: block; font-size: 12px; color: var(--text-2); margin-bottom: 4px; }
.ap-auth { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-1); margin: 12px 0; }
.ap-auth em { color: var(--text-2); font-style: normal; }
.ap-btns { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-top: 6px; }
.ap-confirm-note { font-size: 11.5px; color: var(--text-2); }

.ap-result { margin-top: 16px; padding: 12px; background: var(--ink-1); border: 1px solid var(--line); border-radius: 10px; }
.ap-result.blocked { border-color: rgba(255,99,99,.4); }
.apr-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.apr-verdict { font-size: 12px; font-weight: 700; padding: 2px 10px; border-radius: 999px; }
.apr-verdict.ok { background: var(--jade-soft); color: var(--jade); }
.apr-verdict.warn { background: var(--amber-soft); color: var(--amber); }
.apr-verdict.bad { background: var(--coral); color: #1a0808; }
.apr-risk { font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px; }
.apr-risk.bad { background: var(--coral-soft); color: var(--coral); }
.apr-risk.warn { background: var(--amber-soft); color: var(--amber); }
.apr-risk.info { background: var(--cyan-soft); color: var(--cyan); }
.apr-cmd { display: block; font-family: var(--mono); font-size: 12px; color: var(--cyan); background: var(--ink-0);
  border: 1px solid var(--line-soft); border-radius: 6px; padding: 7px 9px; margin-bottom: 8px; word-break: break-all; }
.apr-reason { font-size: 13px; color: var(--text-1); line-height: 1.6; }
.apr-priv { margin-top: 8px; font-size: 12px; color: var(--amber); background: var(--amber-soft); border-radius: 6px; padding: 7px 9px; line-height: 1.55; }
.apr-priv b { color: var(--amber); }
.apr-rules { margin-top: 8px; font-size: 12px; color: var(--text-2); }
.apr-rules code { font-family: var(--mono); background: var(--ink-3); color: var(--text-1); padding: 1px 6px; border-radius: 4px; margin-left: 4px; }
.apr-trace { margin-top: 10px; font-size: 12px; color: var(--text-2); }
.apr-trace code { font-family: var(--mono); background: var(--ink-3); color: var(--cyan); padding: 1px 6px; border-radius: 4px; }

/* 面板内按钮（与全局共用样式语言） */
.btn { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--line); background: var(--ink-2);
  color: var(--text-1); border-radius: 8px; padding: 7px 13px; font-size: 13px; cursor: pointer; transition: all .15s; font-family: var(--sans); }
.btn:hover:not(:disabled) { border-color: var(--line-glow); color: var(--text-0); }
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn.primary { background: var(--jade); color: #06140e; border-color: var(--jade); font-weight: 600; }
.btn.primary:hover:not(:disabled) { box-shadow: 0 0 16px rgba(43,217,154,.45); color: #06140e; }
.btn.warn { background: var(--amber); color: #1f1403; border-color: var(--amber); font-weight: 600; }
.btn.warn:hover:not(:disabled) { box-shadow: 0 0 16px rgba(243,181,61,.4); }
</style>
