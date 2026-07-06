<script setup>
/**
 * 智能对话视图（评分①②）：自然语言运维主入口。
 * 一句话 → 意图分类 → 选 MCP 工具 → 中文作答，每条回复内联可展开的五段执行链。
 * 空态给「按场景分组」的引导问句，覆盖只读感知 / 危险命令拦截 / 根因三类，便于现场演示。
 * 受控动作面板：白名单参数化处置 → dry-run 预览护栏裁决 → 二次确认 → 执行留痕。
 */
import { ref, nextTick, computed } from 'vue'
import { chat, executeAction } from '../api.js'
import { message } from '../ui.js'
import Icon from '../Icon.vue'
import Drawer from '../Drawer.vue'
import Toggle from '../Toggle.vue'
import TraceTimeline from '../TraceTimeline.vue'

const props = defineProps({ provider: { type: String, default: '-' } })

const input = ref('')
const loading = ref(false)
const messages = ref([])
const scroller = ref(null)
const openTrace = ref({})   // index -> 是否展开 trace
// 深度思考开关：on → 后端编排改用 DeepSeek 推理模型，把模型「思维链」入执行链回放，更慢但更可解释
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

// ── 受控动作面板（评分③）：白名单参数化动作的可操作演示 ──────────────────
// 流程：dry-run 预览护栏裁决 → 二次确认 → 经护栏执行 → 五段 trace 推回对话流留痕。
// 关键演示点：needAuth 动作未授权时，预览即被防线4 拦下；打开「授权」开关再预览即放行。
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
  if (r.blocked) return { cls: 'bad solid', text: '已拦截' }
  if (phase.value === 'done') return r.executed ? { cls: 'ok solid', text: '已执行' } : { cls: 'warn', text: '未执行' }
  return { cls: 'warn', text: '待确认（dry-run 已通过护栏）' }
})

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
  } catch (e) { message.error('预览失败：' + errText(e)) }
  finally { busy.value = false }
}

async function confirmExec() {
  if (!sel.value || busy.value) return
  busy.value = true
  try {
    const r = await executeAction(sel.value.key, buildParams(),
      { confirmed: true, authorized: authorized.value, dryRun: false })
    result.value = r; phase.value = 'done'
    // 把动作的五段 trace 推回对话流——与对话留痕统一，复用 TraceTimeline 回放（可追溯）
    messages.value.push({
      role: 'assistant', answer: r.reason || (r.executed ? '动作已执行。' : '未执行。'),
      trace: r.trace || [], intent: 'action', blocked: r.blocked,
      trace_id: r.trace_id, tool_calls: [],
    })
    if (r.executed && r.ok) message.success('已执行 · 链 ' + (r.trace_id || '').slice(0, 8))
    else if (r.blocked) message.error('护栏拦截：' + r.reason)
    else message.warning(r.reason || '未执行')
    drawer.value = false
    await scrollBottom()
  } catch (e) { message.error('执行失败：' + errText(e)) }
  finally { busy.value = false }
}
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="console" :size="19" /> 智能对话</div>
        <div class="view-sub">用自然语言运维 Linux：感知 → 推理 → 安全校验 → 留痕，每条回复可展开完整执行链。</div>
      </div>
      <div class="view-actions">
        <button class="btn" @click="drawer = true">
          <Icon name="bolt" :size="14" /> 受控动作
        </button>
      </div>
    </div>

    <div ref="scroller" class="stream">
      <!-- 空态：引导问句 -->
      <div v-if="!hasMsg" class="welcome">
        <div class="wc-title">用一句话开始运维</div>
        <div class="wc-sub">我会选对工具拿真实系统数据；遇到危险操作会当场拦下并解释原因。</div>
        <div class="wc-groups">
          <div v-for="grp in SUGGESTS" :key="grp.g" class="wc-group">
            <div class="block-label" style="margin:0 0 7px">{{ grp.g }}</div>
            <div class="wc-chips">
              <button v-for="q in grp.items" :key="q" class="wc-chip" @click="send(q)">{{ q }}</button>
            </div>
          </div>
        </div>
      </div>

      <!-- 对话流 -->
      <div v-for="(m, i) in messages" :key="i" :class="['msg', m.role]">
        <div class="msg-who mono">{{ m.role === 'user' ? '你' : 'AGENT' }}</div>
        <div class="msg-body" :class="{ err: m.error, blocked: m.blocked }">
          <div v-if="m.role === 'assistant' && (m.intent || m.blocked || m.deep_thinking || m.tainted)" class="msg-tags">
            <span v-if="m.intent" class="tag" :class="(INTENT[m.intent] || {}).cls">
              {{ (INTENT[m.intent] || {}).text || m.intent }}
            </span>
            <span v-if="m.deep_thinking" class="tag plum">深度思考</span>
            <span v-if="m.blocked" class="tag bad solid">护栏拦截</span>
            <span v-if="m.tainted" class="tag warn">污点输入 · 已隔离</span>
            <span v-for="t in m.tool_calls" :key="t.tool || t.name || t" class="tag mono">
              {{ t.tool || t.name || t }}
            </span>
          </div>
          <div class="msg-text">{{ m.answer }}</div>
          <div v-if="m.trace && m.trace.length" class="trace-toggle">
            <button class="tt-btn" @click="openTrace[i] = !openTrace[i]">
              {{ openTrace[i] ? '收起' : '展开' }}执行链 · {{ m.trace.length }} 段
              <code v-if="m.trace_id" class="tok">{{ m.trace_id.slice(0, 8) }}</code>
            </button>
            <div v-if="openTrace[i]" class="trace-wrap">
              <TraceTimeline :steps="m.trace" />
            </div>
          </div>
        </div>
      </div>

      <div v-if="loading" class="msg assistant">
        <div class="msg-who mono">AGENT</div>
        <div class="msg-body busyline" style="padding:10px 14px"><span class="spin" /> 正在推理与调用工具…</div>
      </div>
    </div>

    <div class="composer">
      <div class="composer-bar">
        <label class="think-toggle">
          <Toggle v-model="deepThinking" /> 深度思考
        </label>
        <span class="think-hint muted">{{ deepThinking
          ? '推理模型 · 执行链回放展示完整思维链，响应更慢'
          : '快速模型 · 低延迟秒级响应' }}</span>
      </div>
      <div class="composer-row">
        <textarea v-model="input" rows="2" class="field composer-input"
                  placeholder="用自然语言描述运维需求，回车发送（Shift+回车换行）"
                  @keydown.enter.exact.prevent="send()" />
        <button class="btn primary send-btn" :disabled="loading || !input.trim()" @click="send()">
          <Icon name="send" :size="16" />
        </button>
      </div>
    </div>

    <!-- 受控动作面板：白名单参数化处置 → dry-run 预览裁决 → 二次确认 → 经护栏执行 → 留痕 -->
    <Drawer v-model="drawer" title="受控动作 · 白名单参数化处置">
      <p class="note" style="margin:0 0 14px">
        每个动作都先 dry-run 预览护栏裁决 → 二次确认 → 经护栏执行 → 五段 trace 推回对话流留痕。
        绝不放开自由命令，能力靠「往白名单加受控动作」增长。
      </p>

      <!-- 动作选择（按类分组） -->
      <div v-for="g in ACTION_GROUPS" :key="g" class="ap-group">
        <div class="block-label" style="margin:0 0 6px">{{ g }}</div>
        <div class="ap-acts">
          <button v-for="a in actionsByGroup(g)" :key="a.key" class="btn sm"
                  :class="{ picked: sel && sel.key === a.key }" @click="pickAction(a)">
            <Icon :name="a.ic" :size="13" /> {{ a.label }}
          </button>
        </div>
      </div>

      <!-- 参数表单 -->
      <div v-if="sel" class="ap-form">
        <div class="note warn ap-hint">{{ sel.hint }}</div>
        <div v-for="f in sel.fields" :key="f.k" class="ap-field">
          <label>{{ f.label }}</label>
          <input v-model="form[f.k]" class="field" :placeholder="f.ph"
                 @keydown.enter.prevent="preview()" />
        </div>
        <label class="ap-auth">
          <Toggle v-model="authorized" />
          <span>显式授权提权操作（防线4）<em v-if="sel.auth"> · 本动作需提权，未授权将被拦下</em></span>
        </label>
        <button class="btn primary" :disabled="!canPreview || busy" @click="preview">
          <Icon name="search" :size="13" /> 预览护栏裁决（dry-run）
        </button>
      </div>

      <!-- 裁决 / 执行结果 -->
      <div v-if="result && verdict" class="ap-result" :class="{ blocked: result.blocked }">
        <div class="apr-head">
          <span class="tag" :class="verdict.cls">{{ verdict.text }}</span>
          <span v-if="result.guard && result.guard.risk" class="tag" :class="RISK_CLS[result.guard.risk]">
            风险 {{ result.guard.risk }}
          </span>
        </div>
        <code v-if="result.command" class="apr-cmd">{{ result.command }}</code>
        <div class="apr-reason">{{ result.reason }}</div>
        <div v-if="result.privilege && !result.privilege.allowed" class="note warn" style="margin-top:8px">
          <b>防线4 · 最小权限</b>：{{ result.privilege.reason }}
        </div>
        <div v-if="result.guard && (result.guard.matched_rules || []).length" class="apr-rules">
          命中规则：<code v-for="id in result.guard.matched_rules" :key="id" class="tok">{{ id }}</code>
        </div>
        <div v-if="phase === 'previewed' && !result.blocked" class="apr-exec">
          <button class="btn danger" :disabled="busy" @click="confirmExec">
            <Icon name="check" :size="13" /> 确认执行（真正落地）
          </button>
          <span class="muted" style="font-size:11.5px">将真正改变系统状态，经护栏 + 最小权限校验后执行并留痕。</span>
        </div>
        <div v-if="phase === 'done' && result.trace_id" class="apr-trace muted">
          已留痕 · trace <code class="tok">{{ result.trace_id.slice(0, 8) }}</code>（见对话流 / 审计回放）
        </div>
      </div>
    </Drawer>
  </div>
</template>

<style scoped>
.stream { flex: 1; min-height: 0; overflow-y: auto; padding: 20px 24px; }

/* 空态 */
.welcome { max-width: 640px; margin: 40px auto; }
.wc-title { font-size: 19px; font-weight: 700; color: var(--t0); }
.wc-sub { color: var(--t2); margin: 7px 0 22px; font-size: 12.5px; line-height: 1.6; }
.wc-groups { display: flex; flex-direction: column; gap: 16px; }
.wc-chips { display: flex; flex-wrap: wrap; gap: 8px; }
.wc-chip {
  background: var(--s0); border: 1px solid var(--line-2); color: var(--t1);
  border-radius: var(--r-s); padding: 7px 13px; font-size: 12.5px; cursor: pointer;
  font-family: var(--sans); transition: border-color .12s, color .12s;
}
.wc-chip:hover { border-color: var(--acc); color: var(--acc); }

/* 对话：留言簿式（左标签 + 正文），不用聊天气泡 */
.msg { display: grid; grid-template-columns: 52px 1fr; gap: 12px; margin-bottom: 14px; max-width: 900px; }
.msg-who { font-size: 10px; letter-spacing: 1px; color: var(--t2); padding-top: 12px; text-align: right; }
.msg.user .msg-who { color: var(--acc); }
.msg-body {
  min-width: 0; background: var(--s0); border: 1px solid var(--line);
  border-radius: var(--r-s); padding: 11px 14px;
}
.msg.user .msg-body { background: transparent; border-color: var(--line-2); }
.msg-body.err { border-left: 2px solid var(--bad); }
.msg-body.blocked { border-left: 2px solid var(--bad); }
.msg-tags { display: flex; gap: 6px; margin-bottom: 8px; flex-wrap: wrap; align-items: center; }
.msg-text { white-space: pre-wrap; line-height: 1.7; font-size: 13.5px; color: var(--t0); }

.trace-toggle { margin-top: 10px; border-top: 1px solid var(--line); padding-top: 8px; }
.tt-btn {
  display: inline-flex; align-items: center; gap: 7px; background: transparent; border: none;
  color: var(--t2); font-size: 12px; cursor: pointer; padding: 2px 0; font-family: var(--sans);
}
.tt-btn:hover { color: var(--acc); }
.trace-wrap { margin-top: 12px; padding: 12px 12px 0; background: var(--bg); border: 1px solid var(--line); border-radius: var(--r-s); }

/* 输入栏 */
.composer { display: flex; flex-direction: column; gap: 8px; padding: 12px 24px 16px; border-top: 1px solid var(--line); }
.composer-bar { display: flex; align-items: center; gap: 10px; }
.think-toggle { display: inline-flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--t1); cursor: pointer; }
.think-hint { font-size: 11.5px; }
.composer-row { display: flex; gap: 8px; align-items: stretch; }
.composer-input { flex: 1; }
.send-btn { width: 44px; justify-content: center; }

/* 受控动作面板 */
.ap-group { margin-bottom: 12px; }
.ap-acts { display: flex; flex-wrap: wrap; gap: 6px; }
.btn.picked { border-color: var(--acc); color: var(--acc); background: var(--acc-soft); }

.ap-form { margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--line); }
.ap-hint { margin-bottom: 12px; }
.ap-field { margin-bottom: 10px; display: flex; flex-direction: column; gap: 4px; }
.ap-field label { font-size: 12px; color: var(--t2); }
.ap-auth { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--t1); margin: 12px 0; cursor: pointer; }
.ap-auth em { color: var(--t2); font-style: normal; }

.ap-result { margin-top: 14px; padding: 12px; background: var(--bg); border: 1px solid var(--line); border-radius: var(--r-s); }
.ap-result.blocked { border-left: 2px solid var(--bad); }
.apr-head { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.apr-cmd {
  display: block; font-family: var(--mono); font-size: 12px; color: var(--acc);
  background: var(--s1); border: 1px solid var(--line); border-radius: var(--r-s);
  padding: 7px 9px; margin-bottom: 8px; word-break: break-all;
}
.apr-reason { font-size: 12.5px; color: var(--t1); line-height: 1.6; }
.apr-rules { margin-top: 8px; font-size: 12px; color: var(--t2); display: flex; align-items: center; gap: 5px; flex-wrap: wrap; }
.apr-exec { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-top: 10px; }
.apr-trace { margin-top: 10px; font-size: 12px; }
</style>
