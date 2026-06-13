<script setup>
/**
 * 智能对话视图（评分①②）：自然语言运维主入口。
 * 一句话 → 意图分类 → 选 MCP 工具 → 中文作答，每条回复内联可展开的五段执行链。
 * 空态给「按场景分组」的引导问句，覆盖只读感知 / 危险命令拦截 / 根因三类，便于现场演示。
 */
import { ref, nextTick, computed } from 'vue'
import { chat } from '../api.js'
import Icon from '../Icon.vue'
import TraceTimeline from '../TraceTimeline.vue'

const props = defineProps({ provider: { type: String, default: '-' } })

const input = ref('')
const loading = ref(false)
const messages = ref([])
const scroller = ref(null)
const openTrace = ref({})   // index -> 是否展开 trace

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
    const data = await chat(msg)
    messages.value.push({
      role: 'assistant', answer: data.answer, trace: data.trace || [],
      intent: data.intent, blocked: data.blocked, tainted: data.tainted,
      trace_id: data.trace_id, tool_calls: data.tool_calls || [],
    })
  } catch (e) {
    messages.value.push({ role: 'assistant', answer: '请求失败：' + (e.message || e), trace: [], error: true })
  } finally {
    loading.value = false
    await scrollBottom()
  }
}
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="console" :size="20" /> 智能对话</div>
        <div class="view-sub">用自然语言运维 Linux：感知 → 推理 → 安全校验 → 留痕，每条回复可展开完整执行链。</div>
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
          <div v-if="m.role === 'assistant' && (m.intent || m.blocked)" class="bubble-tags">
            <span v-if="m.intent" class="ichip" :class="(INTENT[m.intent] || {}).cls">
              {{ (INTENT[m.intent] || {}).text || m.intent }}
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
      <el-input
        v-model="input" type="textarea" :rows="2" resize="none"
        placeholder="用自然语言描述运维需求，回车发送（Shift+回车换行）"
        @keydown.enter.exact.prevent="send()" />
      <button class="send-btn" :disabled="loading || !input.trim()" @click="send()">
        <Icon name="send" :size="18" />
      </button>
    </div>
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
.composer { display: flex; gap: 10px; padding: 14px 24px 18px; border-top: 1px solid var(--line); align-items: flex-end; }
.composer :deep(.el-textarea__inner) { background: var(--ink-2); box-shadow: 0 0 0 1px var(--line) inset; border-radius: 12px;
  color: var(--text-0); font-family: var(--sans); padding: 11px 13px; }
.composer :deep(.el-textarea__inner:focus) { box-shadow: 0 0 0 1px var(--jade) inset; }
.send-btn { width: 46px; height: 46px; flex: 0 0 auto; border-radius: 12px; border: none; cursor: pointer;
  background: var(--jade); color: #06140e; display: flex; align-items: center; justify-content: center; transition: all .15s; }
.send-btn:hover:not(:disabled) { box-shadow: 0 0 16px rgba(43,217,154,.5); }
.send-btn:disabled { background: var(--ink-3); color: var(--text-2); cursor: not-allowed; }
</style>
