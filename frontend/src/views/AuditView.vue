<script setup>
/**
 * 审计回放视图（可追溯闭环）：左侧历史会话，右侧整条五段执行链回放。
 * 叠加两层防篡改证据：① 库内 HMAC 哈希链完整性校验（断链即报）；
 * ② 自封口审计证据包导出（完整五段 + verify + 规则/工具基线指纹 + HMAC seal），可离线核验、可下载留档。
 */
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { listTraces, getTrace, verifyTrace, exportEvidence } from '../api.js'
import Icon from '../Icon.vue'
import TraceTimeline from '../TraceTimeline.vue'

const traces = ref([])
const active = ref(null)
const listLoading = ref(false)
const detailLoading = ref(false)
const verifyResult = ref(null)
const verifying = ref(false)
const evidence = ref(null)
const exporting = ref(false)

const INTENT = { white: 'ok', gray: 'warn', black: 'bad', action: 'info', rules_reload: 'info', action_exec: 'info' }
function fmt(ts) { return ts ? new Date(ts * 1000).toLocaleString() : '' }

async function loadList() {
  listLoading.value = true
  try { traces.value = await listTraces(50) } finally { listLoading.value = false }
}
async function open(id) {
  detailLoading.value = true
  verifyResult.value = null; evidence.value = null
  try { active.value = await getTrace(id) } finally { detailLoading.value = false }
}
async function doVerify() {
  if (!active.value) return
  verifying.value = true
  try { verifyResult.value = await verifyTrace(active.value.trace_id) }
  finally { verifying.value = false }
}
async function doExport() {
  if (!active.value) return
  exporting.value = true
  try {
    evidence.value = await exportEvidence(active.value.trace_id)
    if (!evidence.value.ok) ElMessage.error('导出失败：' + (evidence.value.error || '未知'))
  } catch (e) { ElMessage.error('导出失败：' + (e.message || e)) }
  finally { exporting.value = false }
}
function download() {
  if (!evidence.value) return
  const blob = new Blob([JSON.stringify(evidence.value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = `evidence-${active.value.trace_id.slice(0, 12)}.json`; a.click()
  URL.revokeObjectURL(url)
}

onMounted(loadList)
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="audit" :size="20" /> 审计回放</div>
        <div class="view-sub">每次会话生成 trace_id，五段执行链按链回放；HMAC 哈希链防篡改，可导出自封口证据包离线核验。</div>
      </div>
      <div class="view-actions">
        <button class="btn ghost sm" :disabled="listLoading" @click="loadList"><Icon name="refresh" :size="14" /> 刷新</button>
      </div>
    </div>

    <div class="audit">
      <!-- 左：历史列表 -->
      <div class="tlist" v-loading="listLoading">
        <div v-if="!traces.length" class="hollow"><Icon name="audit" :size="26" class="he-ic" /><div>暂无历史会话</div></div>
        <button v-for="t in traces" :key="t.trace_id" class="trow" :class="{ on: active && active.trace_id === t.trace_id }" @click="open(t.trace_id)">
          <div class="trow-top">
            <span class="ichip" :class="INTENT[t.intent] || 'info'">{{ t.intent || '-' }}</span>
            <span v-if="t.blocked" class="ichip bad solid">拦截</span>
            <span v-if="t.tainted" class="ichip warn">☣</span>
            <span class="trow-time">{{ fmt(t.created_at) }}</span>
          </div>
          <div class="trow-input">{{ t.user_input }}</div>
        </button>
      </div>

      <!-- 右：回放 -->
      <div class="tdetail" v-loading="detailLoading">
        <div v-if="!active" class="hollow"><Icon name="audit" :size="30" class="he-ic" /><div>点击左侧会话回放整条执行链</div></div>
        <template v-else>
          <div class="d-meta panel panel-pad">
            <div class="dm-row">
              <span class="muted mono" style="font-size:11px">trace_id</span>
              <code class="tok">{{ active.trace_id }}</code>
              <span class="ichip" :class="active.tainted ? 'warn' : 'ok'">{{ active.tainted ? '☣ 污点路径（仅只读）' : '✓ 无污点' }}</span>
              <span class="muted mono" style="font-size:11px;margin-left:auto">{{ active.llm_provider }}</span>
            </div>
            <div class="dm-actions">
              <button class="btn ghost sm" :disabled="verifying" @click="doVerify"><Icon name="lock" :size="13" /> 校验完整性</button>
              <span v-if="verifyResult" class="ichip" :class="verifyResult.valid ? 'ok' : 'bad'">
                {{ verifyResult.valid ? `✓ 哈希链完整（${verifyResult.steps} 段）` : `✗ 检测到篡改${verifyResult.broken_at != null ? '（断链于第 ' + verifyResult.broken_at + ' 段）' : ''}` }}
              </span>
              <button class="btn ghost sm" :disabled="exporting" @click="doExport"><Icon name="download" :size="13" /> 导出证据包</button>
              <button v-if="evidence && evidence.ok" class="btn ghost sm" @click="download"><Icon name="download" :size="13" /> 下载 JSON</button>
            </div>
            <div v-if="verifyResult" class="muted" style="font-size:11.5px;margin-top:6px">{{ verifyResult.reason }}</div>
            <div v-if="evidence && evidence.ok" class="seal">
              <span class="muted mono" style="font-size:11px">HMAC seal</span>
              <code class="tok">{{ (evidence.seal || '').slice(0, 24) }}…</code>
              <span class="muted" style="font-size:11.5px">同密钥封口，导出后任何改动都会令 seal 失配</span>
            </div>
          </div>

          <div class="d-timeline panel panel-pad">
            <TraceTimeline :steps="active.steps || []" show-time />
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<style scoped>
.audit { flex: 1; min-height: 0; display: grid; grid-template-columns: 320px 1fr; }
.tlist { overflow-y: auto; border-right: 1px solid var(--line); padding: 14px; display: flex; flex-direction: column; gap: 8px; }
.trow { text-align: left; background: var(--ink-2); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; cursor: pointer; transition: all .15s; font-family: var(--sans); }
.trow:hover { border-color: var(--line-glow); }
.trow.on { border-color: var(--jade); background: var(--jade-soft); }
.trow-top { display: flex; align-items: center; gap: 6px; }
.trow-time { font-size: 10.5px; color: var(--text-2); margin-left: auto; font-family: var(--mono); }
.trow-input { margin-top: 6px; font-size: 12.5px; color: var(--text-1); word-break: break-all; line-height: 1.5;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }

.tdetail { overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 14px; }
.d-meta { }
.dm-row { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
.dm-actions { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; margin-top: 11px; }
.seal { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--line-soft); }

.ichip { font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px; flex: 0 0 auto; }
.ichip.ok { background: var(--jade-soft); color: var(--jade); }
.ichip.warn { background: var(--amber-soft); color: var(--amber); }
.ichip.bad { background: var(--coral-soft); color: var(--coral); }
.ichip.bad.solid { background: var(--coral); color: #1a0808; }
.ichip.info { background: var(--cyan-soft); color: var(--cyan); }

.btn { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--line); background: var(--ink-2);
  color: var(--text-1); border-radius: 8px; padding: 6px 12px; font-size: 12.5px; cursor: pointer; transition: all .15s; font-family: var(--sans); }
.btn:hover:not(:disabled) { border-color: var(--line-glow); color: var(--text-0); }
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn.ghost { background: transparent; }
.btn.sm { padding: 6px 11px; }
</style>
