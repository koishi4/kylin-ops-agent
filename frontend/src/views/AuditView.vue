<script setup>
/**
 * 审计回放视图（可追溯闭环）：左侧历史会话，右侧整条五段执行链回放。
 * 叠加两层防篡改证据：① 库内 HMAC 哈希链完整性校验（断链即报）；
 * ② 自封口审计证据包导出（完整五段 + verify + 规则/工具基线指纹 + HMAC seal），可离线核验、可下载留档。
 */
import { ref, onMounted } from 'vue'
import { listTraces, getTrace, verifyTrace, exportEvidence } from '../api.js'
import { message } from '../ui.js'
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

const INTENT = { white: 'ok', gray: 'warn', black: 'bad', action: 'info', briefing: 'info', rules_reload: 'info' }
function fmt(ts) { return ts ? new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) : '' }

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
    if (!evidence.value.ok) message.error('导出失败：' + (evidence.value.error || '未知'))
  } catch (e) { message.error('导出失败：' + (e.message || e)) }
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
        <div class="view-title"><Icon name="audit" :size="19" /> 审计回放</div>
        <div class="view-sub">每次会话生成 trace_id，五段执行链按链回放；HMAC 哈希链防篡改，可导出自封口证据包离线核验。</div>
      </div>
      <div class="view-actions">
        <button class="btn ghost sm" :disabled="listLoading" @click="loadList"><Icon name="refresh" :size="13" /> 刷新</button>
      </div>
    </div>

    <div class="audit">
      <!-- 左：历史列表 -->
      <div class="tlist">
        <div v-if="listLoading" class="busyline"><span class="spin" /> 加载…</div>
        <div v-if="!traces.length && !listLoading" class="hollow"><Icon name="audit" :size="24" /><div>暂无历史会话</div></div>
        <button v-for="t in traces" :key="t.trace_id" class="trow" :class="{ on: active && active.trace_id === t.trace_id }" @click="open(t.trace_id)">
          <div class="trow-top">
            <span class="tag" :class="INTENT[t.intent] || 'info'">{{ t.intent || '-' }}</span>
            <span v-if="t.blocked" class="tag bad solid">拦截</span>
            <span v-if="t.tainted" class="tag warn">污点</span>
            <span class="trow-time mono">{{ fmt(t.created_at) }}</span>
          </div>
          <div class="trow-input">{{ t.user_input }}</div>
        </button>
      </div>

      <!-- 右：回放 -->
      <div class="tdetail">
        <div v-if="detailLoading" class="busyline"><span class="spin" /> 加载执行链…</div>
        <div v-if="!active && !detailLoading" class="hollow"><Icon name="audit" :size="28" /><div>点击左侧会话回放整条执行链</div></div>
        <template v-if="active">
          <div class="panel panel-pad">
            <div class="dm-row">
              <span class="muted mono" style="font-size:11px">trace_id</span>
              <code class="tok acc">{{ active.trace_id }}</code>
              <span class="tag" :class="active.tainted ? 'warn' : 'ok'">{{ active.tainted ? '污点路径（仅只读）' : '无污点' }}</span>
              <span class="muted mono" style="font-size:11px;margin-left:auto">{{ active.llm_provider }}</span>
            </div>
            <div class="dm-actions">
              <button class="btn ghost sm" :disabled="verifying" @click="doVerify"><Icon name="lock" :size="13" /> 校验完整性</button>
              <span v-if="verifyResult" class="tag" :class="verifyResult.valid ? 'ok' : 'bad solid'">
                {{ verifyResult.valid ? `哈希链完整（${verifyResult.steps} 段）` : `检测到篡改${verifyResult.broken_at != null ? '（断链于第 ' + verifyResult.broken_at + ' 段）' : ''}` }}
              </span>
              <button class="btn ghost sm" :disabled="exporting" @click="doExport"><Icon name="download" :size="13" /> 导出证据包</button>
              <button v-if="evidence && evidence.ok" class="btn ghost sm" @click="download"><Icon name="download" :size="13" /> 下载 JSON</button>
            </div>
            <div v-if="verifyResult" class="muted" style="font-size:11.5px;margin-top:6px">{{ verifyResult.reason }}</div>
            <div v-if="evidence && evidence.ok" class="seal">
              <span class="muted mono" style="font-size:11px">HMAC seal</span>
              <code class="tok">{{ (evidence.seal || evidence.evidence?.seal || '').slice(0, 24) }}…</code>
              <span class="muted" style="font-size:11.5px">同密钥封口，导出后任何改动都会令 seal 失配</span>
            </div>
          </div>

          <div class="panel panel-pad" style="margin-top:12px">
            <TraceTimeline :steps="active.steps || []" show-time />
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<style scoped>
.audit { flex: 1; min-height: 0; display: grid; grid-template-columns: 300px 1fr; }
.tlist { overflow-y: auto; border-right: 1px solid var(--line); padding: 12px; display: flex; flex-direction: column; gap: 7px; }
.trow {
  text-align: left; background: var(--s0); border: 1px solid var(--line); border-radius: var(--r-s);
  padding: 9px 11px; cursor: pointer; transition: border-color .12s; font-family: var(--sans);
}
.trow:hover { border-color: var(--line-2); }
.trow.on { border-color: var(--acc); }
.trow-top { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; }
.trow-time { font-size: 10px; color: var(--t2); margin-left: auto; }
.trow-input {
  margin-top: 6px; font-size: 12px; color: var(--t1); word-break: break-all; line-height: 1.5;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}

.tdetail { overflow-y: auto; padding: 14px 18px; }
.dm-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.dm-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 11px; }
.seal { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--line); }
</style>
