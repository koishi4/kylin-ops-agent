<script setup>
/**
 * 运维简报视图：一键生成日报/周报——聚合系统快照 + 健康诊断 + 安全态势 + 审计活动。
 * 全只读聚合、确定性可离线；可选 AI 导语（仅改写既有数据，失败自动降级）。
 * 结构化数据按「文档」版式呈现，Markdown 原文可预览、可一键下载归档；
 * 简报生成本身也落审计 trace，与全站「可追溯」口径一致。
 */
import { ref, computed } from 'vue'
import { getBriefing } from '../api.js'
import { message } from '../ui.js'
import Icon from '../Icon.vue'
import Toggle from '../Toggle.vue'

const period = ref('daily')
const useAi = ref(true)
const loading = ref(false)
const data = ref(null)

const stats = computed(() => {
  const b = data.value
  if (!b) return []
  const a = b.activity || {}
  return [
    { k: '会话', v: a.total ?? 0 },
    { k: '护栏拦截', v: a.blocked ?? 0, cls: a.blocked ? 'bad' : '' },
    { k: '受控动作', v: a.actions ?? 0 },
    { k: '待关注问题', v: (b.diagnosis?.issues || []).length, cls: (b.diagnosis?.issues || []).length ? 'warn' : '' },
  ]
})

const snapshotRows = computed(() => {
  const s = data.value?.snapshot
  if (!s) return []
  const load = (s.loadavg || []).map(v => (v == null ? '-' : v.toFixed(2))).join(' / ')
  return [
    ['主机', `${s.hostname}（${s.arch}）`],
    ['内核', s.kernel],
    ['运行时长', s.uptime_human],
    ['负载 1/5/15m', `${load}（${s.cpu_count} 核）`],
    ['CPU 使用率', `${s.cpu_percent}%`],
    ['内存', `${s.mem_used_gb} / ${s.mem_total_gb} GB（${s.mem_percent}%）`],
    ['根分区', `${s.disk_used_gb} / ${s.disk_total_gb} GB（${s.disk_percent}%）`],
  ]
})

// 待办 = 诊断建议 + 情报缓解（与后端 markdown 渲染同口径，去重保序）
const todos = computed(() => {
  const b = data.value
  if (!b) return []
  const list = [...(b.diagnosis?.suggestions || []).slice(0, 8)]
  for (const h of (b.posture?.hits || [])) list.push(...(h.mitigations || []).slice(0, 1))
  return [...new Set(list)]
})

async function generate() {
  loading.value = true
  try {
    const r = await getBriefing(period.value, { ai: useAi.value })
    if (!r.ok) { message.error(r.error || '生成失败'); return }
    data.value = r
    message.success(`${r.period_label}已生成（trace ${String(r.trace_id || '').slice(0, 8)}）`)
  } catch (e) {
    message.error('生成失败：' + (e?.response?.data?.detail || e.message || e))
  } finally { loading.value = false }
}

function download() {
  const b = data.value
  if (!b) return
  const blob = new Blob([b.markdown], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${b.period_label}-${b.date}.md`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="report" :size="19" /> 运维简报</div>
        <div class="view-sub">
          一键聚合系统快照、健康诊断、安全态势与运维活动为结构化日报/周报。全程只读、不依赖模型也能生成；
          所有建议仅供人工决策，处置须走受控动作。
        </div>
      </div>
      <div class="view-actions">
        <div class="seg">
          <button :class="{ on: period === 'daily' }" @click="period = 'daily'">日报 · 24h</button>
          <button :class="{ on: period === 'weekly' }" @click="period = 'weekly'">周报 · 7d</button>
        </div>
        <label class="ai-opt">
          <Toggle v-model="useAi" /> AI 导语
        </label>
        <button class="btn primary" :disabled="loading" @click="generate">
          <Icon name="play" :size="14" /> {{ loading ? '生成中…' : '生成简报' }}
        </button>
        <button v-if="data" class="btn ghost" @click="download">
          <Icon name="download" :size="14" /> 下载 .md
        </button>
      </div>
    </div>

    <div class="view-body">
      <div v-if="loading" class="busyline"><span class="spin" /> 正在聚合数据源（快照 / 诊断 / 态势 / 审计）…</div>

      <div v-if="!data && !loading" class="hollow">
        <Icon name="report" :size="28" />
        <div>选择周期并点「生成简报」。数据源全部只读：psutil 快照 · 根因诊断 · 离线情报态势 · 审计库统计。</div>
      </div>

      <template v-if="data">
        <!-- 统计行 -->
        <div class="stats">
          <div v-for="s in stats" :key="s.k" class="stat">
            <div class="stat-v" :class="s.cls">{{ s.v }}</div>
            <div class="stat-k">{{ s.k }}</div>
          </div>
        </div>

        <!-- 文档主体 -->
        <div class="doc panel">
          <div class="doc-head">
            <div class="doc-title">{{ data.period_label }} <span class="doc-date">{{ data.date }}</span></div>
            <div class="doc-meta mono">
              窗口 {{ data.window_start }} — {{ data.generated_at }}
              <span class="tag mono" :class="data.ai_overview_used ? 'info' : ''">
                导语：{{ data.ai_overview_used ? 'AI 撰写（数据约束）' : '确定性模板' }}
              </span>
              <span v-if="data.trace_id" class="tag mono">trace {{ data.trace_id.slice(0, 12) }}</span>
            </div>
          </div>

          <div class="doc-sec">
            <div class="block-label">一 · 导语</div>
            <p class="doc-overview">{{ data.overview }}</p>
          </div>

          <div class="doc-sec">
            <div class="block-label">二 · 系统概况</div>
            <div class="kv">
              <template v-for="([k, v]) in snapshotRows" :key="k">
                <span class="kv-k">{{ k }}</span><span class="kv-v">{{ v }}</span>
              </template>
            </div>
          </div>

          <div class="doc-sec">
            <div class="block-label">三 · 健康诊断</div>
            <p class="dim" style="margin:0 0 8px">{{ data.diagnosis.summary || '（无结论）' }}</p>
            <div v-if="data.diagnosis.issues.length" class="issue-list">
              <div v-for="i in data.diagnosis.issues" :key="i.topic" class="issue">
                <span class="sev" :class="i.severity"><i class="sd" />{{ i.topic }}</span>
                <span class="issue-f">{{ i.finding }}</span>
              </div>
            </div>
            <div v-else class="muted">未发现需要关注的问题。</div>
          </div>

          <div class="doc-sec">
            <div class="block-label">四 · 安全态势</div>
            <template v-if="data.posture.hits.length">
              <p class="dim" style="margin:0 0 8px">
                态势档位 <span class="sev" :class="data.posture.severity"><i class="sd" />{{ data.posture.severity }}</span>，
                命中情报 {{ data.posture.hits.length }} 条（情报源 {{ data.posture.intel_source || '本地种子库' }}）：
              </p>
              <div v-for="h in data.posture.hits" :key="h.cve" class="hit">
                <code class="tok warn">{{ h.cve }}</code>
                <span class="tag warn">{{ h.status }}</span>
                <span v-if="h.mitigations.length" class="muted">缓解：{{ h.mitigations[0] }}</span>
              </div>
            </template>
            <div v-else class="muted">内核 {{ data.posture.kernel }}，与情报库比对未命中已知风险。</div>
          </div>

          <div class="doc-sec">
            <div class="block-label">五 · 运维活动</div>
            <p class="dim" style="margin:0 0 8px">
              会话 {{ data.activity.total }} 次 · 护栏拦截 {{ data.activity.blocked }} 次 ·
              污点路径 {{ data.activity.tainted }} 条 · 受控动作 {{ data.activity.actions }} 次
            </p>
            <div v-if="Object.keys(data.activity.by_intent || {}).length" class="intents">
              <span v-for="(n, k) in data.activity.by_intent" :key="k" class="tag mono">{{ k }} × {{ n }}</span>
            </div>
            <div v-if="data.activity.blocked_samples.length" class="blocked">
              <div class="blocked-t">拦截事件样例（可在「审计回放」按 trace 回放）</div>
              <div v-for="e in data.activity.blocked_samples" :key="e.trace_id" class="blocked-row">
                <span class="tag bad">拦截</span>
                <span class="blocked-input">{{ e.user_input }}</span>
                <code class="tok">{{ e.trace_id.slice(0, 12) }}</code>
              </div>
            </div>
          </div>

          <div class="doc-sec">
            <div class="block-label">六 · 待办与建议</div>
            <div v-if="todos.length" class="todos">
              <label v-for="(t, i) in todos" :key="i" class="todo">
                <input type="checkbox" /><span>{{ t }}</span>
              </label>
            </div>
            <div v-else class="muted">暂无待办。</div>
          </div>

          <div class="doc-foot">
            本简报由系统只读聚合自动生成；任何变更须经受控动作（二次确认 + 护栏 + 审计）执行。
          </div>
        </div>

        <!-- Markdown 原文 -->
        <details class="raw" style="margin-top:12px">
          <summary>Markdown 原文（下载归档内容）</summary>
          <pre class="detail">{{ data.markdown }}</pre>
        </details>
      </template>
    </div>
  </div>
</template>

<style scoped>
.ai-opt { display: inline-flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--t1); cursor: pointer; }

.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; }
.stat { background: var(--s0); border: 1px solid var(--line); border-radius: var(--r); padding: 12px 14px; }
.stat-v { font-family: var(--mono); font-size: 22px; font-weight: 700; color: var(--t0); }
.stat-v.bad { color: var(--bad); }
.stat-v.warn { color: var(--warn); }
.stat-k { font-size: 11.5px; color: var(--t2); margin-top: 3px; }

.doc { max-width: 860px; }
.doc-head { padding: 16px 20px 13px; border-bottom: 1px solid var(--line); }
.doc-title { font-size: 17px; font-weight: 700; color: var(--t0); }
.doc-date { font-family: var(--mono); font-weight: 500; font-size: 13px; color: var(--t2); margin-left: 8px; }
.doc-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 11px; color: var(--t2); margin-top: 7px; }

.doc-sec { padding: 4px 20px 14px; border-bottom: 1px solid var(--line); }
.doc-sec:last-of-type { border-bottom: none; }
.doc-overview { margin: 0; font-size: 13.5px; line-height: 1.85; color: var(--t0); }

.kv { display: grid; grid-template-columns: 110px 1fr; row-gap: 6px; column-gap: 14px; font-size: 12.5px; }
.kv-k { color: var(--t2); }
.kv-v { color: var(--t1); font-variant-numeric: tabular-nums; }

.issue { display: flex; align-items: baseline; gap: 10px; padding: 5px 0; }
.issue-f { font-size: 12.5px; color: var(--t1); line-height: 1.6; }

.hit { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 3px 0; font-size: 12.5px; }
.intents { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
.blocked { margin-top: 8px; }
.blocked-t { font-size: 11.5px; color: var(--t2); margin-bottom: 6px; }
.blocked-row { display: flex; align-items: center; gap: 8px; padding: 3px 0; min-width: 0; }
.blocked-input { font-size: 12.5px; color: var(--t1); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.todos { display: flex; flex-direction: column; gap: 6px; }
.todo { display: flex; align-items: baseline; gap: 9px; font-size: 12.5px; color: var(--t1); line-height: 1.6; cursor: pointer; }
.todo input { accent-color: var(--acc-deep); margin: 0; transform: translateY(1px); }
.todo input:checked + span { color: var(--t2); text-decoration: line-through; }

.doc-foot { padding: 12px 20px; font-size: 11.5px; color: var(--t2); border-top: 1px solid var(--line); line-height: 1.6; }
</style>
