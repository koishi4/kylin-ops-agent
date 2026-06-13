<script setup>
/**
 * 根因体检视图（评分④，本次加厚的核心展示面）。
 * 支持全部诊断主题：磁盘 / 内存(泄漏·压力) / 负载 / 磁盘IO / 僵尸 / 配置漂移 / 全面体检。
 * 关键卖点可视化：根因结论 + 置信度计量条 + 证据链（信号关联）；磁盘「可清理」项走护栏
 * 二次确认安全清理；配置漂移按 changed/removed/added 分列，确认合法后可重锚 TOFU 基线。
 */
import { ref, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { diagnose, executeAction } from '../api.js'
import Icon from '../Icon.vue'

const TOPICS = [
  { key: 'all', label: '全面体检', ic: 'diagnose' },
  { key: 'disk', label: '磁盘', ic: 'layers' },
  { key: 'memory', label: '内存·泄漏', ic: 'cpu' },
  { key: 'load', label: '负载', ic: 'bolt' },
  { key: 'io', label: '磁盘 IO', ic: 'refresh' },
  { key: 'zombie', label: '僵尸进程', ic: 'alert' },
  { key: 'configdrift', label: '配置漂移', ic: 'lock' },
]
const TOPIC_NAME = { disk: '磁盘空间', memory: '内存压力 / 泄漏', load: '系统负载',
  io: '磁盘 IO 关联', zombie: '僵尸进程', configdrift: '配置文件漂移' }

const topic = ref('all')
const path = ref('/')
const loading = ref(false)
const report = ref(null)
const cleaning = ref('')

const showPath = computed(() => ['disk', 'io', 'all'].includes(topic.value))
const reports = computed(() => {
  const d = report.value
  if (!d) return []
  return d.topic === 'all' ? (d.reports || []) : [d]
})
const summary = computed(() => (report.value && report.value.topic === 'all') ? report.value.summary : null)

async function run(t) {
  if (t) topic.value = t
  loading.value = true
  report.value = null
  try {
    report.value = await diagnose(topic.value, path.value)
  } catch (e) {
    ElMessage.error('诊断失败：' + (e.message || e))
  } finally {
    loading.value = false
  }
}

// 配置漂移：确认所有变更合法后重锚基线（TOFU re-pin）
async function repin() {
  try {
    await ElMessageBox.confirm(
      '重锚会把【当前】配置指纹设为新基线，之后的漂移以此为准。请仅在确认所有变更均为合法计划内变更后操作。',
      '重锚配置基线', { type: 'warning', confirmButtonText: '确认重锚', cancelButtonText: '取消' })
    await diagnose('configdrift', '/', { pin: true })
    ElMessage.success('已重锚配置基线')
    await run('configdrift')
  } catch (e) { if (e !== 'cancel' && e !== 'close') ElMessage.error('重锚失败：' + (e.message || e)) }
}

// 受控安全清理：dry-run 预览护栏裁决 → 二次确认 → 经护栏执行 → 刷新
function actionFor(p) { return /\.log($|\.)/i.test(p) ? 'truncate_log' : 'clean_path' }
async function safeClean(file) {
  const p = file.path
  const action = actionFor(p)
  cleaning.value = p
  try {
    const preview = await executeAction(action, { path: p }, { dryRun: true })
    if (preview.blocked) {
      await ElMessageBox.alert(`护栏拦截，未执行。\n命令：${preview.command || '-'}\n原因：${preview.reason}`,
        '⛔ 被安全护栏拦截', { type: 'error' })
      return
    }
    await ElMessageBox.confirm(`将执行：${preview.command}\n护栏结论：${preview.reason}\n确认安全清理？`,
      '二次确认', { type: 'warning', confirmButtonText: '确认执行', cancelButtonText: '取消' })
    const res = await executeAction(action, { path: p }, { confirmed: true, dryRun: false })
    if (res.executed && res.ok) {
      ElMessage.success(`已安全清理：${p}（执行链 ${res.trace_id?.slice(0, 8)}）`)
      await run()
    } else if (res.blocked) { ElMessage.error(`护栏拦截：${res.reason}`) }
    else { ElMessage.warning(res.reason || '未执行') }
  } catch (e) { if (e !== 'cancel' && e !== 'close') ElMessage.info('已取消') }
  finally { cleaning.value = '' }
}

const fileClass = { critical: { cls: 'bad', t: '关键·勿删' }, cleanable: { cls: 'ok', t: '可清理' }, unknown: { cls: 'warn', t: '未知' } }
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="diagnose" :size="20" /> 根因体检</div>
        <div class="view-sub">不止告警——跨信号关联定位根因，给出证据链与置信度。只分析、只建议，绝不自动处置。</div>
      </div>
      <div class="view-actions">
        <el-input v-if="showPath" v-model="path" size="small" style="width:170px"
                  placeholder="扫描路径" :prefix-icon="undefined">
          <template #prefix><span class="mono muted" style="font-size:11px">path</span></template>
        </el-input>
        <button class="btn primary" :disabled="loading" @click="run()">
          <Icon name="play" :size="15" /> 运行诊断
        </button>
      </div>
    </div>

    <div class="view-body" v-loading="loading">
      <!-- 主题切换 -->
      <div class="topics">
        <button v-for="t in TOPICS" :key="t.key" class="topic" :class="{ on: topic === t.key }" @click="run(t.key)">
          <Icon :name="t.ic" :size="15" /> {{ t.label }}
        </button>
      </div>

      <div v-if="summary" class="summary"><Icon name="diagnose" :size="15" /> {{ summary }}</div>

      <div v-if="!report" class="hollow">
        <Icon name="diagnose" :size="30" class="he-ic" />
        <div>选择上方主题并运行诊断，结果将在此呈现根因与证据链。</div>
      </div>

      <!-- 报告卡 -->
      <div class="reports">
        <div v-for="(r, i) in reports" :key="i" class="panel lit report">
          <div class="r-head">
            <div class="r-title">{{ TOPIC_NAME[r.topic] || r.topic }}</div>
            <span class="sev" :class="r.severity || 'unknown'"><i class="sd" />{{ r.severity || 'unknown' }}</span>
            <span v-if="r.confidence != null" class="conf">
              置信度 <b>{{ Math.round(r.confidence * 100) }}%</b>
              <span class="conf-lbl">{{ r.confidence_label }}</span>
            </span>
          </div>

          <!-- 根因结论 -->
          <div v-if="r.root_cause" class="rootcause">
            <span class="rc-tag">根因</span>{{ r.root_cause }}
          </div>

          <!-- 置信度计量 -->
          <div v-if="r.confidence != null" class="meter" style="margin:10px 0 12px">
            <i :style="{ width: Math.round(r.confidence * 100) + '%' }" />
          </div>

          <!-- 证据链 -->
          <div v-if="r.chain && r.chain.length" class="chain">
            <div class="block-label"><Icon name="layers" :size="13" /> 证据链（信号关联 {{ (r.evidence || []).length }} 项）</div>
            <div v-for="(c, k) in r.chain" :key="k" class="chain-step">
              <span class="cs-dot" /><span class="cs-text">{{ c }}</span>
            </div>
          </div>

          <!-- 配置漂移：分列 changed/removed/added -->
          <div v-if="r.topic === 'configdrift'" class="drift">
            <div class="drift-stat">
              <span class="ds-pill"><b>{{ r.watched }}</b> 监控</span>
              <span class="ds-pill ok" v-if="r.baseline_pinned">基线已锚定</span>
              <span class="ds-pill bad" v-if="(r.critical_drift || []).length"><b>{{ r.critical_drift.length }}</b> 关键漂移</span>
            </div>
            <template v-for="grp in [
                { k: 'changed', t: '已变更', cls: 'warn' },
                { k: 'removed', t: '已消失', cls: 'bad' },
                { k: 'added', t: '新增', cls: 'info' }]" :key="grp.k">
              <div v-if="(r[grp.k] || []).length" class="drift-grp">
                <span class="dg-label" :class="grp.cls">{{ grp.t }}</span>
                <code v-for="f in r[grp.k]" :key="f" class="tok" :class="(r.critical_drift || []).includes(f) ? 'bad' : 'neutral'">{{ f }}</code>
              </div>
            </template>
            <button v-if="!r.baseline_pinned" class="btn ghost sm" @click="repin">
              <Icon name="pin" :size="13" /> 确认合法 · 重锚基线
            </button>
          </div>

          <!-- 大文件（磁盘）：可清理项走护栏二次确认 -->
          <div v-if="r.large_files && r.large_files.length" class="files">
            <div class="block-label"><Icon name="search" :size="13" /> 大文件 Top {{ r.large_files.length }}</div>
            <div v-for="(f, k) in r.large_files" :key="k" class="file">
              <span class="ichip" :class="(fileClass[f.class] || {}).cls">{{ (fileClass[f.class] || {}).t || f.class }}</span>
              <code class="f-path">{{ f.path }}</code>
              <span class="f-size">{{ f.size_mb }} MB</span>
              <button v-if="f.class === 'cleanable'" class="btn ghost xs" :disabled="cleaning === f.path" @click="safeClean(f)">
                {{ cleaning === f.path ? '清理中…' : '安全清理' }}
              </button>
            </div>
          </div>

          <!-- findings -->
          <div v-if="r.findings && r.findings.length" class="findings">
            <div v-for="(f, k) in r.findings" :key="k" class="finding">{{ f }}</div>
          </div>

          <!-- 建议（命令文本，给人看，绝不自动执行） -->
          <div v-if="r.suggestions && r.suggestions.length" class="suggest">
            <div class="block-label"><Icon name="check" :size="13" /> 处置建议</div>
            <div v-for="(s, k) in r.suggestions" :key="k" class="sg-line">{{ s }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.topics { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
.topic { display: inline-flex; align-items: center; gap: 7px; background: var(--ink-2); border: 1px solid var(--line);
  color: var(--text-1); border-radius: 999px; padding: 7px 14px; font-size: 13px; cursor: pointer; transition: all .15s; }
.topic:hover { border-color: var(--line-glow); color: var(--text-0); }
.topic.on { background: var(--jade-soft); border-color: rgba(43,217,154,.35); color: var(--jade); }

.summary { display: flex; align-items: center; gap: 9px; background: var(--cyan-soft); border: 1px solid rgba(56,189,248,.25);
  color: var(--text-0); border-radius: 10px; padding: 11px 14px; margin-bottom: 16px; font-size: 13.5px; }
.summary :deep(.icon) { color: var(--cyan); }

.reports { display: flex; flex-direction: column; gap: 14px; }
.report { padding: 16px 18px; }
.r-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.r-title { font-size: 15px; font-weight: 650; color: var(--text-0); }
.conf { font-size: 12px; color: var(--text-2); margin-left: auto; }
.conf b { color: var(--text-0); font-family: var(--mono); }
.conf-lbl { color: var(--jade); margin-left: 5px; }

.rootcause { margin-top: 12px; padding: 11px 13px; background: var(--ink-0); border: 1px solid var(--line); border-left: 3px solid var(--coral);
  border-radius: 8px; line-height: 1.66; font-size: 13.5px; color: var(--text-0); }
.rc-tag { display: inline-block; font-size: 11px; font-weight: 700; color: var(--coral); background: var(--coral-soft);
  padding: 1px 8px; border-radius: 6px; margin-right: 9px; }

.block-label { display: flex; align-items: center; gap: 6px; font-size: 11.5px; letter-spacing: .5px; color: var(--text-2);
  text-transform: uppercase; font-family: var(--mono); margin: 14px 0 8px; }
.block-label :deep(.icon) { color: var(--text-2); }

.chain-step { display: flex; gap: 10px; align-items: flex-start; padding: 4px 0; }
.cs-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--cyan); margin-top: 7px; flex: 0 0 auto; box-shadow: 0 0 7px var(--cyan); }
.cs-text { font-size: 13px; color: var(--text-1); line-height: 1.6; }

.drift { margin-top: 12px; }
.drift-stat { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
.ds-pill { font-size: 12px; color: var(--text-1); background: var(--ink-3); border: 1px solid var(--line); padding: 3px 10px; border-radius: 999px; }
.ds-pill b { color: var(--text-0); font-family: var(--mono); }
.ds-pill.ok { color: var(--jade); border-color: rgba(43,217,154,.3); }
.ds-pill.bad { color: var(--coral); border-color: rgba(255,99,99,.3); }
.drift-grp { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; margin-bottom: 8px; }
.dg-label { font-size: 11px; font-weight: 700; padding: 2px 9px; border-radius: 6px; flex: 0 0 auto; }
.dg-label.warn { background: var(--amber-soft); color: var(--amber); }
.dg-label.bad { background: var(--coral-soft); color: var(--coral); }
.dg-label.info { background: var(--cyan-soft); color: var(--cyan); }

.file { display: flex; align-items: center; gap: 10px; padding: 5px 0; font-size: 13px; border-bottom: 1px solid var(--line-soft); }
.file:last-child { border-bottom: none; }
.f-path { font-family: var(--mono); font-size: 12px; color: var(--text-1); word-break: break-all; }
.f-size { color: var(--text-2); margin-left: auto; white-space: nowrap; font-family: var(--mono); font-size: 12px; }
.ichip { font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px; flex: 0 0 auto; }
.ichip.ok { background: var(--jade-soft); color: var(--jade); }
.ichip.warn { background: var(--amber-soft); color: var(--amber); }
.ichip.bad { background: var(--coral-soft); color: var(--coral); }

.findings { margin-top: 12px; }
.finding { font-size: 13px; color: var(--text-1); line-height: 1.7; }
.finding::before { content: "· "; color: var(--text-2); }

.suggest { margin-top: 12px; padding: 11px 13px; background: var(--jade-soft); border: 1px solid rgba(43,217,154,.2); border-radius: 8px; }
.sg-line { font-size: 12.5px; color: var(--text-1); line-height: 1.7; white-space: pre-wrap; }

/* 按钮（与全局共用样式语言） */
.btn { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--line); background: var(--ink-2);
  color: var(--text-1); border-radius: 8px; padding: 7px 13px; font-size: 13px; cursor: pointer; transition: all .15s; font-family: var(--sans); }
.btn:hover:not(:disabled) { border-color: var(--line-glow); color: var(--text-0); }
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn.primary { background: var(--jade); color: #06140e; border-color: var(--jade); font-weight: 600; }
.btn.primary:hover:not(:disabled) { box-shadow: 0 0 16px rgba(43,217,154,.45); color: #06140e; }
.btn.ghost { background: transparent; }
.btn.sm { padding: 5px 11px; font-size: 12px; margin-top: 10px; }
.btn.xs { padding: 3px 10px; font-size: 12px; margin-left: auto; color: var(--jade); border-color: rgba(43,217,154,.3); }
.btn.xs:hover:not(:disabled) { background: var(--jade-soft); }
</style>
