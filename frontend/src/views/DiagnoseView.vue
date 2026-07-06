<script setup>
/**
 * 根因体检视图（评分④）。
 * 支持全部诊断主题：磁盘 / 内存(泄漏·压力) / 负载 / 磁盘IO / 僵尸 / 配置漂移 / 全面体检。
 * 关键卖点可视化：根因结论 + 置信度计量条 + 证据链（信号关联）；磁盘「可清理」项走护栏
 * 二次确认安全清理；配置漂移按 changed/removed/added 分列，确认合法后可重锚 TOFU 基线。
 */
import { ref, computed } from 'vue'
import { diagnose, executeAction } from '../api.js'
import { message, confirmBox, alertBox } from '../ui.js'
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
    message.error('诊断失败：' + (e.message || e))
  } finally {
    loading.value = false
  }
}

// 配置漂移：确认所有变更合法后重锚基线（TOFU re-pin）
async function repin() {
  const ok = await confirmBox({
    title: '重锚配置基线',
    body: '重锚会把「当前」配置指纹设为新基线，之后的漂移以此为准。\n请仅在确认所有变更均为合法计划内变更后操作。',
    confirmText: '确认重锚',
  })
  if (!ok) return
  try {
    await diagnose('configdrift', '/', { pin: true })
    message.success('已重锚配置基线')
    await run('configdrift')
  } catch (e) { message.error('重锚失败：' + (e.message || e)) }
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
      await alertBox({ title: '被安全护栏拦截', danger: true,
        body: `护栏拦截，未执行。\n命令：${preview.command || '-'}\n原因：${preview.reason}` })
      return
    }
    const ok = await confirmBox({
      title: '二次确认 · 安全清理',
      body: `将执行：${preview.command}\n护栏结论：${preview.reason}`,
      confirmText: '确认执行', danger: true,
    })
    if (!ok) return
    const res = await executeAction(action, { path: p }, { confirmed: true, dryRun: false })
    if (res.executed && res.ok) {
      message.success(`已安全清理：${p}（执行链 ${res.trace_id?.slice(0, 8)}）`)
      await run()
    } else if (res.blocked) { message.error(`护栏拦截：${res.reason}`) }
    else { message.warning(res.reason || '未执行') }
  } catch (e) { message.error('清理失败：' + (e.message || e)) }
  finally { cleaning.value = '' }
}

const fileClass = { critical: { cls: 'bad', t: '关键·勿删' }, cleanable: { cls: 'ok', t: '可清理' }, unknown: { cls: 'warn', t: '未知' } }
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="diagnose" :size="19" /> 根因体检</div>
        <div class="view-sub">不止告警——跨信号关联定位根因，给出证据链与置信度。只分析、只建议，绝不自动处置。</div>
      </div>
      <div class="view-actions">
        <input v-if="showPath" v-model="path" class="field" style="width:160px" placeholder="扫描路径" />
        <button class="btn primary" :disabled="loading" @click="run()">
          <Icon name="play" :size="14" /> 运行诊断
        </button>
      </div>
    </div>

    <div class="view-body">
      <!-- 主题切换 -->
      <div class="topics">
        <button v-for="t in TOPICS" :key="t.key" class="btn sm" :class="{ picked: topic === t.key }" @click="run(t.key)">
          <Icon :name="t.ic" :size="13" /> {{ t.label }}
        </button>
      </div>

      <div v-if="loading" class="busyline"><span class="spin" /> 正在采集信号并关联分析…</div>

      <div v-if="summary" class="note info" style="margin-bottom:14px">{{ summary }}</div>

      <div v-if="!report && !loading" class="hollow">
        <Icon name="diagnose" :size="28" />
        <div>选择上方主题并运行诊断，结果将在此呈现根因与证据链。</div>
      </div>

      <!-- 报告卡 -->
      <div class="reports">
        <div v-for="(r, i) in reports" :key="i" class="panel report">
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
            <div class="block-label">证据链 · 信号关联 {{ (r.evidence || []).length }} 项</div>
            <div v-for="(c, k) in r.chain" :key="k" class="chain-step">
              <span class="cs-no mono">{{ k + 1 }}</span><span class="cs-text">{{ c }}</span>
            </div>
          </div>

          <!-- 配置漂移：分列 changed/removed/added -->
          <div v-if="r.topic === 'configdrift'" class="drift">
            <div class="drift-stat">
              <span class="tag line"><b>{{ r.watched }}</b>&nbsp;监控</span>
              <span v-if="r.baseline_pinned" class="tag ok">基线已锚定</span>
              <span v-if="(r.critical_drift || []).length" class="tag bad">{{ r.critical_drift.length }} 关键漂移</span>
            </div>
            <template v-for="grp in [
                { k: 'changed', t: '已变更', cls: 'warn' },
                { k: 'removed', t: '已消失', cls: 'bad' },
                { k: 'added', t: '新增', cls: 'info' }]" :key="grp.k">
              <div v-if="(r[grp.k] || []).length" class="drift-grp">
                <span class="tag" :class="grp.cls">{{ grp.t }}</span>
                <code v-for="f in r[grp.k]" :key="f" class="tok" :class="{ bad: (r.critical_drift || []).includes(f) }">{{ f }}</code>
              </div>
            </template>
            <button v-if="!r.baseline_pinned" class="btn ghost sm" style="margin-top:8px" @click="repin">
              <Icon name="pin" :size="13" /> 确认合法 · 重锚基线
            </button>
          </div>

          <!-- 大文件（磁盘）：可清理项走护栏二次确认 -->
          <div v-if="r.large_files && r.large_files.length" class="files">
            <div class="block-label">大文件 Top {{ r.large_files.length }}</div>
            <div v-for="(f, k) in r.large_files" :key="k" class="file">
              <span class="tag" :class="(fileClass[f.class] || {}).cls">{{ (fileClass[f.class] || {}).t || f.class }}</span>
              <code class="f-path">{{ f.path }}</code>
              <span class="f-size mono">{{ f.size_mb }} MB</span>
              <button v-if="f.class === 'cleanable'" class="btn okline xs" :disabled="cleaning === f.path" @click="safeClean(f)">
                {{ cleaning === f.path ? '清理中…' : '安全清理' }}
              </button>
            </div>
          </div>

          <!-- findings -->
          <div v-if="r.findings && r.findings.length" class="findings">
            <div v-for="(f, k) in r.findings" :key="k" class="finding">{{ f }}</div>
          </div>

          <!-- 建议（命令文本，给人看，绝不自动执行） -->
          <div v-if="r.suggestions && r.suggestions.length" class="suggest note ok">
            <div class="block-label" style="margin:0 0 6px">处置建议</div>
            <div v-for="(s, k) in r.suggestions" :key="k" class="sg-line">{{ s }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.topics { display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 16px; }
.btn.picked { border-color: var(--acc); color: var(--acc); background: var(--acc-soft); }

.reports { display: flex; flex-direction: column; gap: 12px; }
.report { padding: 15px 17px; }
.r-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.r-title { font-size: 14px; font-weight: 650; color: var(--t0); }
.conf { font-size: 12px; color: var(--t2); margin-left: auto; }
.conf b { color: var(--t0); font-family: var(--mono); }
.conf-lbl { color: var(--acc); margin-left: 5px; }

.rootcause {
  margin-top: 12px; padding: 10px 13px; background: var(--bg); border: 1px solid var(--line);
  border-left: 2px solid var(--bad); border-radius: var(--r-s);
  line-height: 1.66; font-size: 13px; color: var(--t0);
}
.rc-tag {
  display: inline-block; font-size: 11px; font-weight: 700; color: var(--bad);
  background: var(--bad-soft); padding: 0 7px; border-radius: var(--r-s); margin-right: 9px;
}

.chain-step { display: flex; gap: 10px; align-items: baseline; padding: 3px 0; }
.cs-no { font-size: 10.5px; color: var(--info); border: 1px solid var(--line-2); border-radius: var(--r-s);
  width: 18px; height: 18px; display: inline-flex; align-items: center; justify-content: center; flex: 0 0 auto; transform: translateY(3px); }
.cs-text { font-size: 12.5px; color: var(--t1); line-height: 1.6; }

.drift { margin-top: 12px; }
.drift-stat { display: flex; gap: 7px; flex-wrap: wrap; margin-bottom: 10px; }
.drift-grp { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-bottom: 7px; }

.file { display: flex; align-items: center; gap: 10px; padding: 5px 0; font-size: 12.5px; border-bottom: 1px solid var(--line); }
.file:last-child { border-bottom: none; }
.f-path { font-family: var(--mono); font-size: 11.5px; color: var(--t1); word-break: break-all; }
.f-size { color: var(--t2); margin-left: auto; white-space: nowrap; font-size: 11.5px; }

.findings { margin-top: 12px; }
.finding { font-size: 12.5px; color: var(--t1); line-height: 1.7; }
.finding::before { content: "— "; color: var(--t2); }

.suggest { margin-top: 12px; }
.sg-line { font-size: 12.5px; color: var(--t1); line-height: 1.7; white-space: pre-wrap; }
</style>
