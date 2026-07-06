<script setup>
/**
 * 能力边界视图（评分③ 架构主张）：致命三要素 / Meta「Rule of Two」能力面板 + MCP 工具供应链扫描。
 * 主张「即使 LLM 被诱导也炸不了系统」靠架构——感知层全部只读、能力上限 ≤2 腿（无『改状态/外联』），
 * 第三条腿只存于强制二次确认的动作层。表格逐工具列出三腿，扫描则检测元数据投毒/影子/隐形载荷并处置。
 */
import { ref, computed, onMounted } from 'vue'
import { getTrifecta, getToolScan } from '../api.js'
import { message } from '../ui.js'
import Icon from '../Icon.vue'

const data = ref(null)
const loading = ref(false)
const levelCls = { READONLY: 'ok', MUTATING: 'warn', UNKNOWN: '' }

const scanning = ref(false)
const scan = ref(null)
const scanStatus = { isolated: { cls: 'bad', t: '已隔离' }, review: { cls: 'warn', t: '需复核' }, cleared: { cls: 'ok', t: '已放行' } }

async function load() {
  loading.value = true
  try { data.value = await getTrifecta() } finally { loading.value = false }
}
async function runScan() {
  scanning.value = true
  try {
    scan.value = await getToolScan()
    if (scan.value.ok) message.success(`供应链扫描通过：${scan.value.scanned} 个工具元数据洁净`)
    else message.warning(`命中 ${scan.value.flagged} 个可疑工具`)
  } catch (e) { message.error('扫描失败：' + (e.message || e)) }
  finally { scanning.value = false }
}

const inv = computed(() => (data.value && data.value.invariant) || {})
const suspicious = computed(() => (scan.value && scan.value.tools || []).filter(t => t.suspicious))
// 默认按能力腿数降序，最「重」的能力面排最前
const sortedTools = computed(() =>
  ((data.value && data.value.tools) || []).slice().sort((a, b) => b.leg_count - a.leg_count))

onMounted(load)
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="capability" :size="19" /> 能力边界</div>
        <div class="view-sub">致命三要素 / Rule of Two：一条路径同时集齐「不可信内容 + 敏感数据 + 改状态/外联」才危险；至多两者即安全。</div>
      </div>
      <div class="view-actions">
        <button class="btn ghost" :disabled="scanning" @click="runScan"><Icon name="scan" :size="14" /> 工具投毒扫描</button>
      </div>
    </div>

    <div class="view-body">
      <div v-if="loading" class="busyline"><span class="spin" /> 加载能力面…</div>

      <!-- 结构性不变量 -->
      <div v-if="data" class="note ok" style="margin-bottom:14px">
        <div class="inv-head">结构性安全不变量：感知层永不集齐致命三要素</div>
        <div class="inv-note">{{ inv.note }}</div>
        <div class="inv-stats">
          <span class="tag ok">只读工具能力腿上限 {{ inv.readonly_max_legs }}/3</span>
          <span class="tag" :class="inv.readonly_has_state_change ? 'bad' : 'ok'">
            含「改状态/外联」腿的只读工具：{{ inv.readonly_has_state_change ? '有（异常）' : '无' }}
          </span>
        </div>
      </div>

      <!-- 三腿图例 -->
      <div v-if="data" class="legend">
        <span class="leg-item"><span class="ld a" />A · 接触不可信内容</span>
        <span class="leg-item"><span class="ld b" />B · 访问敏感数据</span>
        <span class="leg-item"><span class="ld c" />C · 改状态 / 外联</span>
        <span class="muted" style="font-size:12px">— 集齐三者才危险</span>
      </div>

      <!-- 供应链扫描结果 -->
      <div v-if="scan" class="scan-bar">
        <span class="tag" :class="scan.ok ? 'ok' : 'bad'">
          {{ scan.ok ? `${scan.scanned} 工具元数据洁净` : `命中 ${scan.flagged}/${scan.scanned} 可疑工具` }}
        </span>
        <span v-if="scan.quarantined && scan.quarantined.length" class="tag bad solid">已隔离 {{ scan.quarantined.length }}（不进 LLM 上下文）</span>
        <span class="muted" style="font-size:12px">本地静态扫描，不上传文件/凭据；命中即隔离（fail-closed）</span>
      </div>
      <div v-if="scan && suspicious.length" class="scan-flags">
        <div v-for="t in suspicious" :key="t.name" class="flag">
          <span class="tag" :class="(scanStatus[t.status] || {}).cls">{{ (scanStatus[t.status] || {}).t || t.status }}</span>
          <code class="tok">{{ t.name }}</code>
          <span class="muted">{{ t.max_severity }} · {{ (t.findings || []).map(f => f.code).join(', ') }}</span>
        </div>
      </div>

      <!-- 能力矩阵 -->
      <div v-if="data" class="table-wrap" style="max-height:calc(100vh - 380px);margin-top:14px">
        <table class="table">
          <thead>
            <tr>
              <th>工具 / 动作</th><th>级别</th>
              <th style="text-align:center">A 不可信</th>
              <th style="text-align:center">B 敏感</th>
              <th style="text-align:center">C 改状态</th>
              <th style="text-align:center">能力腿</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in sortedTools" :key="row.name">
              <td class="mono">{{ row.name }}</td>
              <td><span class="tag" :class="levelCls[row.level]">{{ row.level }}</span></td>
              <td class="c"><span v-if="row.untrusted" class="dot a" /><span v-else class="dash">—</span></td>
              <td class="c"><span v-if="row.sensitive" class="dot b" /><span v-else class="dash">—</span></td>
              <td class="c"><span v-if="row.state_change" class="dot c3" /><span v-else class="dash">—</span></td>
              <td class="c"><span class="legs mono" :class="'n' + row.leg_count">{{ row.leg_count }}/3</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.inv-head { font-weight: 650; color: var(--ok); font-size: 13px; }
.inv-note { font-size: 12px; color: var(--t1); line-height: 1.7; margin: 8px 0 10px; }
.inv-stats { display: flex; gap: 8px; flex-wrap: wrap; }

.legend { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 12px; }
.leg-item { display: inline-flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--t1); }
.ld, .dot { display: inline-block; width: 9px; height: 9px; border-radius: 1px; }
.ld.a, .dot.a { background: var(--bad); }
.ld.b, .dot.b { background: var(--warn); }
.ld.c, .dot.c3 { background: var(--plum); }

.scan-bar { display: flex; gap: 9px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
.scan-flags { display: flex; flex-direction: column; gap: 6px; margin-bottom: 6px; }
.flag { display: flex; align-items: center; gap: 9px; font-size: 12.5px; }

td.c { text-align: center; }
.dash { color: var(--t2); }
.legs { font-size: 11.5px; font-weight: 700; padding: 1px 8px; border-radius: var(--r-s); }
.legs.n0 { color: var(--t2); background: var(--s2); }
.legs.n1 { color: var(--info); background: var(--info-soft); }
.legs.n2 { color: var(--warn); background: var(--warn-soft); }
.legs.n3 { color: var(--bad); background: var(--bad-soft); }
</style>
