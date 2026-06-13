<script setup>
/**
 * 能力边界视图（评分③ 架构主张）：致命三要素 / Meta「Rule of Two」能力面板 + MCP 工具供应链扫描。
 * 主张「即使 LLM 被诱导也炸不了系统」靠架构——感知层全部只读、能力上限 ≤2 腿（无『改状态/外联』），
 * 第三条腿只存于强制二次确认的动作层。表格逐工具列出三腿，扫描则检测元数据投毒/影子/隐形载荷并处置。
 */
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { getTrifecta, getToolScan } from '../api.js'
import Icon from '../Icon.vue'

const data = ref(null)
const loading = ref(false)
const levelType = { READONLY: 'success', MUTATING: 'warning', UNKNOWN: 'info' }

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
    if (scan.value.ok) ElMessage.success(`供应链扫描通过：${scan.value.scanned} 个工具元数据洁净`)
    else ElMessage.warning(`命中 ${scan.value.flagged} 个可疑工具`)
  } catch (e) { ElMessage.error('扫描失败：' + (e.message || e)) }
  finally { scanning.value = false }
}

const inv = computed(() => (data.value && data.value.invariant) || {})
const suspicious = computed(() => (scan.value && scan.value.tools || []).filter(t => t.suspicious))

onMounted(load)
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="capability" :size="20" /> 能力边界</div>
        <div class="view-sub">致命三要素 / Rule of Two：一条路径同时集齐「不可信内容 + 敏感数据 + 改状态/外联」才危险；至多两者即安全。</div>
      </div>
      <div class="view-actions">
        <button class="btn ghost" :disabled="scanning" @click="runScan"><Icon name="scan" :size="15" /> 工具投毒扫描</button>
      </div>
    </div>

    <div class="view-body" v-loading="loading">
      <!-- 结构性不变量 -->
      <div v-if="data" class="invariant panel lit panel-pad">
        <div class="inv-head"><Icon name="check" :size="16" /> 结构性安全不变量：感知层永不集齐致命三要素</div>
        <div class="inv-note">{{ inv.note }}</div>
        <div class="inv-stats">
          <span class="ds-pill ok">只读工具能力腿上限 <b>{{ inv.readonly_max_legs }}/3</b></span>
          <span class="ds-pill" :class="inv.readonly_has_state_change ? 'bad' : 'ok'">
            含「改状态/外联」腿的只读工具：<b>{{ inv.readonly_has_state_change ? '有（异常！）' : '无' }}</b>
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
        <span class="ichip" :class="scan.ok ? 'ok' : 'bad'">
          {{ scan.ok ? `✓ ${scan.scanned} 工具元数据洁净` : `✗ 命中 ${scan.flagged}/${scan.scanned} 可疑工具` }}
        </span>
        <span v-if="scan.quarantined && scan.quarantined.length" class="ichip bad solid">🚫 已隔离 {{ scan.quarantined.length }}（不进 LLM 上下文）</span>
        <span class="muted" style="font-size:12px">本地静态扫描，不上传文件/凭据；命中即隔离（fail-closed）</span>
      </div>
      <div v-if="scan && suspicious.length" class="scan-flags">
        <div v-for="t in suspicious" :key="t.name" class="flag">
          <span class="ichip" :class="(scanStatus[t.status] || {}).cls">{{ (scanStatus[t.status] || {}).t || t.status }}</span>
          <code class="tok neutral">{{ t.name }}</code>
          <span class="muted">{{ t.max_severity }} · {{ (t.findings || []).map(f => f.code).join(', ') }}</span>
        </div>
      </div>

      <!-- 能力矩阵 -->
      <div v-if="data" class="panel" style="padding:4px 6px;margin-top:14px">
        <el-table :data="data.tools" size="small" height="calc(100vh - 420px)"
                  :default-sort="{ prop: 'leg_count', order: 'descending' }">
          <el-table-column prop="name" label="工具 / 动作" min-width="170" show-overflow-tooltip />
          <el-table-column label="级别" width="110">
            <template #default="{ row }"><el-tag size="small" :type="levelType[row.level]">{{ row.level }}</el-tag></template>
          </el-table-column>
          <el-table-column label="A 不可信" width="92" align="center">
            <template #default="{ row }"><span v-if="row.untrusted" class="dot a" /><span v-else class="dash">—</span></template>
          </el-table-column>
          <el-table-column label="B 敏感" width="86" align="center">
            <template #default="{ row }"><span v-if="row.sensitive" class="dot b" /><span v-else class="dash">—</span></template>
          </el-table-column>
          <el-table-column label="C 改状态" width="92" align="center">
            <template #default="{ row }"><span v-if="row.state_change" class="dot c" /><span v-else class="dash">—</span></template>
          </el-table-column>
          <el-table-column prop="leg_count" label="能力腿" width="100" align="center" sortable>
            <template #default="{ row }">
              <span class="legs" :class="'n' + row.leg_count">{{ row.leg_count }}/3</span>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.invariant { margin-bottom: 16px; }
.inv-head { display: flex; align-items: center; gap: 8px; font-weight: 650; color: var(--jade); font-size: 14px; }
.inv-head :deep(.icon) { color: var(--jade); }
.inv-note { font-size: 12.5px; color: var(--text-1); line-height: 1.7; margin: 9px 0 11px; }
.inv-stats { display: flex; gap: 9px; flex-wrap: wrap; }

.legend { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-bottom: 14px; }
.leg-item { display: inline-flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--text-1); }
.ld { width: 9px; height: 9px; border-radius: 50%; }
.ld.a, .dot.a { background: var(--coral); box-shadow: 0 0 7px var(--coral); }
.ld.b, .dot.b { background: var(--amber); box-shadow: 0 0 7px var(--amber); }
.ld.c, .dot.c { background: var(--violet); box-shadow: 0 0 7px var(--violet); }

.scan-bar { display: flex; gap: 9px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
.scan-flags { display: flex; flex-direction: column; gap: 6px; margin-bottom: 6px; }
.flag { display: flex; align-items: center; gap: 9px; font-size: 12.5px; }

.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; }
.dash { color: var(--text-2); }
.legs { font-family: var(--mono); font-size: 12px; font-weight: 700; padding: 2px 9px; border-radius: 7px; }
.legs.n0 { color: var(--text-2); background: var(--ink-3); }
.legs.n1 { color: var(--cyan); background: var(--cyan-soft); }
.legs.n2 { color: var(--amber); background: var(--amber-soft); }
.legs.n3 { color: var(--coral); background: var(--coral-soft); }

.ichip { font-size: 11.5px; font-weight: 600; padding: 3px 10px; border-radius: 999px; }
.ichip.ok { background: var(--jade-soft); color: var(--jade); }
.ichip.warn { background: var(--amber-soft); color: var(--amber); }
.ichip.bad { background: var(--coral-soft); color: var(--coral); }
.ichip.bad.solid { background: var(--coral); color: #1a0808; }
.ds-pill { font-size: 12px; color: var(--text-1); background: var(--ink-3); border: 1px solid var(--line); padding: 3px 10px; border-radius: 999px; }
.ds-pill b { color: var(--text-0); font-family: var(--mono); }
.ds-pill.ok { color: var(--jade); border-color: rgba(43,217,154,.3); }
.ds-pill.bad { color: var(--coral); border-color: rgba(255,99,99,.3); }

.btn { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--line); background: var(--ink-2);
  color: var(--text-1); border-radius: 8px; padding: 7px 13px; font-size: 13px; cursor: pointer; transition: all .15s; font-family: var(--sans); }
.btn:hover:not(:disabled) { border-color: var(--line-glow); color: var(--text-0); }
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn.ghost { background: transparent; }
</style>
