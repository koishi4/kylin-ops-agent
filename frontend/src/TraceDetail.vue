<script setup>
/**
 * 执行链单段明细渲染（P4-2/P4-3 前端接入）。
 * 在原本的「原始 JSON」基础上，对两类结构做友好可视化：
 *   - 安全校验段含 guard（含 ast_findings）→ 渲染「正则 / AST 结构分析」两栏（GuardVerdict）
 *   - 执行结果段 output 含沙箱字段 → 渲染「沙箱内执行 / 失控被掐死」横幅
 * 其余明细仍回退为原始 JSON。复用于内联对话 trace 与回放抽屉。
 */
import { computed } from 'vue'
import GuardVerdict from './GuardVerdict.vue'

const props = defineProps({ detail: { default: null } })

const isObj = computed(() => props.detail && typeof props.detail === 'object')
// 命令护栏裁决（executor 护栏段把 GuardResult.to_dict() 放在 detail.guard）
const guard = computed(() =>
  isObj.value && props.detail.guard && typeof props.detail.guard === 'object'
    ? props.detail.guard : null)
// 沙箱处置（执行结果段 detail.output 里带 sandbox_killed/limit_hit/sandbox）
const sandbox = computed(() => {
  const o = isObj.value ? props.detail.output : null
  if (o && typeof o === 'object' && ('limit_hit' in o || 'sandbox_killed' in o)) return o
  return null
})
const sbKilled = computed(() => !!sandbox.value && !!(sandbox.value.sandbox_killed || sandbox.value.limit_hit))

const enriched = computed(() => !!guard.value || !!sandbox.value)
function pretty(d) { return typeof d === 'string' ? d : JSON.stringify(d, null, 2) }
</script>

<template>
  <div class="td-body">
    <GuardVerdict v-if="guard" :guard="guard" />

    <el-alert
      v-if="sandbox"
      :type="sbKilled ? 'error' : 'success'"
      :closable="false"
      class="sb"
      show-icon
      :title="sbKilled
        ? `⛔ 失控进程被执行沙箱掐死（命中限额：${sandbox.limit_hit || '未知'}）`
        : `✓ 命令在执行沙箱内安全落地（后端：${sandbox.sandbox || 'rlimit'}）`"
    >
      <div class="sb-meta">
        沙箱后端：<code>{{ sandbox.sandbox || '-' }}</code> ·
        被杀：{{ sandbox.sandbox_killed }} ·
        命中限额：{{ sandbox.limit_hit || '无（未触发）' }}
      </div>
    </el-alert>

    <!-- 富视图存在时，原始 JSON 收进折叠；否则直接展示 JSON（保持旧行为） -->
    <el-collapse v-if="enriched" class="td-raw">
      <el-collapse-item title="原始明细 (JSON)" name="raw">
        <pre class="detail">{{ pretty(detail) }}</pre>
      </el-collapse-item>
    </el-collapse>
    <pre v-else class="detail">{{ pretty(detail) }}</pre>
  </div>
</template>

<style scoped>
.td-body { display: flex; flex-direction: column; gap: 8px; }
.sb { margin: 0; }
.sb-meta { font-size: 12px; margin-top: 2px; }
.sb-meta code { background: rgba(0,0,0,.06); padding: 0 4px; border-radius: 3px; }
.td-raw :deep(.el-collapse-item__header) { font-size: 12px; height: 30px; line-height: 30px; }
</style>
