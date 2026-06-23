<script setup>
/**
 * 执行链单段明细渲染。在「原始 JSON」之上对若干结构做友好可视化：
 *   - 安全校验段含 guard（含 ast_findings）→ 正则 / AST 双栏（GuardVerdict）
 *   - 安全校验段含 privilege_posture → 「最小权限落地身份」徽标（赛题需求④ per-action 证据）
 *   - 安全校验段含 rule_of_two → 「致命三要素 / Rule of Two」能力面小结
 *   - 执行结果段 output 含沙箱字段 → 「沙箱内执行 / 失控被掐死」横幅
 * 其余明细回退为原始 JSON。复用于内联对话 trace、回放与评委模式。
 */
import { computed } from 'vue'
import GuardVerdict from './GuardVerdict.vue'
import Icon from './Icon.vue'

const props = defineProps({ detail: { default: null } })

const isObj = computed(() => props.detail && typeof props.detail === 'object')
const guard = computed(() =>
  isObj.value && props.detail.guard && typeof props.detail.guard === 'object'
    ? props.detail.guard : null)

// 最小权限落地态势（actions.py 写入安全校验段）
const posture = computed(() =>
  isObj.value && props.detail.privilege_posture && typeof props.detail.privilege_posture === 'object'
    ? props.detail.privilege_posture : null)
const postureKind = computed(() => {
  const p = posture.value
  if (!p) return null
  if (p.elevated_landing) return { cls: 'bad', text: '⚠ 以 root 落地', ic: 'alert' }
  if (!p.running_as_root) return { cls: 'ok', text: '非 root · 受限账户落地', ic: 'lock' }
  if (p.drop_usable) return { cls: 'ok', text: `降权 → ${p.drop_target}`, ic: 'lock' }
  return { cls: 'warn', text: '权限态势', ic: 'lock' }
})

// 致命三要素 / Rule of Two 能力面（actions.py 写入安全校验段）
const rot = computed(() =>
  isObj.value && props.detail.rule_of_two && typeof props.detail.rule_of_two === 'object'
    ? props.detail.rule_of_two : null)

// 深度思考思维链（orchestrator._push_thinking 写入「推理决策」段）：
// 把 DeepSeek 推理模型返回的 reasoning_content 原样展示，是「可追溯思维链」最直接的证据。
const thinking = computed(() =>
  isObj.value && props.detail.source === 'deepseek_reasoning'
    && typeof props.detail.thinking === 'string'
    ? props.detail : null)

// 安全研判的思维链（risk_assessor 写入「安全校验」段的双层意图研判）：深度思考时
// 把 AI 安全评审「为何判危险」的推理过程也展示出来，呼应「解决 AI 推理不可控」命题。
const riskThinking = computed(() => {
  const aj = isObj.value && props.detail.phase === '双层意图研判'
    ? props.detail.ai_judgment : null
  return aj && typeof aj.thinking === 'string' && aj.thinking ? aj.thinking : null
})

// 沙箱处置（执行结果段）
const sandbox = computed(() => {
  const o = isObj.value ? props.detail.output : null
  if (o && typeof o === 'object' && ('limit_hit' in o || 'sandbox_killed' in o)) return o
  return null
})
const sbKilled = computed(() => !!sandbox.value && !!(sandbox.value.sandbox_killed || sandbox.value.limit_hit))

const enriched = computed(() =>
  !!guard.value || !!sandbox.value || !!posture.value || !!rot.value
  || !!thinking.value || !!riskThinking.value)
function pretty(d) { return typeof d === 'string' ? d : JSON.stringify(d, null, 2) }
</script>

<template>
  <div class="td-body">
    <!-- 深度思考思维链：DeepSeek 推理模型的真实思考过程（可追溯思维链最直接证据） -->
    <div v-if="thinking" class="think-card">
      <div class="think-h">
        <Icon name="judge" :size="14" />
        <span class="think-t">DeepSeek 思维链</span>
        <span class="think-by">{{ thinking.by }}</span>
      </div>
      <div class="think-body">{{ thinking.thinking }}</div>
    </div>

    <!-- 安全研判思维链：AI 安全评审「为何判危险」的推理过程（深度思考时） -->
    <div v-if="riskThinking" class="think-card">
      <div class="think-h">
        <Icon name="judge" :size="14" />
        <span class="think-t">DeepSeek 思维链</span>
        <span class="think-by">安全研判</span>
      </div>
      <div class="think-body">{{ riskThinking }}</div>
    </div>

    <GuardVerdict v-if="guard" :guard="guard" />

    <!-- 最小权限落地身份 -->
    <div v-if="posture" class="mini" :class="postureKind.cls">
      <div class="mini-h">
        <Icon :name="postureKind.ic" :size="14" />
        <span class="mini-t">最小权限落地</span>
        <span class="mini-badge" :class="postureKind.cls">{{ postureKind.text }}</span>
      </div>
      <div class="mini-r">{{ posture.reason }}</div>
    </div>

    <!-- 致命三要素 / Rule of Two -->
    <div v-if="rot" class="mini" :class="rot.rule_of_two_satisfied ? 'ok' : 'bad'">
      <div class="mini-h">
        <Icon name="capability" :size="14" />
        <span class="mini-t">致命三要素 · Rule of Two</span>
        <span class="mini-badge neutral">{{ rot.leg_count }}/3 腿</span>
        <span class="mini-badge" :class="rot.rule_of_two_satisfied ? 'ok' : 'bad'">
          {{ rot.rule_of_two_satisfied ? '✓ 满足' : '✗ 需人工审批' }}
        </span>
        <span v-if="rot.human_in_loop" class="mini-badge warn">人工在环</span>
      </div>
      <div v-if="rot.legs && rot.legs.length" class="mini-legs">
        <span v-for="l in rot.legs" :key="l" class="leg-chip">{{ l }}</span>
      </div>
      <div v-if="rot.note" class="mini-r">{{ rot.note }}</div>
    </div>

    <!-- 沙箱处置 -->
    <div v-if="sandbox" class="sb" :class="sbKilled ? 'bad' : 'ok'">
      <Icon :name="sbKilled ? 'bolt' : 'check'" :size="15" />
      <div class="sb-body">
        <div class="sb-t">{{ sbKilled
          ? `失控进程被执行沙箱掐死（命中限额：${sandbox.limit_hit || '未知'}）`
          : `命令在执行沙箱内安全落地（后端：${sandbox.sandbox || 'rlimit'}）` }}</div>
        <div class="sb-meta">
          后端 <code>{{ sandbox.sandbox || '-' }}</code> · 被杀 {{ sandbox.sandbox_killed }} ·
          命中限额 {{ sandbox.limit_hit || '无' }}
        </div>
      </div>
    </div>

    <!-- 富视图存在时原始 JSON 收进折叠；否则直接展示（保旧行为） -->
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

/* 深度思考思维链卡（amber，与「推理决策」段同色系） */
.think-card { border: 1px solid rgba(243,181,61,.3); border-left: 3px solid var(--amber);
  border-radius: 8px; background: var(--amber-soft); padding: 9px 11px; }
.think-h { display: flex; align-items: center; gap: 7px; }
.think-h :deep(.icon) { color: var(--amber); flex: 0 0 auto; }
.think-t { font-size: 12.5px; font-weight: 600; color: var(--amber); }
.think-by { font-size: 10.5px; font-family: var(--mono); color: var(--text-2);
  background: var(--ink-2); padding: 1px 7px; border-radius: 999px; }
.think-body { margin-top: 7px; font-size: 12px; line-height: 1.66; color: var(--text-1);
  white-space: pre-wrap; word-break: break-word; max-height: 240px; overflow-y: auto;
  font-family: var(--mono); padding-right: 4px; }

.mini { border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; background: var(--ink-1); border-left-width: 3px; }
.mini.ok { border-left-color: var(--jade); }
.mini.warn { border-left-color: var(--amber); }
.mini.bad { border-left-color: var(--coral); }
.mini-h { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; color: var(--text-1); }
.mini-t { font-size: 12.5px; font-weight: 600; color: var(--text-0); }
.mini-badge { font-size: 11px; padding: 1px 8px; border-radius: 999px; font-weight: 600; }
.mini-badge.ok { background: var(--jade-soft); color: var(--jade); }
.mini-badge.warn { background: var(--amber-soft); color: var(--amber); }
.mini-badge.bad { background: var(--coral-soft); color: var(--coral); }
.mini-badge.neutral { background: var(--ink-3); color: var(--text-1); font-family: var(--mono); }
.mini-r { font-size: 11.5px; color: var(--text-2); line-height: 1.55; margin-top: 5px; }
.mini-legs { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 6px; }
.leg-chip { font-family: var(--mono); font-size: 10.5px; color: var(--cyan); background: var(--cyan-soft); padding: 1px 7px; border-radius: 6px; }

.sb { display: flex; gap: 9px; align-items: flex-start; border: 1px solid var(--line); border-radius: 8px; padding: 9px 11px; }
.sb.ok { background: var(--jade-soft); color: var(--jade); }
.sb.bad { background: var(--coral-soft); color: var(--coral); }
.sb-body { min-width: 0; }
.sb-t { font-size: 12.5px; font-weight: 600; }
.sb-meta { font-size: 11px; color: var(--text-2); margin-top: 2px; }
.sb-meta code { background: var(--ink-3); padding: 0 4px; border-radius: 3px; color: var(--text-1); }

.detail {
  margin: 0; padding: 9px 11px; background: var(--ink-0); border: 1px solid var(--line-soft); border-radius: 7px;
  font-size: 11.5px; white-space: pre-wrap; word-break: break-all; color: var(--text-1); line-height: 1.55;
}
.td-raw { border: none; --el-collapse-border-color: var(--line-soft); }
.td-raw :deep(.el-collapse-item__header) { font-size: 12px; height: 30px; line-height: 30px; background: transparent; color: var(--text-2); border: none; }
.td-raw :deep(.el-collapse-item__wrap) { background: transparent; border: none; }
.td-raw :deep(.el-collapse-item__content) { padding-bottom: 6px; }
</style>
