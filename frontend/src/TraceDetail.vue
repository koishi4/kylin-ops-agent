<script setup>
/**
 * 执行链单段明细渲染。在「原始 JSON」之上对若干结构做友好可视化：
 *   - 安全校验段含 guard（含 ast_findings）→ 正则 / AST 双栏（GuardVerdict）
 *   - 安全校验段含 privilege_posture → 「最小权限落地身份」徽标（赛题需求④ per-action 证据）
 *   - 安全校验段含 rule_of_two → 「致命三要素 / Rule of Two」能力面小结
 *   - 推理决策段含 reasoning_content → 深度思考思维链卡
 *   - 执行结果段 output 含沙箱字段 → 「沙箱内执行 / 失控被掐死」横幅
 * 其余明细回退为原始 JSON（native details 折叠）。复用于内联对话 trace、回放与评委模式。
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
  if (p.elevated_landing) return { cls: 'bad', text: '以 root 落地', ic: 'alert' }
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

// 安全研判的思维链（risk_assessor 写入「安全校验」段的双层意图研判）
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
        <Icon name="judge" :size="13" />
        <span class="think-t">模型思维链</span>
        <span class="tag mono">{{ thinking.by }}</span>
      </div>
      <div class="think-body">{{ thinking.thinking }}</div>
    </div>

    <!-- 安全研判思维链：AI 安全评审「为何判危险」的推理过程（深度思考时） -->
    <div v-if="riskThinking" class="think-card">
      <div class="think-h">
        <Icon name="judge" :size="13" />
        <span class="think-t">模型思维链</span>
        <span class="tag mono">安全研判</span>
      </div>
      <div class="think-body">{{ riskThinking }}</div>
    </div>

    <GuardVerdict v-if="guard" :guard="guard" />

    <!-- 最小权限落地身份 -->
    <div v-if="posture" class="mini" :class="postureKind.cls">
      <div class="mini-h">
        <Icon :name="postureKind.ic" :size="13" />
        <span class="mini-t">最小权限落地</span>
        <span class="tag" :class="postureKind.cls">{{ postureKind.text }}</span>
      </div>
      <div class="mini-r">{{ posture.reason }}</div>
    </div>

    <!-- 致命三要素 / Rule of Two -->
    <div v-if="rot" class="mini" :class="rot.rule_of_two_satisfied ? 'ok' : 'bad'">
      <div class="mini-h">
        <Icon name="capability" :size="13" />
        <span class="mini-t">致命三要素 · Rule of Two</span>
        <span class="tag mono">{{ rot.leg_count }}/3 腿</span>
        <span class="tag" :class="rot.rule_of_two_satisfied ? 'ok' : 'bad'">
          {{ rot.rule_of_two_satisfied ? '满足' : '需人工审批' }}
        </span>
        <span v-if="rot.human_in_loop" class="tag warn">人工在环</span>
      </div>
      <div v-if="rot.legs && rot.legs.length" class="mini-legs">
        <span v-for="l in rot.legs" :key="l" class="tag mono info">{{ l }}</span>
      </div>
      <div v-if="rot.note" class="mini-r">{{ rot.note }}</div>
    </div>

    <!-- 沙箱处置 -->
    <div v-if="sandbox" class="mini" :class="sbKilled ? 'bad' : 'ok'">
      <div class="mini-h">
        <Icon :name="sbKilled ? 'bolt' : 'check'" :size="13" />
        <span class="mini-t">{{ sbKilled
          ? `失控进程被执行沙箱掐死（命中限额：${sandbox.limit_hit || '未知'}）`
          : `命令在执行沙箱内安全落地（后端：${sandbox.sandbox || 'rlimit'}）` }}</span>
      </div>
      <div class="mini-r">
        后端 <code class="tok">{{ sandbox.sandbox || '-' }}</code> · 被杀 {{ sandbox.sandbox_killed }} ·
        命中限额 {{ sandbox.limit_hit || '无' }}
      </div>
    </div>

    <!-- 富视图存在时原始 JSON 收进折叠；否则直接展示（保旧行为） -->
    <details v-if="enriched" class="raw">
      <summary>原始明细 JSON</summary>
      <pre class="detail">{{ pretty(detail) }}</pre>
    </details>
    <pre v-else class="detail">{{ pretty(detail) }}</pre>
  </div>
</template>

<style scoped>
.td-body { display: flex; flex-direction: column; gap: 8px; }

/* 深度思考思维链卡（琥珀左线，与「推理决策」段同色系） */
.think-card { border: 1px solid var(--line); border-left: 2px solid var(--warn);
  border-radius: var(--r-s); background: var(--s0); padding: 9px 11px; }
.think-h { display: flex; align-items: center; gap: 7px; }
.think-h .icon { color: var(--warn); }
.think-t { font-size: 12px; font-weight: 600; color: var(--warn); }
.think-body { margin-top: 7px; font-size: 11.5px; line-height: 1.66; color: var(--t1);
  white-space: pre-wrap; word-break: break-word; max-height: 240px; overflow-y: auto;
  font-family: var(--mono); padding-right: 4px; }

.mini { border: 1px solid var(--line); border-radius: var(--r-s); padding: 8px 10px;
  background: var(--s0); border-left-width: 2px; }
.mini.ok { border-left-color: var(--ok); }
.mini.warn { border-left-color: var(--warn); }
.mini.bad { border-left-color: var(--bad); }
.mini-h { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; color: var(--t1); }
.mini-h .icon { color: var(--t2); }
.mini-t { font-size: 12px; font-weight: 600; color: var(--t0); }
.mini-legs { display: flex; gap: 5px; flex-wrap: wrap; margin-top: 6px; }
.mini-r { font-size: 11.5px; color: var(--t2); line-height: 1.55; margin-top: 5px; }
</style>
