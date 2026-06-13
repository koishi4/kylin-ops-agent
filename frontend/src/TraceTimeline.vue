<script setup>
/**
 * 五段执行链时间线（接收指令 → 感知环境 → 推理决策 → 安全校验 → 执行结果）。
 * 自绘竖向链路（不直接用 el-timeline），每段按阶段语义着色、带发光节点与连接线，
 * 是「可追溯思维链」这一核心卖点的统一视觉载体。复用于对话内联、审计回放、评委模式。
 */
import Icon from './Icon.vue'
import TraceDetail from './TraceDetail.vue'

defineProps({
  steps: { type: Array, default: () => [] },
  showTime: { type: Boolean, default: false },
})

// 阶段 → 主题色变量 + 序号字（前缀去重，兼容偶发的别名）
const STAGE = {
  接收指令: { c: 'var(--stage-recv)', n: 1 },
  感知环境: { c: 'var(--stage-perc)', n: 2 },
  推理决策: { c: 'var(--stage-reason)', n: 3 },
  安全校验: { c: 'var(--stage-verify)', n: 4 },
  执行结果: { c: 'var(--stage-result)', n: 5 },
}
function meta(stage) { return STAGE[stage] || { c: 'var(--slate)', n: '·' } }
function fmt(ts) { return ts ? new Date(ts * 1000).toLocaleTimeString() : '' }
</script>

<template>
  <div class="tl">
    <div v-for="(s, i) in steps" :key="i" class="tl-step">
      <div class="tl-gutter">
        <span class="tl-node" :style="{ '--sc': meta(s.stage).c }">{{ meta(s.stage).n }}</span>
        <span v-if="i < steps.length - 1" class="tl-line" />
      </div>
      <div class="tl-content">
        <div class="tl-head">
          <span class="tl-stage" :style="{ color: meta(s.stage).c }">{{ s.stage }}</span>
          <span v-if="showTime && s.ts" class="tl-time">{{ fmt(s.ts) }}</span>
        </div>
        <TraceDetail :detail="s.detail" />
      </div>
    </div>
    <div v-if="!steps.length" class="tl-empty">
      <Icon name="audit" :size="22" /> 暂无执行链
    </div>
  </div>
</template>

<style scoped>
.tl { display: flex; flex-direction: column; }
.tl-step { display: grid; grid-template-columns: 30px 1fr; gap: 12px; }
.tl-gutter { display: flex; flex-direction: column; align-items: center; }
.tl-node {
  width: 26px; height: 26px; border-radius: 50%; flex: 0 0 auto;
  display: flex; align-items: center; justify-content: center;
  font-family: var(--mono); font-size: 12px; font-weight: 700; color: var(--sc);
  background: var(--ink-1); border: 1.5px solid var(--sc);
  box-shadow: 0 0 10px color-mix(in srgb, var(--sc) 45%, transparent);
}
.tl-line { flex: 1; width: 2px; min-height: 14px; margin: 3px 0; background: linear-gradient(var(--line-glow), var(--line-soft)); }
.tl-content { min-width: 0; padding-bottom: 16px; }
.tl-head { display: flex; align-items: center; gap: 10px; margin-bottom: 7px; }
.tl-stage { font-weight: 650; font-size: 13.5px; letter-spacing: .3px; }
.tl-time { font-family: var(--mono); font-size: 11px; color: var(--text-2); }
.tl-empty { display: flex; align-items: center; gap: 8px; color: var(--text-2); padding: 20px 0; }
</style>
