<script setup>
/**
 * 小型开关（自持实现，替代组件库 switch）：role=switch，键盘可达。
 */
defineProps({ modelValue: { type: Boolean, default: false } })
const emit = defineEmits(['update:modelValue'])
</script>

<template>
  <button type="button" role="switch" :aria-checked="modelValue" class="tgl"
          :class="{ on: modelValue }" @click="emit('update:modelValue', !modelValue)">
    <span class="knob" />
  </button>
</template>

<style scoped>
.tgl {
  width: 32px; height: 18px; border-radius: 9px; padding: 0; position: relative;
  border: 1px solid var(--line-2); background: var(--s2); cursor: pointer;
  transition: background .15s, border-color .15s; flex: 0 0 auto;
}
.tgl .knob {
  position: absolute; top: 2px; left: 2px; width: 12px; height: 12px; border-radius: 50%;
  background: var(--t2); transition: left .15s, background .15s;
}
.tgl.on { background: var(--acc-deep); border-color: var(--acc-deep); }
.tgl.on .knob { left: 16px; background: #eef3f8; }
</style>
