<script setup>
/**
 * 右侧抽屉（自持实现，替代组件库 drawer）：overlay 点击或 Esc 关闭，宽度可定制。
 */
import { watch, onUnmounted } from 'vue'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  title: { type: String, default: '' },
  width: { type: String, default: '460px' },
})
const emit = defineEmits(['update:modelValue'])
function close() { emit('update:modelValue', false) }

function onKey(e) { if (e.key === 'Escape') close() }
watch(() => props.modelValue, (v) => {
  if (v) document.addEventListener('keydown', onKey)
  else document.removeEventListener('keydown', onKey)
})
onUnmounted(() => document.removeEventListener('keydown', onKey))
</script>

<template>
  <Teleport to="body">
    <div v-if="modelValue" class="overlay" @click="close" />
    <div v-if="modelValue" class="drawer-panel" :style="{ width }">
      <div class="drawer-head">
        {{ title }}
        <button class="drawer-x" aria-label="关闭" @click="close">✕</button>
      </div>
      <div class="drawer-body"><slot /></div>
    </div>
  </Teleport>
</template>
