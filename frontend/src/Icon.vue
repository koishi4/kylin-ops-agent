<script setup>
/**
 * 统一的描边图标组件（自绘 SVG，stroke=currentColor）。
 * 刻意不用 emoji 图标——emoji 正是「一眼 AI 模板」的来源之一；改用一致笔触的线性图标，
 * 随父级 color 着色、随主题统一，是去模板化的关键视觉信号。每个名字对应一组 path d。
 */
const props = defineProps({
  name: { type: String, required: true },
  size: { type: [Number, String], default: 20 },
  width: { type: Number, default: 1.6 },
})

// 每个图标 = 一组 path 的 d 属性（viewBox 0 0 24 24，圆角端点）
const P = {
  // 导航
  console: ['M5 4h14a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H9l-4 4V6a2 2 0 0 1 2-2z', 'M8.5 10h.01', 'M12 10h.01', 'M15.5 10h.01'],
  diagnose: ['M3 12h4l2 6 4-15 3 11 1.5-2H21'],
  guardrail: ['M12 3l7 3v5.5c0 4.6-3 7.6-7 9-4-1.4-7-4.4-7-9V6z', 'M9 12l2 2 4-4.5'],
  capability: ['M12 3v17', 'M6 20h12', 'M12 5.5l-6 2', 'M12 5.5l6 2', 'M3.2 12a2.8 2.8 0 0 0 5.6 0', 'M15.2 12a2.8 2.8 0 0 0 5.6 0', 'M6 7.5l-2.8 4.5', 'M18 7.5l2.8 4.5'],
  audit: ['M3.05 12a9 9 0 1 0 2.7-6.4', 'M3 4v4h4', 'M12 8v4.2l3 1.8'],
  judge: ['M7 4h10v4a5 5 0 0 1-10 0z', 'M7 5.2H4.6a2.4 2.4 0 0 0 2.4 4', 'M17 5.2h2.4a2.4 2.4 0 0 1-2.4 4', 'M12 13v3.5', 'M8.5 20h7l-1.2-3.5h-4.6z'],
  // 操作
  refresh: ['M20.5 11a8 8 0 1 0-1.6 5.2', 'M21 6v6h-6'],
  play: ['M8 5.5v13l11-6.5z'],
  bolt: ['M13 3L5.5 13H11l-1 8 8.5-11H13z'],
  lock: ['M5.5 11h13v9.5h-13z', 'M8.5 11V8a3.5 3.5 0 0 1 7 0v3'],
  search: ['M11 4.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13z', 'M20 20l-4-4'],
  close: ['M6 6l12 12', 'M18 6L6 18'],
  pin: ['M12 3v6.5', 'M8.5 9.5h7l-1 4.5h-5z', 'M12 14v6.5'],
  scan: ['M4 8V5.5A1.5 1.5 0 0 1 5.5 4H8', 'M16 4h2.5A1.5 1.5 0 0 1 20 5.5V8', 'M20 16v2.5a1.5 1.5 0 0 1-1.5 1.5H16', 'M8 20H5.5A1.5 1.5 0 0 1 4 18.5V16', 'M4 12h16'],
  alert: ['M12 4l8.5 15h-17z', 'M12 10v4', 'M12 17h.01'],
  check: ['M5 12.5l4.5 4.5L19 7'],
  flask: ['M9 3h6', 'M10 3v6l-5 8.5A2 2 0 0 0 6.8 21h10.4a2 2 0 0 0 1.8-3.5L14 9V3', 'M7.5 15h9'],
  download: ['M12 4v11', 'M8 11l4 4 4-4', 'M5 20h14'],
  cpu: ['M7 7h10v10H7z', 'M9.5 9.5h5v5h-5z', 'M9 3v2.5M15 3v2.5M9 18.5V21M15 18.5V21M3 9h2.5M3 15h2.5M18.5 9H21M18.5 15H21'],
  send: ['M5 12l15-7-6 15-3-6-6-2z'],
  layers: ['M12 3l9 5-9 5-9-5z', 'M3 13l9 5 9-5'],
}

const sz = typeof props.size === 'number' ? props.size : parseInt(props.size, 10)
</script>

<template>
  <svg :width="sz" :height="sz" viewBox="0 0 24 24" fill="none"
       stroke="currentColor" :stroke-width="width" stroke-linecap="round" stroke-linejoin="round"
       aria-hidden="true" class="icon">
    <path v-for="(d, i) in (P[name] || [])" :key="i" :d="d" />
  </svg>
</template>

<style scoped>
.icon { display: block; flex: 0 0 auto; }
</style>
