import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发服务器默认 5173；/api 代理到 FastAPI 后端，避免跨域配置散落
export default defineConfig({
  plugins: [vue()],
  // 代码分割（P1 vendor 拆分 + P2 业务懒加载）：
  // ① manualChunks 把体积大头 element-plus 与 vue 运行时拆成独立 vendor chunk，
  //    业务代码改动不再使整个 ~1.08MB 包失效缓存，首屏也能并行下载。
  // ② 评委模式面板（JudgeMode.vue）用 defineAsyncComponent 动态 import（见 App.vue），
  //    Vite 自动为它切出独立 async chunk，首屏主包不再包含这块，点开抽屉时才按需下载。
  // 轻量配置，不重写前端。
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          'element-plus': ['element-plus'],
          vue: ['vue'],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
})
