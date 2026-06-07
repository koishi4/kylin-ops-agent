import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发服务器默认 5173；/api 代理到 FastAPI 后端，避免跨域配置散落
export default defineConfig({
  plugins: [vue()],
  // P1（可选）代码分割：把体积大头 element-plus 与 vue 运行时拆成独立 vendor chunk，
  // 业务代码改动不再使整个 ~1.08MB 包失效缓存，首屏也能并行下载。轻量配置，不重写前端。
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
