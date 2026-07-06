import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发服务器默认 5173；/api 代理到 FastAPI 后端，避免跨域配置散落。
// 前端已无组件库依赖（设计系统与交互组件全自持实现），vendor 只需拆 vue 运行时：
// 业务代码改动不再使框架 chunk 失效缓存，构建产物总量也从 MB 级降到百 KB 级。
export default defineConfig({
  plugins: [vue()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: { vue: ['vue'] },
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
