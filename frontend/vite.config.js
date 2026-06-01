import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发服务器默认 5173；/api 代理到 FastAPI 后端，避免跨域配置散落
export default defineConfig({
  plugins: [vue()],
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
