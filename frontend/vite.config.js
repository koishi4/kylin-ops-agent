import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发服务器默认 5173；/api 代理到 FastAPI 后端，避免跨域配置散落
export default defineConfig({
  plugins: [vue()],
  // 代码分割（vendor 拆分）：manualChunks 把体积大头 element-plus 与 vue 运行时拆成独立
  // vendor chunk，业务代码改动不再使整个包失效缓存，首屏也能并行下载。
  // 业务视图（views/*）已是常驻指挥台的一部分、体积很小（业务主包仅 ~90KB），随主包加载即可，
  // 无需再切 async chunk；大头始终是 element-plus（约 922KB），由 vendor 拆分独立缓存。
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
