import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
// 启用 Element Plus 暗色变量，再由 theme.css 改写为「墨+玉」指挥台调色板（覆盖默认蓝）。
import 'element-plus/theme-chalk/dark/css-vars.css'
import './theme.css'
import App from './App.vue'

createApp(App).use(ElementPlus).mount('#app')
