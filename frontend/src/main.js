import { createApp } from 'vue'
// 无组件库依赖：设计系统与全部交互组件（抽屉/开关/弹框/表格）均为自持实现，见 theme.css / ui.js。
import './theme.css'
import App from './App.vue'

createApp(App).mount('#app')
