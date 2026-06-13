<script setup>
/**
 * 麒麟运维指挥台 · 应用外壳（Kylin Ops Command Deck）。
 * 取「安全运维指挥台」隐喻：顶部实时状态条 + 左侧常驻导航栏 + 右侧工作区视图切换，
 * 取代原先「顶栏一排按钮弹抽屉」的通用后台模板。各视图按评分子项组织，keep-alive 保活切换不丢状态。
 */
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { getHealth, listTools } from './api.js'
import Icon from './Icon.vue'
import ConsoleView from './views/ConsoleView.vue'
import DiagnoseView from './views/DiagnoseView.vue'
import GuardrailView from './views/GuardrailView.vue'
import CapabilityView from './views/CapabilityView.vue'
import AuditView from './views/AuditView.vue'
import JudgeMode from './JudgeMode.vue'

const provider = ref('…')
const toolCount = ref(0)
const connected = ref(false)
const clock = ref('')

const view = ref('console')
const NAV = [
  { key: 'console', label: '智能对话', ic: 'console', comp: ConsoleView },
  { key: 'diagnose', label: '根因体检', ic: 'diagnose', comp: DiagnoseView },
  { key: 'guardrail', label: '安全护栏', ic: 'guardrail', comp: GuardrailView },
  { key: 'capability', label: '能力边界', ic: 'capability', comp: CapabilityView },
  { key: 'audit', label: '审计回放', ic: 'audit', comp: AuditView },
]
const judge = { key: 'judge', label: '评委模式', ic: 'judge', comp: JudgeMode }
const current = computed(() => (view.value === 'judge' ? judge : NAV.find(n => n.key === view.value) || NAV[0]).comp)

let timer = null
function tick() { clock.value = new Date().toLocaleTimeString('zh-CN', { hour12: false }) }

onMounted(async () => {
  tick(); timer = setInterval(tick, 1000)
  try {
    provider.value = (await getHealth()).llm_provider
    toolCount.value = (await listTools()).length
    connected.value = true
  } catch { provider.value = '后端未连接'; connected.value = false }
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="deck-bg" />
  <div class="deck">
    <!-- 顶部状态条 -->
    <header class="deck-header">
      <div class="brand">
        <svg class="brand-mark" viewBox="0 0 32 32" fill="none">
          <defs>
            <linearGradient id="qg" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stop-color="#3ce3a6" /><stop offset="1" stop-color="#23a3d6" />
            </linearGradient>
          </defs>
          <path d="M16 2.5l12 4.3v8.4c0 7.6-4.9 12.5-12 15-7.1-2.5-12-7.4-12-15V6.8z"
                fill="rgba(43,217,154,.08)" stroke="url(#qg)" stroke-width="1.6" stroke-linejoin="round" />
          <path d="M7.5 16.5h3.6l2 5.2 4.2-11.4 2.1 6.2H25" fill="none" stroke="#3ce3a6"
                stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
        <div class="brand-text">
          <div class="brand-title">麒麟运维指挥台</div>
          <div class="brand-sub">Kylin Ops Command Deck</div>
        </div>
      </div>

      <div class="vitals">
        <span class="vital" :class="connected ? 'live' : 'down'">
          <span class="dot" /><span class="lbl">LLM</span><b>{{ provider }}</b>
        </span>
        <span class="vital"><span class="lbl">MCP</span><b>{{ toolCount }}</b> 工具</span>
        <span class="vital armed"><Icon name="guardrail" :size="13" /> 护栏 ARMED</span>
        <span class="vital"><span class="lbl mono">{{ clock }}</span></span>
      </div>
    </header>

    <div class="deck-body">
      <!-- 左侧导航 -->
      <nav class="rail">
        <div class="rail-group-label">运维台</div>
        <div v-for="n in NAV" :key="n.key" class="nav-item" :class="{ active: view === n.key }" @click="view = n.key">
          <span class="ni-icon"><Icon :name="n.ic" :size="19" /></span>
          <span class="ni-text">{{ n.label }}</span>
        </div>

        <div class="rail-spacer" />
        <div class="rail-group-label">演示</div>
        <div class="nav-item accent" :class="{ active: view === 'judge' }" @click="view = 'judge'">
          <span class="ni-icon"><Icon name="judge" :size="19" /></span>
          <span class="ni-text">{{ judge.label }}</span>
          <span class="ni-badge">①②③④</span>
        </div>
        <div class="rail-foot">A2 · 麒麟智能运维<br />安全护栏 · 可追溯 · 根因分析</div>
      </nav>

      <!-- 工作区 -->
      <main class="workspace">
        <keep-alive>
          <component :is="current" :provider="provider" />
        </keep-alive>
      </main>
    </div>
  </div>
</template>
