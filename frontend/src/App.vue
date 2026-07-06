<script setup>
/**
 * 麒麟运维台 · 应用外壳。
 * 布局：顶栏（品牌印章 + 等宽读数）+ 左侧编号导航 + 右侧工作区（keep-alive 保活切换）。
 * 同时承载全局 UI 反馈宿主（toast / 确认框，见 ui.js）。
 */
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { getHealth, listTools } from './api.js'
import { toasts, confirmState, settleConfirm } from './ui.js'
import ConsoleView from './views/ConsoleView.vue'
import BriefingView from './views/BriefingView.vue'
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
  { key: 'console', no: '01', label: '智能对话', comp: ConsoleView },
  { key: 'briefing', no: '02', label: '运维简报', comp: BriefingView },
  { key: 'diagnose', no: '03', label: '根因体检', comp: DiagnoseView },
  { key: 'guardrail', no: '04', label: '安全护栏', comp: GuardrailView },
  { key: 'capability', no: '05', label: '能力边界', comp: CapabilityView },
  { key: 'audit', no: '06', label: '审计回放', comp: AuditView },
]
const judge = { key: 'judge', no: '07', label: '评委模式', comp: JudgeMode }
const current = computed(() =>
  (view.value === 'judge' ? judge : NAV.find(n => n.key === view.value) || NAV[0]).comp)

let timer = null
function tick() { clock.value = new Date().toLocaleTimeString('zh-CN', { hour12: false }) }

onMounted(async () => {
  tick(); timer = setInterval(tick, 1000)
  try {
    provider.value = (await getHealth()).llm_provider
    toolCount.value = (await listTools()).length
    connected.value = true
  } catch { provider.value = '未连接'; connected.value = false }
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="shell">
    <!-- 顶栏 -->
    <header class="topbar">
      <div class="brand">
        <span class="brand-seal">麒</span>
        <div>
          <div class="brand-name">麒麟运维台</div>
          <div class="brand-code">KYLIN OPS · A2</div>
        </div>
      </div>
      <div class="readouts">
        <span class="readout" :class="connected ? 'live' : 'down'">
          <span class="sq" /><span class="k">LLM</span><b>{{ provider }}</b>
        </span>
        <span class="readout"><span class="k">MCP</span><b>{{ toolCount }}</b> 工具 · 全只读</span>
        <span class="readout"><span class="k">护栏</span><b>在位</b></span>
        <span class="readout">{{ clock }}</span>
      </div>
    </header>

    <div class="shell-body">
      <!-- 左侧导航 -->
      <nav class="rail">
        <div class="rail-label">运维台</div>
        <button v-for="n in NAV" :key="n.key" class="nav-item"
                :class="{ active: view === n.key }" @click="view = n.key">
          <span class="ni-no">{{ n.no }}</span>{{ n.label }}
        </button>

        <div class="rail-spacer" />
        <div class="rail-label">演示</div>
        <button class="nav-item" :class="{ active: view === 'judge' }" @click="view = 'judge'">
          <span class="ni-no">{{ judge.no }}</span>{{ judge.label }}
        </button>
        <div class="rail-foot">安全护栏 · 思维链留痕<br />根因分析 · 受控动作</div>
      </nav>

      <!-- 工作区 -->
      <main class="workspace">
        <keep-alive>
          <component :is="current" :provider="provider" />
        </keep-alive>
      </main>
    </div>
  </div>

  <!-- toast 宿主 -->
  <div class="toasts">
    <div v-for="t in toasts" :key="t.id" class="toast" :class="t.type">{{ t.msg }}</div>
  </div>

  <!-- 确认框宿主 -->
  <Teleport to="body">
    <div v-if="confirmState.open" class="overlay" @click="settleConfirm(false)" />
    <div v-if="confirmState.open" class="modal">
      <div class="modal-title">{{ confirmState.title }}</div>
      <div class="modal-body">{{ confirmState.body }}</div>
      <div class="modal-foot">
        <button v-if="confirmState.cancelText" class="btn ghost" @click="settleConfirm(false)">
          {{ confirmState.cancelText }}
        </button>
        <button class="btn" :class="confirmState.danger ? 'danger' : 'primary'" @click="settleConfirm(true)">
          {{ confirmState.confirmText }}
        </button>
      </div>
    </div>
  </Teleport>
</template>
