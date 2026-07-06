/**
 * 轻量 UI 反馈层：toast 通知 + 确认/告知弹框（Promise 化）。
 * 去除组件库依赖后的自持实现——状态放响应式单例，宿主渲染在 App.vue，
 * 视图侧只 import { message, confirmBox, alertBox } 即可，用法与原组件库等价。
 */
import { reactive } from 'vue'

// ---- toast ----
export const toasts = reactive([])
let seq = 0

export function toast(msg, type = 'info', ms = 3400) {
  const id = ++seq
  toasts.push({ id, msg: String(msg), type })
  setTimeout(() => {
    const i = toasts.findIndex((t) => t.id === id)
    if (i >= 0) toasts.splice(i, 1)
  }, ms)
}

export const message = {
  success: (m) => toast(m, 'ok'),
  error: (m) => toast(m, 'bad', 5200),
  warning: (m) => toast(m, 'warn', 4200),
  info: (m) => toast(m, 'info'),
}

// ---- 确认 / 告知弹框 ----
export const confirmState = reactive({
  open: false, title: '', body: '', confirmText: '确认', cancelText: '取消',
  danger: false, _resolve: null,
})

/** 确认框：resolve(true|false)。danger 时确认键红色。 */
export function confirmBox({ title = '确认', body = '', confirmText = '确认执行',
                             cancelText = '取消', danger = false } = {}) {
  return new Promise((resolve) => {
    Object.assign(confirmState, { open: true, title, body, confirmText, cancelText, danger, _resolve: resolve })
  })
}

/** 告知框：只有一个按钮（cancelText 为空即隐藏取消键）。 */
export function alertBox({ title = '提示', body = '', confirmText = '知道了', danger = false } = {}) {
  return confirmBox({ title, body, confirmText, cancelText: '', danger })
}

export function settleConfirm(v) {
  confirmState.open = false
  const r = confirmState._resolve
  confirmState._resolve = null
  if (r) r(v)
}
