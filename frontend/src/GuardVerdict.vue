<script setup>
/**
 * 护栏裁决两栏视图（P4-2）：把一次 check_command 的结果拆成
 *   ① 正则 / 路径规则判定   ② AST 结构分析（语法树）
 * 并排呈现，正面回答答辩必问「正则能被变形绕过吗」——当正则字面失配、AST 结构命中时，
 * 两栏一目了然地展示「变形绕过被语法树兜住」。复用于执行链回放与护栏检测台。
 */
import { computed } from 'vue'

const props = defineProps({ guard: { type: Object, required: true } })

const riskCls = { critical: 'bad', high: 'warn', medium: 'warn', low: 'info' }
const actionCls = { deny: 'bad', confirm: 'warn', allow: 'ok' }

// 正则/路径命中：剔除 AST- 前缀的合成规则（那些单列到右栏，避免两栏重复）
const regexRules = computed(() =>
  (props.guard.matched_rules || []).filter(id => !id.startsWith('AST-')))
const ast = computed(() => props.guard.ast_findings || [])

const verdict = computed(() => {
  const g = props.guard
  if (g.allowed) return { text: '放行', cls: 'ok solid' }
  if (g.require_confirm) return { text: '需二次确认', cls: 'warn' }
  return { text: '已拦截', cls: 'bad solid' }
})
// 「正则漏网、AST 抓到」的高亮条件：字面规则未命中，但语法树发现了危险结构
const astSaved = computed(() => regexRules.value.length === 0 && ast.value.length > 0)
</script>

<template>
  <div class="gv">
    <div class="gv-head">
      <span class="tag" :class="verdict.cls">{{ verdict.text }}</span>
      <span class="tag" :class="riskCls[guard.risk]">风险 {{ guard.risk }}</span>
      <span class="tag line" :class="actionCls[guard.action]">动作 {{ guard.action }}</span>
    </div>

    <div class="gv-cols">
      <!-- 左栏：正则 / 路径规则（确定性、对红线是最终权威） -->
      <div class="gv-col">
        <div class="gv-col-t">① 正则 / 路径规则判定</div>
        <div v-if="regexRules.length" class="gv-rules">
          <span v-for="id in regexRules" :key="id" class="tag mono">{{ id }}</span>
        </div>
        <div v-else class="gv-empty">正则未命中任何字面规则</div>
      </div>

      <!-- 右栏：AST 结构分析（语法树，抓字面正则盖不住的变形） -->
      <div class="gv-col">
        <div class="gv-col-t">② AST 结构分析（Bash 语法树）</div>
        <div v-if="ast.length" class="gv-findings">
          <div v-for="(f, i) in ast" :key="i" class="gv-finding">
            <div class="gv-finding-h">
              <code>{{ f.structure }}</code>
              <span class="tag" :class="riskCls[f.risk]">{{ f.risk }}</span>
              <span class="tag line" :class="actionCls[f.action]">{{ f.action }}</span>
            </div>
            <div class="gv-finding-r">{{ f.reason }}</div>
          </div>
        </div>
        <div v-else class="gv-empty">未发现 shell 危险结构（语法树洁净）</div>
      </div>
    </div>

    <div v-if="astSaved" class="gv-saved">
      正则字面失配、AST 结构命中——变形绕过被语法树兜住（这正是纯正则的盲区）
    </div>
  </div>
</template>

<style scoped>
.gv { border: 1px solid var(--line); border-radius: var(--r-s); padding: 10px; background: var(--s0); }
.gv-head { display: flex; gap: 6px; margin-bottom: 9px; flex-wrap: wrap; }
.gv-cols { display: flex; gap: 8px; }
.gv-col { flex: 1; min-width: 0; background: var(--bg); border: 1px solid var(--line); border-radius: var(--r-s); padding: 9px 10px; }
.gv-col-t { font-weight: 600; font-size: 11.5px; color: var(--t1); margin-bottom: 7px; }
.gv-rules { display: flex; gap: 5px; flex-wrap: wrap; }
.gv-empty { font-size: 12px; color: var(--t2); }
.gv-finding { border-left: 2px solid var(--warn); padding: 2px 0 2px 8px; margin-bottom: 7px; }
.gv-finding:last-child { margin-bottom: 0; }
.gv-finding-h { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.gv-finding-h code { font-size: 11.5px; font-family: var(--mono); background: var(--s2); color: var(--warn); padding: 1px 5px; border-radius: var(--r-s); }
.gv-finding-r { font-size: 12px; color: var(--t1); line-height: 1.55; margin-top: 3px; }
.gv-saved {
  margin-top: 9px; padding: 7px 10px; border-radius: var(--r-s); font-size: 12px;
  background: var(--warn-soft); color: var(--warn); border-left: 2px solid var(--warn);
}
</style>
