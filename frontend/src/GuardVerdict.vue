<script setup>
/**
 * 护栏裁决两栏视图（P4-2）：把一次 check_command 的结果拆成
 *   ① 正则 / 路径规则判定   ② AST 结构分析（语法树）
 * 并排呈现，正面回答答辩必问「正则能被变形绕过吗」——当正则字面失配、AST 结构命中时，
 * 两栏一目了然地展示「变形绕过被语法树兜住」。复用于思维链回放与护栏检测台。
 */
import { computed } from 'vue'

const props = defineProps({ guard: { type: Object, required: true } })

const riskType = { critical: 'danger', high: 'warning', medium: '', low: 'info' }
const actionType = { deny: 'danger', confirm: 'warning', allow: 'success' }

// 正则/路径命中：剔除 AST- 前缀的合成规则（那些单列到右栏，避免两栏重复）
const regexRules = computed(() =>
  (props.guard.matched_rules || []).filter(id => !id.startsWith('AST-')))
const ast = computed(() => props.guard.ast_findings || [])

const verdict = computed(() => {
  const g = props.guard
  if (g.allowed) return { text: '✓ 放行', type: 'success' }
  if (g.require_confirm) return { text: '⚠ 需二次确认', type: 'warning' }
  return { text: '⛔ 已拦截', type: 'danger' }
})
// 「正则漏网、AST 抓到」的高亮条件：字面规则未命中，但语法树发现了危险结构
const astSaved = computed(() => regexRules.value.length === 0 && ast.value.length > 0)
</script>

<template>
  <div class="gv">
    <div class="gv-head">
      <el-tag size="small" :type="verdict.type" effect="dark">{{ verdict.text }}</el-tag>
      <el-tag size="small" :type="riskType[guard.risk]">风险 {{ guard.risk }}</el-tag>
      <el-tag size="small" effect="plain" :type="actionType[guard.action]">动作 {{ guard.action }}</el-tag>
    </div>

    <div class="gv-cols">
      <!-- 左栏：正则 / 路径规则（确定性、对红线是最终权威） -->
      <div class="gv-col">
        <div class="gv-col-t">① 正则 / 路径规则判定</div>
        <div v-if="regexRules.length" class="gv-rules">
          <el-tag v-for="id in regexRules" :key="id" size="small" class="gv-rule">{{ id }}</el-tag>
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
              <el-tag size="small" :type="riskType[f.risk]">{{ f.risk }}</el-tag>
              <el-tag size="small" effect="plain" :type="actionType[f.action]">{{ f.action }}</el-tag>
            </div>
            <div class="gv-finding-r">{{ f.reason }}</div>
          </div>
        </div>
        <div v-else class="gv-empty">未发现 shell 危险结构（语法树洁净）</div>
      </div>
    </div>

    <div v-if="astSaved" class="gv-saved">
      ⚡ 正则字面失配、AST 结构命中 —— 变形绕过被语法树兜住（这正是纯正则的盲区）
    </div>
  </div>
</template>

<style scoped>
.gv { border: 1px solid #ebeef5; border-radius: 8px; padding: 10px; background: #fff; }
.gv-head { display: flex; gap: 6px; margin-bottom: 8px; flex-wrap: wrap; }
.gv-cols { display: flex; gap: 10px; }
.gv-col { flex: 1; min-width: 0; background: #f8f9fb; border-radius: 6px; padding: 8px; }
.gv-col-t { font-weight: 600; font-size: 12px; color: #5a6677; margin-bottom: 6px; }
.gv-rules { display: flex; gap: 6px; flex-wrap: wrap; }
.gv-rule { font-family: monospace; }
.gv-empty { font-size: 12px; color: #909399; }
.gv-finding { border-left: 3px solid #e6a23c; padding: 2px 0 2px 8px; margin-bottom: 6px; }
.gv-finding-h { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.gv-finding-h code { font-size: 12px; background: #eef1f6; padding: 1px 5px; border-radius: 4px; }
.gv-finding-r { font-size: 12px; color: #606266; line-height: 1.5; margin-top: 2px; }
.gv-saved {
  margin-top: 8px; padding: 6px 10px; border-radius: 6px; font-size: 12px;
  background: #fff7e6; color: #b88230; border: 1px dashed #f0c78a;
}
</style>
