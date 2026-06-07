<script setup>
// 评委模式首页（P1-5）：四张卡正对评分四子项，每张一键 demo，
// 把「输入 → 工具调用 → 安全判定 → 审计 trace → 结果」整条链路喂到评委眼前。
import { reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { chat, checkCommand, checkPosture, diagnose } from './api.js'
import GuardVerdict from './GuardVerdict.vue'
import TraceDetail from './TraceDetail.vue'

const stageColor = {
  接收指令: '#909399', 感知环境: '#409EFF', 推理决策: '#E6A23C',
  安全校验: '#F56C6C', 执行结果: '#67C23A',
}
const intentTag = { white: 'success', gray: 'warning', black: 'danger', action: 'primary' }
const sevType = { ok: 'success', warning: 'warning', critical: 'danger', unknown: 'info' }
const postureStatusType = { exposed: 'danger', module_only: 'danger', kernel_only: 'warning' }

// 四张卡：对应评分①②③④。每张一个一键 runner，结果写进 results[id]。
const cards = [
  {
    id: 'perception', badge: '①', tag: 'OS 感知 + MCP 插件',
    title: '实时感知本机系统状态',
    desc: '一句话经 MCP 工具拿到真实磁盘数据，全程留五段执行链。',
    sample: '磁盘还剩多少？',
    run: async () => normChat(await chat('磁盘还剩多少？'), '磁盘还剩多少？'),
  },
  {
    id: 'nlops', badge: '②', tag: '自然语言运维',
    title: '听懂人话并选对工具',
    desc: '自然语言 → 正确意图分类 → 选对 MCP 工具 → 简洁中文作答。',
    sample: '哪个进程最吃 CPU？',
    run: async () => normChat(await chat('哪个进程最吃 CPU？'), '哪个进程最吃 CPU？'),
  },
  {
    id: 'guardrail', badge: '③', tag: '安全护栏 + 内核遏制',
    title: '危险命令拦截 + 内核姿态体检',
    desc: '危险命令被正则/AST 双栏拦死；并比对漏洞情报研判本机内核暴露面。',
    sample: 'rm -rf /var/lib/mysql',
    run: async () => ({
      input: 'rm -rf /var/lib/mysql',
      guard: await checkCommand('rm -rf /var/lib/mysql'),
      posture: await checkPosture(),
    }),
  },
  {
    id: 'rootcause', badge: '④', tag: '根因分析 + 处置闭环',
    title: '不止告警，定位根因给建议',
    desc: '磁盘/负载/僵尸跨信号关联根因；可清理项走护栏二次确认安全处置。',
    sample: '一键根因体检（/）',
    run: async () => ({ input: '根因体检 topic=all path=/', diag: await diagnose('all', '/') }),
  },
]

function normChat(d, input) {
  return {
    input, toolCalls: d.tool_calls || [], intent: d.intent,
    blocked: d.blocked, trace: d.trace || [], traceId: d.trace_id, answer: d.answer,
  }
}

const results = reactive({})   // id -> result
const busy = reactive({})      // id -> bool

async function runCard(card) {
  if (busy[card.id]) return
  busy[card.id] = true
  results[card.id] = null
  try {
    results[card.id] = await card.run()
  } catch (e) {
    results[card.id] = { error: e?.message || String(e) }
    ElMessage.error('演示失败：' + (e?.message || e))
  } finally {
    busy[card.id] = false
  }
}

async function runAll() {
  for (const c of cards) await runCard(c)
}
</script>

<template>
  <div class="judge">
    <div class="intro">
      <p>四张卡对应初赛评分四子项，点「▶ 运行演示」即把整条链路（输入→工具调用→安全判定→审计 trace→结果）走给你看。</p>
      <el-button type="primary" plain size="small" @click="runAll">▶ 全部依次运行</el-button>
    </div>

    <div class="grid">
      <el-card v-for="c in cards" :key="c.id" class="card" shadow="hover">
        <template #header>
          <div class="ch">
            <span class="badge">{{ c.badge }}</span>
            <div class="ch-text">
              <div class="ch-title">{{ c.title }}</div>
              <el-tag size="small" type="info" effect="plain">{{ c.tag }}</el-tag>
            </div>
          </div>
        </template>

        <div class="desc">{{ c.desc }}</div>
        <div class="run-row">
          <code class="sample">{{ c.sample }}</code>
          <el-button type="primary" size="small" :loading="busy[c.id]" @click="runCard(c)">▶ 运行演示</el-button>
        </div>

        <!-- 结果区：按链路分段渲染 -->
        <div v-if="results[c.id]" class="result">
          <el-alert v-if="results[c.id].error" :title="results[c.id].error" type="error" :closable="false" />

          <template v-else>
            <!-- 输入 -->
            <div class="seg"><span class="seg-k">输入</span><span class="seg-v">{{ results[c.id].input }}</span></div>

            <!-- 工具调用 -->
            <div v-if="results[c.id].toolCalls && results[c.id].toolCalls.length" class="seg">
              <span class="seg-k">工具调用</span>
              <span class="seg-v">
                <el-tag v-for="(t, k) in results[c.id].toolCalls" :key="k" size="small" type="success" effect="plain">
                  {{ t.tool || t.name || t }}
                </el-tag>
              </span>
            </div>

            <!-- 安全判定：intent（对话路径）/ GuardVerdict 两栏（护栏路径）-->
            <div v-if="results[c.id].intent" class="seg">
              <span class="seg-k">安全判定</span>
              <span class="seg-v">
                <el-tag size="small" :type="intentTag[results[c.id].intent] || 'info'">{{ results[c.id].intent }}</el-tag>
                <el-tag v-if="results[c.id].blocked" size="small" type="danger" effect="dark">护栏拦截</el-tag>
              </span>
            </div>
            <div v-if="results[c.id].guard" class="seg-block">
              <span class="seg-k">安全判定（正则/AST 双栏）</span>
              <GuardVerdict :guard="results[c.id].guard" />
            </div>

            <!-- 内核姿态（③ 专属：Dirty Frag 这类内核漏洞的本机暴露面）-->
            <div v-if="results[c.id].posture" class="seg-block">
              <span class="seg-k">
                内核姿态体检
                <el-tag size="small" :type="sevType[results[c.id].posture.severity] || 'info'">
                  {{ results[c.id].posture.severity }}
                </el-tag>
              </span>
              <div class="posture">
                <div class="p-line">内核 <code>{{ results[c.id].posture.kernel }}</code>，已加载模块 {{ results[c.id].posture.loaded_module_count }} 个</div>
                <div v-if="results[c.id].posture.matches?.length">
                  <div v-for="m in results[c.id].posture.matches" :key="m.cve" class="p-match">
                    <el-tag size="small" :type="postureStatusType[m.status] || 'info'">{{ m.status }}</el-tag>
                    <b>{{ m.cve }}</b>
                    <span v-if="m.aliases?.length" class="alias">（{{ m.aliases[0] }}）</span>
                    <span v-if="m.loaded_modules_hit?.length" class="mods">模块: {{ m.loaded_modules_hit.join(', ') }}</span>
                  </div>
                </div>
                <div v-else class="p-clear">✓ 未命中情报库中已披露内核漏洞（仅就 N-day feed 而言）</div>
                <div class="p-scope">{{ results[c.id].posture.scope_note }}</div>
              </div>
            </div>

            <!-- 根因分析（④ 专属）-->
            <div v-if="results[c.id].diag" class="seg-block">
              <span class="seg-k">根因分析结果</span>
              <div class="diag">
                <div class="d-summary">{{ results[c.id].diag.summary }}</div>
                <div v-for="(r, k) in (results[c.id].diag.reports || [])" :key="k" class="d-report">
                  <el-tag size="small" :type="sevType[r.severity] || 'info'">{{ r.topic }} · {{ r.severity }}</el-tag>
                  <span v-if="r.findings && r.findings.length" class="d-find">{{ r.findings[0] }}</span>
                </div>
              </div>
            </div>

            <!-- 审计 trace：五段执行链时间线 -->
            <div v-if="results[c.id].trace && results[c.id].trace.length" class="seg-block">
              <span class="seg-k">
                审计 trace
                <code v-if="results[c.id].traceId" class="tid">{{ results[c.id].traceId.slice(0, 8) }}</code>
              </span>
              <el-timeline>
                <el-timeline-item v-for="(s, j) in results[c.id].trace" :key="j" :color="stageColor[s.stage] || '#909399'">
                  <span class="stage">{{ s.stage }}</span>
                  <TraceDetail :detail="s.detail" />
                </el-timeline-item>
              </el-timeline>
            </div>

            <!-- 结果（对话路径的最终答复）-->
            <div v-if="results[c.id].answer" class="seg-block">
              <span class="seg-k">结果</span>
              <div class="answer">{{ results[c.id].answer }}</div>
            </div>
          </template>
        </div>
      </el-card>
    </div>
  </div>
</template>

<style scoped>
.judge { padding: 4px 2px 24px; }
.intro { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 12px; color: #555; font-size: 13px; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 1100px) { .grid { grid-template-columns: 1fr; } }
.card { border-radius: 10px; }
.ch { display: flex; gap: 10px; align-items: center; }
.badge { font-size: 22px; font-weight: 700; color: #409EFF; }
.ch-title { font-weight: 600; margin-bottom: 2px; }
.desc { color: #666; font-size: 13px; margin-bottom: 10px; }
.run-row { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px; }
.sample { background: #f5f7fa; padding: 3px 8px; border-radius: 5px; font-size: 12px; color: #333; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.result { border-top: 1px dashed #e0e0e0; padding-top: 10px; margin-top: 4px; }
.seg, .seg-block { margin-bottom: 8px; font-size: 13px; }
.seg { display: flex; gap: 8px; align-items: baseline; }
.seg-k { color: #909399; font-size: 12px; flex: 0 0 auto; min-width: 56px; }
.seg-v { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
.seg-block .seg-k { display: block; margin-bottom: 6px; }
.posture, .diag { background: #fafafa; border-radius: 6px; padding: 8px 10px; }
.p-line, .p-match, .d-report { margin-bottom: 4px; display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.alias { color: #E6A23C; }
.mods { color: #888; font-size: 12px; }
.p-clear { color: #67C23A; }
.p-scope { color: #999; font-size: 12px; margin-top: 6px; line-height: 1.5; }
.d-summary { font-weight: 600; margin-bottom: 6px; }
.d-find { color: #555; font-size: 12px; }
.tid { background: #eef; padding: 1px 6px; border-radius: 4px; font-size: 11px; }
.stage { font-weight: 600; margin-right: 6px; }
.answer { background: #f0f9eb; border-radius: 6px; padding: 8px 10px; color: #333; white-space: pre-wrap; }
</style>
