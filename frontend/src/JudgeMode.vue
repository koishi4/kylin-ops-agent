<script setup>
/**
 * 评委模式视图（P1-5）：四张卡正对初赛评分四子项，每张一键 demo，
 * 把「输入 → 工具调用 → 安全判定 → 审计 trace → 结果」整条链路喂到评委眼前。
 */
import { reactive } from 'vue'
import { chat, checkCommand, checkPosture, diagnose } from './api.js'
import { message } from './ui.js'
import Icon from './Icon.vue'
import GuardVerdict from './GuardVerdict.vue'
import TraceTimeline from './TraceTimeline.vue'

const intentText = { white: '只读放行', gray: '需校验', black: '已拦截', action: '动作执行' }
const intentCls = { white: 'ok', gray: 'warn', black: 'bad', action: 'info' }
const postureStatus = { exposed: 'bad', module_only: 'bad', kernel_only: 'warn' }

const cards = [
  { id: 'perception', badge: '①', tag: 'OS 感知 + MCP 插件', title: '实时感知本机系统状态',
    desc: '一句话经 MCP 工具拿到真实磁盘数据，全程留五段执行链。', sample: '磁盘还剩多少？',
    run: async () => normChat(await chat('磁盘还剩多少？'), '磁盘还剩多少？') },
  { id: 'nlops', badge: '②', tag: '自然语言运维', title: '听懂人话并选对工具',
    desc: '自然语言 → 正确意图分类 → 选对 MCP 工具 → 简洁中文作答。', sample: '哪个进程最吃 CPU？',
    run: async () => normChat(await chat('哪个进程最吃 CPU？'), '哪个进程最吃 CPU？') },
  { id: 'guardrail', badge: '③', tag: '安全护栏 + 内核遏制', title: '危险命令拦截 + 内核姿态体检',
    desc: '危险命令被正则/AST 双栏拦死；并比对漏洞情报研判本机内核暴露面。', sample: 'rm -rf /var/lib/mysql',
    run: async () => ({ input: 'rm -rf /var/lib/mysql', guard: await checkCommand('rm -rf /var/lib/mysql'), posture: await checkPosture() }) },
  { id: 'rootcause', badge: '④', tag: '根因分析 + 处置闭环', title: '不止告警，定位根因给建议',
    desc: '磁盘/内存/负载跨信号关联根因；可清理项走护栏二次确认安全处置。', sample: '一键根因体检（/）',
    run: async () => ({ input: '根因体检 topic=all path=/', diag: await diagnose('all', '/') }) },
]

function normChat(d, input) {
  return { input, toolCalls: d.tool_calls || [], intent: d.intent, blocked: d.blocked,
           trace: d.trace || [], traceId: d.trace_id, answer: d.answer }
}

const results = reactive({})
const busy = reactive({})

async function runCard(card) {
  if (busy[card.id]) return
  busy[card.id] = true; results[card.id] = null
  try { results[card.id] = await card.run() }
  catch (e) { results[card.id] = { error: e?.message || String(e) }; message.error('演示失败：' + (e?.message || e)) }
  finally { busy[card.id] = false }
}
async function runAll() { for (const c of cards) await runCard(c) }
</script>

<template>
  <div class="view">
    <div class="view-head">
      <div class="vh-main">
        <div class="view-title"><Icon name="judge" :size="19" /> 评委模式</div>
        <div class="view-sub">四张卡对应初赛评分四子项，点「运行演示」即把整条链路（输入 → 工具调用 → 安全判定 → 审计 trace → 结果）走给你看。</div>
      </div>
      <div class="view-actions">
        <button class="btn primary" @click="runAll"><Icon name="play" :size="14" /> 全部依次运行</button>
      </div>
    </div>

    <div class="view-body">
      <div class="grid">
        <div v-for="c in cards" :key="c.id" class="panel jcard">
          <div class="jc-head">
            <span class="jc-badge mono">{{ c.badge }}</span>
            <div>
              <div class="jc-title">{{ c.title }}</div>
              <span class="jc-tag mono">{{ c.tag }}</span>
            </div>
          </div>
          <div class="jc-desc">{{ c.desc }}</div>
          <div class="jc-run">
            <code class="tok jc-sample">{{ c.sample }}</code>
            <button class="btn sm" :disabled="busy[c.id]" @click="runCard(c)">
              <Icon name="play" :size="12" /> {{ busy[c.id] ? '运行中…' : '运行演示' }}
            </button>
          </div>

          <div v-if="results[c.id]" class="jc-result">
            <div v-if="results[c.id].error" class="note bad">{{ results[c.id].error }}</div>
            <template v-else>
              <div class="seg-row"><span class="seg-k mono">输入</span><span class="seg-v">{{ results[c.id].input }}</span></div>

              <div v-if="results[c.id].toolCalls && results[c.id].toolCalls.length" class="seg-row">
                <span class="seg-k mono">工具调用</span>
                <span class="seg-v">
                  <span v-for="(t, k) in results[c.id].toolCalls" :key="k" class="tag mono">{{ t.tool || t.name || t }}</span>
                </span>
              </div>

              <div v-if="results[c.id].intent" class="seg-row">
                <span class="seg-k mono">安全判定</span>
                <span class="seg-v">
                  <span class="tag" :class="intentCls[results[c.id].intent] || 'info'">{{ intentText[results[c.id].intent] || results[c.id].intent }}</span>
                  <span v-if="results[c.id].blocked" class="tag bad solid">护栏拦截</span>
                </span>
              </div>

              <div v-if="results[c.id].guard" class="seg-block">
                <span class="seg-k mono">安全判定（正则 / AST 双栏）</span>
                <GuardVerdict :guard="results[c.id].guard" />
              </div>

              <div v-if="results[c.id].posture" class="seg-block">
                <span class="seg-k mono">内核姿态体检
                  <span class="sev" :class="results[c.id].posture.severity"><i class="sd" />{{ results[c.id].posture.severity }}</span>
                </span>
                <div class="subbox">
                  <div class="p-line">内核 <code class="tok">{{ results[c.id].posture.kernel }}</code>，已加载模块 {{ results[c.id].posture.loaded_module_count }} 个</div>
                  <div v-if="results[c.id].posture.matches?.length">
                    <div v-for="m in results[c.id].posture.matches" :key="m.cve" class="p-match">
                      <span class="tag" :class="postureStatus[m.status] || 'info'">{{ m.status }}</span>
                      <b>{{ m.cve }}</b>
                      <span v-if="m.aliases?.length" class="alias">（{{ m.aliases[0] }}）</span>
                      <span v-if="m.loaded_modules_hit?.length" class="muted">模块: {{ m.loaded_modules_hit.join(', ') }}</span>
                    </div>
                  </div>
                  <div v-else class="p-clear">未命中情报库中已披露内核漏洞（仅就 N-day feed 而言）</div>
                  <div class="muted p-scope">{{ results[c.id].posture.scope_note }}</div>
                </div>
              </div>

              <div v-if="results[c.id].diag" class="seg-block">
                <span class="seg-k mono">根因分析结果</span>
                <div class="subbox">
                  <div class="d-summary">{{ results[c.id].diag.summary }}</div>
                  <div v-for="(r, k) in (results[c.id].diag.reports || [])" :key="k" class="d-report">
                    <span class="sev" :class="r.severity"><i class="sd" />{{ r.topic }}</span>
                    <span v-if="r.root_cause" class="d-find">{{ r.root_cause }}</span>
                    <span v-else-if="r.findings && r.findings.length" class="d-find">{{ r.findings[0] }}</span>
                  </div>
                </div>
              </div>

              <div v-if="results[c.id].trace && results[c.id].trace.length" class="seg-block">
                <span class="seg-k mono">审计 trace <code v-if="results[c.id].traceId" class="tok acc">{{ results[c.id].traceId.slice(0, 8) }}</code></span>
                <div class="subbox" style="padding-bottom:0"><TraceTimeline :steps="results[c.id].trace" /></div>
              </div>

              <div v-if="results[c.id].answer" class="seg-block">
                <span class="seg-k mono">结果</span>
                <div class="answer note ok">{{ results[c.id].answer }}</div>
              </div>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 1180px) { .grid { grid-template-columns: 1fr; } }
.jcard { padding: 15px 17px; }
.jc-head { display: flex; gap: 12px; align-items: center; margin-bottom: 10px; }
.jc-badge {
  font-size: 19px; font-weight: 700; color: var(--acc);
  width: 38px; height: 38px; display: flex; align-items: center; justify-content: center; flex: 0 0 auto;
  border: 1px solid var(--line-2); border-radius: var(--r-s); background: var(--s1);
}
.jc-title { font-weight: 650; font-size: 14px; color: var(--t0); }
.jc-tag { font-size: 10.5px; color: var(--t2); letter-spacing: .5px; }
.jc-desc { color: var(--t1); font-size: 12.5px; line-height: 1.6; margin-bottom: 12px; }
.jc-run { display: flex; align-items: center; gap: 10px; }
.jc-sample { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.jc-result { border-top: 1px dashed var(--line-2); padding-top: 12px; margin-top: 12px; }

.seg-row, .seg-block { margin-bottom: 9px; font-size: 12.5px; }
.seg-row { display: flex; gap: 9px; align-items: baseline; }
.seg-k { color: var(--t2); font-size: 10.5px; flex: 0 0 auto; min-width: 58px; letter-spacing: .5px; }
.seg-v { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; color: var(--t0); }
.seg-block .seg-k { display: flex; align-items: center; gap: 8px; margin-bottom: 7px; }

.subbox { background: var(--bg); border: 1px solid var(--line); border-radius: var(--r-s); padding: 10px 12px; }
.p-line, .p-match, .d-report { margin-bottom: 5px; display: flex; gap: 7px; align-items: center; flex-wrap: wrap; font-size: 12px; }
.alias { color: var(--warn); }
.p-clear { color: var(--ok); font-size: 12px; }
.p-scope { font-size: 11px; margin-top: 6px; line-height: 1.5; }
.d-summary { font-weight: 650; margin-bottom: 7px; color: var(--t0); font-size: 12.5px; }
.d-find { color: var(--t1); font-size: 11.5px; }
.answer { white-space: pre-wrap; line-height: 1.65; font-size: 12.5px; color: var(--t0); }
</style>
