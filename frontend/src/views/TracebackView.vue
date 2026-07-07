<template>
  <div class="tb-wrap">
    <div class="tb-header">
      <div>
        <h2>溯源分析</h2>
        <p class="text-muted">面向 High 告警的攻击路径重建：入口 → 横向 → 提权/持久化 → 外传 → C2/归因</p>
      </div>
      <n-space>
        <n-input v-model:value="tbTimeStart" type="text" placeholder="开始时间" size="tiny" style="width:160px" />
        <n-input v-model:value="tbTimeEnd" type="text" placeholder="结束时间" size="tiny" style="width:160px" />
        <n-button type="primary" size="small" @click="runAnalysis" :loading="analyzing">多源分析</n-button>
        <n-button size="small" @click="fetchAlerts">刷新列表</n-button>
        <span class="text-muted" style="font-size:12px">{{ statusText }}</span>
      </n-space>
    </div>

    <n-grid :cols="8" :x-gap="16" :y-gap="16" responsive="screen">
      <n-grid-item :span="2">
        <n-card title="分析报告列表" :bordered="false" class="section-card" size="small">
          <n-space vertical size="small">
            <n-input v-model:value="searchQuery" placeholder="搜索 ID / IP..." size="tiny" clearable @update:value="doSearch" />
            <n-empty v-if="!filteredAlerts.length" description="暂无报告。请先在「攻击链分析」运行多源LLM分析" style="padding:20px" />
            <div v-for="a in pagedAlerts" :key="a.id" class="alert-entry" :class="{ active: selectedAlert?.id === a.id }" @click="selectedAlert = a">
              <div class="alert-entry-title">{{ a.title || a.report_id }}</div>
              <n-tag :type="a.severity === 'high' ? 'error' : 'warning'" size="tiny">{{ a.severity }}</n-tag>
              <div class="alert-entry-time">{{ a.entry || '' }}</div>
            </div>
            <n-space justify="center" v-if="filteredAlerts.length > pageSize">
              <n-button size="tiny" :disabled="alertPage <= 1" @click="alertPage--">上一页</n-button>
              <span class="text-muted" style="font-size:11px">{{ alertPage }}/{{ totalAlertPages }}</span>
              <n-button size="tiny" :disabled="alertPage >= totalAlertPages" @click="alertPage++">下一页</n-button>
            </n-space>
          </n-space>
        </n-card>
      </n-grid-item>

      <n-grid-item :span="6">
        <n-card :bordered="false" class="section-card">
          <template #header><span>溯源概览</span></template>
          <n-empty v-if="!selectedAlert" description="请选择一个告警，或点击「运行分析」生成溯源报告。" />

          <n-tabs v-else type="line" size="small">
            <n-tab-pane name="overview" tab="概览">
              <n-grid :cols="4" :x-gap="12" :y-gap="12" responsive="screen">
                <n-grid-item>
                  <n-card size="small" title="入口 (Initial Access)" class="sub-card">
                    {{ selectedAlert.entry || '-' }}
                  </n-card>
                </n-grid-item>
                <n-grid-item>
                  <n-card size="small" title="执行 (Execution)" class="sub-card">
                    {{ selectedAlert.execution || '-' }}
                  </n-card>
                </n-grid-item>
                <n-grid-item>
                  <n-card size="small" title="持久化/提权" class="sub-card">
                    {{ selectedAlert.persistence || '-' }}
                  </n-card>
                </n-grid-item>
                <n-grid-item>
                  <n-card size="small" title="C2 / Exfil" class="sub-card">
                    {{ selectedAlert.c2 || '-' }}
                  </n-card>
                </n-grid-item>
              </n-grid>
            </n-tab-pane>
            <n-tab-pane name="path" tab="攻击路径">
              <pre class="tb-pre">{{ JSON.stringify(selectedAlert.attack_chain || selectedAlert.attack_path || {}, null, 2) }}</pre>
            </n-tab-pane>
            <n-tab-pane name="iocs" tab="IOCs">
              <n-space>
                <n-tag v-for="ioc in (selectedAlert.iocs || [])" :key="ioc" type="error" size="tiny">{{ ioc }}</n-tag>
              </n-space>
              <n-empty v-if="!(selectedAlert.iocs || []).length" description="无 IOCs" />
            </n-tab-pane>
            <n-tab-pane name="ai" tab="AI 研判报告">
              <div v-if="selectedAlert.llm_analysis" class="llm-text">{{ selectedAlert.llm_analysis }}</div>
              <n-empty v-else description="该报告不包含 AI 分析" />
            </n-tab-pane>
          </n-tabs>
        </n-card>
      </n-grid-item>
    </n-grid>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import { unifiedAnalysis, listAnalysisReports } from '@/api/attack'
import axios from 'axios'

const message = useMessage()
const alerts = ref<any[]>([])
const selectedAlert = ref<any>(null)
const analyzing = ref(false)
const statusText = ref('')
const searchQuery = ref('')
const alertPage = ref(1)
const tbTimeStart = ref('')
const tbTimeEnd = ref('')
const pageSize = ref(15)

const filteredAlerts = computed(() => {
  if (!searchQuery.value) return alerts.value
  const q = searchQuery.value.toLowerCase()
  return alerts.value.filter((a: any) =>
    (a.report_id || a.title || '').toLowerCase().includes(q) ||
    (a.entry || '').toLowerCase().includes(q)
  )
})
const totalAlertPages = computed(() => Math.max(1, Math.ceil(filteredAlerts.value.length / pageSize.value)))
const pagedAlerts = computed(() => {
  const start = (alertPage.value - 1) * pageSize.value
  return filteredAlerts.value.slice(start, start + pageSize.value)
})
function doSearch() { alertPage.value = 1 }

onMounted(() => { fetchAlerts() })

async function fetchAlerts() {
  try {
    const res = await listAnalysisReports()
    if (res.data?.ok) {
      alerts.value = (res.data.data || []).map((r: any) => {
        let iocs: string[] = []
        try { iocs = typeof r.iocs === 'string' ? JSON.parse(r.iocs) : (r.iocs || []) } catch {}
        let chain: string[] = []
        try {
          const ac = r.attack_chain
          chain = Array.isArray(ac) ? ac : (typeof ac === 'string' ? JSON.parse(ac) : [])
        } catch {}
        return {
          id: r.id, scenario_id: r.report_id, title: r.report_id || 'Analysis Report',
          severity: r.confidence === 'High' ? 'high' : 'medium',
          entry: r.time_start || '-', execution: `${r.total_events || 0} events analyzed`,
          persistence: `${r.techniques_found || 0} techniques`, c2: r.data_sources || '-',
          attack_chain: chain, attack_path: chain, iocs, llm_analysis: r.llm_analysis,
          confidence: r.confidence, report_id: r.report_id,
        }
      })
    }
    // Also try traceback high alerts
    try {
      const tbRes = await axios.get('/traceback/api/high_alerts')
      if (tbRes.data?.ok) {
        alerts.value = [...alerts.value, ...(tbRes.data.items || [])]
      }
    } catch {}
    statusText.value = alerts.value.length ? `已加载 ${alerts.value.length} 条` : '无数据'
  } catch {}
}

async function runAnalysis() {
  analyzing.value = true
  statusText.value = '多源LLM分析中...'
  try {
    const payload: any = {}
    if (tbTimeStart.value) payload.time_start = tbTimeStart.value
    if (tbTimeEnd.value) payload.time_end = tbTimeEnd.value
    const axios = (await import('axios')).default
    const res = await axios.post('/attack/api/analyze/unified', payload, { timeout: 120000 })
    if (res.data?.ok) {
      message.success(`分析完成：${res.data.techniques_count || '?'} 个技术已识别`)
      await fetchAlerts()
      if (alerts.value.length > 0) selectedAlert.value = alerts.value[0]
    } else {
      message.error(res.data?.error || '分析失败')
    }
  } catch (e: any) {
    message.error('分析失败: ' + (e?.response?.data?.error || e?.message || ''))
  }
  finally { analyzing.value = false }
}
</script>

<style scoped>
.tb-wrap { max-width: 1200px; margin: 0 auto; }
.tb-header { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px; margin-bottom: 16px; }
.tb-header h2 { margin: 0 0 6px 0; }
.text-muted { color: #6b7280; font-size: 13px; }
.section-card { border-radius: 14px; }
.alert-entry { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; cursor: pointer; border-radius: 6px; }
.alert-entry:hover { background: #f7f9fc; }
.alert-entry.active { background: #e8f0ff; }
.alert-entry-title { font-weight: 600; font-size: 13px; margin-bottom: 2px; }
.alert-entry-time { font-size: 10px; color: #94a3b8; margin-top: 2px; }
.sub-card { border-radius: 10px; }
.tb-pre { background: #f8fafc; padding: 16px; border-radius: 8px; max-height: 400px; overflow: auto; font-size: 12px; line-height: 1.6; white-space: pre-wrap; }
.llm-text { white-space: pre-wrap; font-size: 14px; line-height: 1.8; padding: 16px; background: #f0f6ff; border-radius: 8px; color: #1e3a5f; max-height: 500px; overflow-y: auto; }
</style>
