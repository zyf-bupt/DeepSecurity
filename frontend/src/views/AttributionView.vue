<template>
  <div class="attr-wrap">
    <h2 class="page-title">🎯 攻击溯源归因分析 <small>TAA-EPLMR + DeepSeek LLM 多源融合</small></h2>

    <n-grid :cols="8" :x-gap="16" :y-gap="16" responsive="screen">
      <!-- Left: Report List + Controls -->
      <n-grid-item :span="3">
        <n-card title="分析报告" size="small" :bordered="false" class="mb-3 section-card">
          <n-space vertical size="small">
            <n-input v-model:value="searchQuery" placeholder="搜索 ID..." size="tiny" clearable />
            <n-input v-model:value="attrTimeStart" type="text" placeholder="开始时间 如 2026-07-07T14:00" size="tiny" />
            <n-input v-model:value="attrTimeEnd" type="text" placeholder="结束时间(留空=现在)" size="tiny" />
            <n-button type="primary" size="small" @click="runAttribution" :loading="loading" block>
              🤖 多源LLM归因分析
            </n-button>
            <n-button size="tiny" @click="fetchReports" block>刷新列表</n-button>
          </n-space>
        </n-card>

        <n-card title="报告列表" size="small" :bordered="false" class="section-card">
          <n-empty v-if="!filteredReports.length" description="暂无报告，请运行归因分析" style="padding:20px" />
          <div v-for="r in pagedReports" :key="r.id" class="report-entry"
            :class="{ active: selectedReport?.id === r.id }" @click="selectReport(r)">
            <div class="report-entry-title">{{ r.report_id || r.id }}</div>
            <n-tag :type="r.confidence === 'High' ? 'error' : 'info'" size="tiny">{{ r.confidence || '?' }}</n-tag>
            <div class="report-entry-time">{{ r.time_start || r.created_at || '' }}</div>
          </div>
          <n-space justify="center" v-if="filteredReports.length > pageSize">
            <n-button size="tiny" :disabled="reportPage <= 1" @click="reportPage--">上一页</n-button>
            <span class="text-muted" style="font-size:11px">{{ reportPage }}/{{ totalPages }}</span>
            <n-button size="tiny" :disabled="reportPage >= totalPages" @click="reportPage++">下一页</n-button>
          </n-space>
        </n-card>
      </n-grid-item>

      <!-- Right: Report Detail -->
      <n-grid-item :span="5">
        <n-card :bordered="false" class="section-card">
          <template #header>
            <span>📋 {{ selectedReport ? '归因分析报告' : '请选择报告或运行归因分析' }}</span>
          </template>

          <n-empty v-if="!selectedReport" description="选择左侧报告查看详情，或输入时间范围运行归因分析" style="padding:60px" />

          <n-tabs v-else type="line" size="small">
            <n-tab-pane name="llm" tab="🤖 LLM分析">
              <div v-if="selectedReport.llm_analysis" class="llm-box">
                <n-alert type="info" :bordered="false" title="DeepSeek 威胁归因分析">
                  <div class="llm-text">{{ selectedReport.llm_analysis }}</div>
                </n-alert>
              </div>
              <n-empty v-else description="该报告不包含 LLM 分析" />
            </n-tab-pane>
            <n-tab-pane name="summary" tab="📊 摘要">
              <n-descriptions bordered size="small" :column="2">
                <n-descriptions-item label="报告ID">{{ selectedReport.report_id || '-' }}</n-descriptions-item>
                <n-descriptions-item label="置信度">{{ selectedReport.confidence || '-' }}</n-descriptions-item>
                <n-descriptions-item label="事件总数">{{ selectedReport.total_events || '-' }}</n-descriptions-item>
                <n-descriptions-item label="检测技术数">{{ selectedReport.techniques_found || '-' }}</n-descriptions-item>
                <n-descriptions-item label="时间范围">{{ selectedReport.time_start || '-' }} ~ {{ selectedReport.time_end || '-' }}</n-descriptions-item>
                <n-descriptions-item label="LLM模型">{{ selectedReport.llm_model || '-' }}</n-descriptions-item>
              </n-descriptions>
            </n-tab-pane>
            <n-tab-pane name="chain" tab="🔗 攻击链">
              <div v-if="attackChain.length">
                <n-tag v-for="(tech, i) in attackChain" :key="i" type="error" size="small" class="mr-1 mb-1">{{ tech }}</n-tag>
              </div>
              <n-empty v-else description="无攻击链数据" />
            </n-tab-pane>
            <n-tab-pane name="iocs" tab="🎯 IOCs">
              <n-space>
                <n-tag v-for="(ioc, i) in selectedIocs" :key="i" type="error" size="tiny">{{ ioc }}</n-tag>
              </n-space>
              <n-empty v-if="!selectedIocs.length" description="无 IOCs" />
            </n-tab-pane>
            <n-tab-pane name="raw" tab="📄 原始JSON">
              <pre class="attr-pre">{{ JSON.stringify(selectedReport, null, 2) }}</pre>
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
import { listAnalysisReports } from '@/api/attack'
import axios from 'axios'

const message = useMessage()
const loading = ref(false)
const reports = ref<any[]>([])
const selectedReport = ref<any>(null)
const searchQuery = ref('')
const attrTimeStart = ref('')
const attrTimeEnd = ref('')
const reportPage = ref(1)
const pageSize = ref(10)

const filteredReports = computed(() => {
  if (!searchQuery.value) return reports.value
  const q = searchQuery.value.toLowerCase()
  return reports.value.filter((r: any) => (r.report_id || '').toLowerCase().includes(q))
})
const totalPages = computed(() => Math.max(1, Math.ceil(filteredReports.value.length / pageSize.value)))
const pagedReports = computed(() => {
  const s = (reportPage.value - 1) * pageSize.value
  return filteredReports.value.slice(s, s + pageSize.value)
})

const attackChain = computed(() => {
  const ac = selectedReport.value?.attack_chain
  if (!ac) return []
  return Array.isArray(ac) ? ac : (typeof ac === 'string' ? (() => { try { return JSON.parse(ac) } catch { return [] } })() : [])
})
const selectedIocs = computed(() => {
  const iocs = selectedReport.value?.iocs
  if (!iocs) return []
  return Array.isArray(iocs) ? iocs : (typeof iocs === 'string' ? (() => { try { return JSON.parse(iocs) } catch { return [] } })() : [])
})

async function fetchReports() {
  try {
    const res = await listAnalysisReports()
    if (res.data?.ok) reports.value = res.data.data || []
  } catch {}
}

function selectReport(r: any) { selectedReport.value = r }

async function runAttribution() {
  loading.value = true
  try {
    const payload: any = {}
    if (attrTimeStart.value) payload.time_start = attrTimeStart.value
    if (attrTimeEnd.value) payload.time_end = attrTimeEnd.value
    const res = await axios.post('/attack/api/analyze/unified', payload, { timeout: 120000 })
    if (res.data?.ok) {
      message.success(`归因分析完成：${res.data.techniques_count || '?'} 个技术已识别`)
      await fetchReports()
      if (reports.value.length > 0) selectReport(reports.value[0])
    } else {
      message.error(res.data?.error || '分析失败')
    }
  } catch (e: any) {
    message.error('分析失败: ' + (e?.response?.data?.error || e?.message || ''))
  }
  finally { loading.value = false }
}

onMounted(() => { fetchReports() })
</script>

<style scoped>
.attr-wrap { max-width: 1200px; margin: 0 auto; }
.page-title { font-size: 20px; margin-bottom: 16px; }
.page-title small { font-size: 13px; color: #6b7280; font-weight: 400; }
.mb-3 { margin-bottom: 16px; }
.mr-1 { margin-right: 4px; }
.mb-1 { margin-bottom: 4px; }
.section-card { border-radius: 14px; }
.report-entry { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; cursor: pointer; border-radius: 6px; }
.report-entry:hover { background: #f7f9fc; }
.report-entry.active { background: #e8f0ff; }
.report-entry-title { font-weight: 600; font-size: 13px; margin-bottom: 2px; }
.report-entry-time { font-size: 10px; color: #94a3b8; margin-top: 2px; }
.llm-box { max-height: 500px; overflow-y: auto; }
.llm-text { white-space: pre-wrap; font-size: 14px; line-height: 1.8; margin-top: 8px; color: #1e3a5f; }
.attr-pre { background: #f8fafc; padding: 16px; border-radius: 8px; max-height: 450px; overflow: auto; font-size: 12px; line-height: 1.6; white-space: pre-wrap; }
.text-muted { color: #6b7280; }
</style>
