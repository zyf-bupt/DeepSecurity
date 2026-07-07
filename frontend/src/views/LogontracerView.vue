<template>
  <div class="lt-wrap">
    <div class="lt-header">
      <div>
        <h2>登录会话可视化（LogonTracer）</h2>
        <p class="text-muted">基于 HostLogs.result 构建登录关系图、会话列表与时间线。</p>
      </div>
      <n-space>
        <n-button size="small" @click="$router.push('/logs')">返回日志分析</n-button>
      </n-space>
    </div>

    <!-- Toolbar -->
    <n-card size="small" :bordered="false" class="toolbar-card">
      <n-space vertical size="small">
        <n-grid :cols="4" :x-gap="12" responsive="screen">
          <n-grid-item>
            <n-form-item label="开始时间" label-placement="top" size="small">
              <n-input v-model:value="filters.start" type="datetime-local" />
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="结束时间" label-placement="top" size="small">
              <n-input v-model:value="filters.end" type="datetime-local" />
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="用户" label-placement="top" size="small">
              <n-input v-model:value="filters.user" placeholder="可选 user" />
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="源 IP" label-placement="top" size="small">
              <n-input v-model:value="filters.srcIp" placeholder="可选 src_ip" />
            </n-form-item>
          </n-grid-item>
        </n-grid>
        <n-grid :cols="3" :x-gap="12" responsive="screen">
          <n-grid-item>
            <n-form-item label="主机（可多选）" label-placement="top" size="small">
              <n-select v-model:value="filters.hostNames" :options="hostOptions" placeholder="选择主机" multiple clearable filterable size="small" />
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="聚合粒度" label-placement="top" size="small">
              <n-select v-model:value="filters.bucket" :options="bucketOptions" size="small" />
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="&nbsp;" label-placement="top" size="small">
              <n-button type="primary" size="small" @click="startAnalysis" :loading="jobRunning">
                开始分析
              </n-button>
            </n-form-item>
          </n-grid-item>
        </n-grid>
        <n-alert :type="statusType" :bordered="false">
          {{ statusText }}
        </n-alert>
      </n-space>
    </n-card>

    <!-- Results -->
    <n-grid :cols="2" :x-gap="16" :y-gap="16" responsive="screen" v-if="jobDone">
      <n-grid-item>
        <n-card title="登录关系图" size="small" :bordered="false" class="section-card">
          <div ref="graphGrid" class="graph-grid"></div>
        </n-card>
      </n-grid-item>
      <n-grid-item>
        <n-card title="时间线（成功/失败）" size="small" :bordered="false" class="section-card">
          <div class="chart-wrap">
            <canvas ref="timelineCanvas"></canvas>
          </div>
        </n-card>
      </n-grid-item>
    </n-grid>

    <!-- Sessions Table -->
    <n-card title="登录会话列表" size="small" :bordered="false" class="section-card mt-2" v-if="jobDone">
      <n-data-table :columns="sessionColumns" :data="sessions" :bordered="false" size="small" max-height="400"
        :row-key="(row: any) => row.host_ip + '|' + row.session_id"
        :expanded-row-keys="expandedKeys"
        @update:expanded-row-keys="onExpand" />
    </n-card>

    <!-- Session detail modal -->
    <n-modal v-model:show="detailVisible" title="会话事件详情" style="max-width:800px" preset="card">
      <n-data-table :columns="eventColumns" :data="detailEvents" :bordered="false" size="small" max-height="400" />
      <n-empty v-if="!detailEvents.length" description="无事件数据" />
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick, h } from 'vue'
import { NButton, useMessage } from 'naive-ui'
import axios from 'axios'

const message = useMessage()

// ---- Filters ----
const filters = ref({
  start: '', end: '', user: '', srcIp: '',
  hostNames: [] as string[], bucket: 'hour',
})
const hostOptions = ref<{ label: string; value: string }[]>([])
const bucketOptions = [
  { label: '按小时', value: 'hour' },
  { label: '按天', value: 'day' },
]

// ---- Job State ----
const jobRunning = ref(false)
const jobDone = ref(false)
const statusText = ref('等待启动分析。')
const statusType = ref<'info' | 'success' | 'error' | 'warning'>('info')
let jobId = ''
let pollTimer: ReturnType<typeof setTimeout> | null = null

// ---- Graph ----
const graphGrid = ref<HTMLDivElement>()
let cyInstances: any[] = []

// ---- Timeline ----
const timelineCanvas = ref<HTMLCanvasElement>()
let timelineChart: any = null

// ---- Sessions ----
const sessions = ref<any[]>([])
const sessionColumns = [
  { title: 'Host', key: 'host_ip', width: 140 },
  { title: 'Session ID', key: 'session_id', width: 100 },
  { title: 'User', key: 'user', width: 120 },
  { title: 'Source IP', key: 'src_ip', width: 140 },
  { title: 'Start', key: 'start_time', width: 180 },
  { title: 'End', key: 'end_time', width: 180 },
  { title: 'Events', key: 'events', width: 80 },
  { title: 'Status', key: 'status', width: 80 },
  {
    title: '详情', key: 'actions', width: 80,
    render: (row: any) => h(NButton, { size: 'tiny', onClick: (e: Event) => { e.stopPropagation(); showDetail(row) } }, { default: () => 'Events' }),
  },
]

// ---- Detail Modal ----
const detailVisible = ref(false)
const detailEvents = ref<any[]>([])
const expandedKeys = ref<string[]>([])
const eventColumns = [
  { title: 'Time', key: 'timestamp', width: 180 },
  { title: 'Type', key: 'event_type', width: 120 },
  { title: 'ID', key: 'raw_id', width: 80 },
  { title: 'User', key: 'user', width: 120, render: (row: any) => row.entities?.user || '' },
  { title: 'Source IP', key: 'src', width: 140, render: (row: any) => row.entities?.src_ip || '' },
  { title: 'Description', key: 'description', ellipsis: { tooltip: true } },
]

// ---- Methods ----
function clearViews() {
  cyInstances.forEach((c: any) => { try { c.destroy() } catch {} })
  cyInstances = []
  if (graphGrid.value) graphGrid.value.innerHTML = ''
  if (timelineChart) { try { timelineChart.destroy() } catch {}; timelineChart = null }
  sessions.value = []
}

function stopPolling() {
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = null }
}

async function loadHostNames() {
  try {
    const res = await axios.get('/logs/', { params: { format: 'json' } })
    hostOptions.value = (res.data?.host_names || []).map((n: string) => ({ label: n, value: n }))
  } catch {}
}

async function startAnalysis() {
  clearViews()
  jobDone.value = false
  jobRunning.value = true
  statusText.value = '分析启动中...'
  statusType.value = 'info'

  try {
    const payload: any = {}
    if (filters.value.start) payload.start = new Date(filters.value.start).toISOString()
    if (filters.value.end) payload.end = new Date(filters.value.end).toISOString()
    if (filters.value.user) payload.user = filters.value.user
    if (filters.value.srcIp) payload.src_ip = filters.value.srcIp
    if (filters.value.hostNames.length) payload.host_names = filters.value.hostNames
    payload.bucket = filters.value.bucket

    const res = await axios.post('/api/logontracer/start', payload)
    if (!res.data?.job_id) {
      statusText.value = '启动失败'
      statusType.value = 'error'
      jobRunning.value = false
      return
    }
    jobId = res.data.job_id
    pollJob()
  } catch {
    statusText.value = '启动失败：请求异常'
    statusType.value = 'error'
    jobRunning.value = false
  }
}

function pollJob() {
  stopPolling()
  axios.get(`/api/logontracer/job/${jobId}`).then(({ data }) => {
    if (!data || !data.status) {
      statusText.value = '状态获取失败'
      statusType.value = 'error'
      jobRunning.value = false
      return
    }
    if (data.status === 'error') {
      statusText.value = `分析失败：${data.message || '未知错误'}`
      statusType.value = 'error'
      jobRunning.value = false
      return
    }
    if (data.status !== 'done') {
      statusText.value = `运行中... ${data.progress || 0}% ${data.message || ''}`
      statusType.value = 'info'
      pollTimer = setTimeout(pollJob, 1000)
      return
    }
    // Done!
    statusText.value = '分析完成。'
    statusType.value = 'success'
    jobRunning.value = false
    jobDone.value = true
    if (data.result_refs) renderAll(data.result_refs)
  }).catch(() => {
    statusText.value = '状态获取异常'
    statusType.value = 'error'
    jobRunning.value = false
  })
}

async function renderAll(refs: any) {
  await nextTick()
  fetchGraph(refs.graph_url)
  fetchTimeline(refs.timeline_url)
  fetchSessions(refs.sessions_url)
}

async function fetchGraph(url: string) {
  try {
    const { data } = await axios.get(url)
    if (!data) return
    const graphs = data.graphs || []
    if (graphs.length) {
      graphs.forEach((item: any) => renderGraph(item.elements, item.host))
      return
    }
    if (data.elements) renderGraph(data.elements, 'All Hosts')
  } catch {}
}

function renderGraph(elements: any, hostLabel: string) {
  if (!graphGrid.value) return
  const panel = document.createElement('div')
  panel.className = 'lt-graph-panel'
  const label = document.createElement('div')
  label.className = 'lt-graph-label'
  label.textContent = hostLabel || 'Host'
  const canvas = document.createElement('div')
  canvas.className = 'lt-graph-canvas'
  canvas.style.width = '100%'
  canvas.style.height = '280px'
  panel.appendChild(label)
  panel.appendChild(canvas)
  graphGrid.value.appendChild(panel)

  try {
    const cy = (window as any).cytoscape({
      container: canvas,
      elements,
      layout: { name: 'cose', animate: false },
      style: [
        { selector: 'node', style: { 'background-color': '#2563eb', label: 'data(label)', color: '#0f172a', 'font-size': '10px', 'text-valign': 'center', 'text-halign': 'center', width: 'mapData(weight, 1, 20, 20, 48)', height: 'mapData(weight, 1, 20, 20, 48)' } },
        { selector: 'node[type="user"]', style: { 'background-color': '#16a34a' } },
        { selector: 'node[type="ip"]', style: { 'background-color': '#f59e0b' } },
        { selector: 'node[type="host"]', style: { 'background-color': '#2563eb' } },
        { selector: 'edge', style: { 'line-color': '#94a3b8', 'target-arrow-color': '#94a3b8', 'target-arrow-shape': 'triangle', width: 'mapData(success_count, 1, 20, 1, 4)', 'curve-style': 'bezier' } },
      ],
    })
    cyInstances.push(cy)
  } catch {}
}

async function fetchTimeline(url: string) {
  try {
    const { data } = await axios.get(url)
    if (!data?.series) return
    renderTimeline(data)
  } catch {}
}

function renderTimeline(payload: any) {
  if (!timelineCanvas.value) return
  const Chart = (window as any).Chart
  if (!Chart) return

  const success = (payload.series.success || []).map((item: any) => ({ x: item.t, y: item.v }))
  const fail = (payload.series.fail || []).map((item: any) => ({ x: item.t, y: item.v }))
  const unit = payload.bucket === 'day' ? 'day' : 'hour'

  const ctx = timelineCanvas.value.getContext('2d')
  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      datasets: [
        { label: 'Success', data: success, borderColor: '#16a34a', backgroundColor: 'rgba(22,163,74,0.2)', tension: 0.25 },
        { label: 'Fail', data: fail, borderColor: '#dc2626', backgroundColor: 'rgba(220,38,38,0.2)', tension: 0.25 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: { x: { type: 'time', time: { unit } }, y: { beginAtZero: true } },
      plugins: { legend: { position: 'bottom' } },
    },
  })
}

async function fetchSessions(url: string) {
  try {
    const { data } = await axios.get(url, { params: { job_id: jobId, draw: 1, start: 0, length: 200 } })
    sessions.value = data?.data || []
  } catch {}
}

async function showDetail(row: any) {
  detailVisible.value = true
  detailEvents.value = []
  try {
    const params: any = { job_id: jobId, host_ip: row.host_ip, session_id: row.session_id }
    if (row.start_time) params.start_time = row.start_time
    if (row.end_time) params.end_time = row.end_time
    const { data } = await axios.get('/api/logontracer/session_events', { params })
    detailEvents.value = data?.events || []
  } catch {}
}

function onExpand(keys: string[]) {
  expandedKeys.value = keys
}

// ---- Lifecycle ----
onMounted(() => loadHostNames())
onUnmounted(() => { stopPolling(); clearViews() })
</script>

<style scoped>
.lt-wrap { max-width: 1200px; margin: 0 auto; }
.lt-header { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px; margin-bottom: 14px; }
.lt-header h2 { margin: 0 0 4px 0; }
.text-muted { color: #6b7280; font-size: 13px; }
.toolbar-card { border-radius: 14px; margin-bottom: 16px; }
.section-card { border-radius: 14px; }
.mt-2 { margin-top: 12px; }
.graph-grid { display: flex; flex-wrap: wrap; gap: 12px; min-height: 300px; }
:deep(.lt-graph-panel) { flex: 1; min-width: 300px; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; }
:deep(.lt-graph-label) { padding: 6px 10px; background: #f8fafc; font-size: 12px; font-weight: 700; border-bottom: 1px solid #e5e7eb; }
:deep(.lt-graph-canvas) { width: 100%; height: 280px; }
.chart-wrap { position: relative; height: 300px; }
.chart-wrap canvas { width: 100% !important; height: 100% !important; }
</style>
