<template>
  <div class="tf-wrap">
    <div class="tf-header">
      <h2>网络流量分析</h2>
      <p class="text-muted">在线抓包使用 <b>dumpcap</b> 子进程写入 pcapng 文件，停止后自动解析并入库（更稳定，适合演示）。</p>
    </div>

    <!-- ====== Online Capture ====== -->
    <n-card title="在线抓包（dumpcap）" :bordered="false" class="section-card">
      <template #header-extra>
        <span class="tf-hint">仅在"停止并导入入库"时进行解析与分析。BPF 示例：<code>net 192.168.86.0/24</code> / <code>host 192.168.86.131</code> / <code>icmp</code></span>
      </template>

      <n-space vertical size="small">
        <!-- Dumpcap status -->
        <n-alert v-if="dumpcapInfo.found" type="success" :bordered="false" class="mb-2">
          ✅ dumpcap 已检测: <code>{{ dumpcapInfo.dumpcap_path }}</code> ｜ 检测到 {{ dumpcapInfo.interfaces?.length || 0 }} 个网卡
        </n-alert>
        <n-alert v-else type="warning" :bordered="false" class="mb-2">
          ⚠️ dumpcap 未找到。请在下方输入完整路径，或设置环境变量 <code>DUMPCAP_PATH=E:\wireshark\dumpcap.exe</code>
        </n-alert>

        <!-- Row 1: iface selector + host_name -->
        <n-grid :cols="3" :x-gap="12" responsive="screen">
          <n-grid-item :span="2">
            <n-form-item label="网卡 iface（必填）" label-placement="top" size="small">
              <n-select v-if="dumpcapInfo.interfaces?.length"
                v-model:value="captureConfig.iface"
                :options="dumpcapInfo.interfaces.map((i: any) => ({ label: `[${i.index}] ${i.description || i.id}`, value: i.id }))"
                placeholder="选择网卡" filterable />
              <n-input v-else v-model:value="captureConfig.iface" placeholder="\Device\NPF_{...}" />
              <template #feedback><span class="help">优先从已检测网卡中选择。</span></template>
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="host_name（可选）" label-placement="top" size="small">
              <n-input v-model:value="captureConfig.host_name" placeholder="VMnet1 / sensor-1" />
              <template #feedback><span class="help">入库标记采集点。</span></template>
            </n-form-item>
          </n-grid-item>
        </n-grid>

        <!-- Row 2: BPF + analysis + dumpcap -->
        <n-grid :cols="3" :x-gap="12" responsive="screen">
          <n-grid-item>
            <n-form-item label="BPF（可空）" label-placement="top" size="small">
              <n-input v-model:value="captureConfig.bpf" placeholder="net 192.168.86.0/24" />
              <template #feedback><span class="help">留空表示不过滤。</span></template>
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="分析开关" label-placement="top" size="small">
              <n-switch v-model:value="captureConfig.enable_analysis" />
              <template #feedback><span class="help">启用后写入结构化检测字段。</span></template>
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="dumpcap_path" label-placement="top" size="small">
              <n-input v-model:value="captureConfig.dumpcap_path" :placeholder="dumpcapInfo.dumpcap_path || '自动检测'" />
              <template #feedback><span class="help">自动检测，可手动覆盖。</span></template>
            </n-form-item>
          </n-grid-item>
        </n-grid>

        <!-- Buttons -->
        <n-space>
          <n-button type="primary" @click="startCapture" :loading="capturing" :disabled="liveRunning">▶ 开始捕获</n-button>
          <n-button type="warning" @click="stopCapture" :loading="stopping" :disabled="!liveRunning">■ 停止并导入入库</n-button>
        </n-space>

        <!-- Status -->
        <n-alert v-if="captureStatus" :type="captureStatus.includes('ERROR') ? 'error' : (liveRunning ? 'success' : 'default')" closable>
          {{ captureStatus }}
        </n-alert>
        <n-alert v-if="importStatus" type="success" closable>
          {{ importStatus }}
        </n-alert>
      </n-space>
    </n-card>

    <!-- ====== Offline Upload ====== -->
    <n-card title="离线导入（pcap / pcapng）" :bordered="false" class="section-card">
      <template #header-extra>
        <span class="tf-hint">上传后立即解析并写入数据库（NetworkTraffic）。</span>
      </template>
      <n-space vertical size="small">
        <n-grid :cols="3" :x-gap="12" responsive="screen">
          <n-grid-item :span="2">
            <n-form-item label="选择文件" label-placement="top" size="small">
              <n-upload
                :multiple="false"
                accept=".pcap,.pcapng,.cap"
                :show-file-list="true"
                :custom-request="handleUpload"
                :disabled="uploading"
              >
                <n-button :loading="uploading">选择文件并上传</n-button>
              </n-upload>
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="host_name（可选）" label-placement="top" size="small">
              <n-input v-model:value="uploadHostName" placeholder="pcap_import" />
            </n-form-item>
          </n-grid-item>
        </n-grid>
        <n-alert v-if="uploadMsg" :type="uploadMsgType" closable>{{ uploadMsg }}</n-alert>
      </n-space>
    </n-card>

    <!-- ====== Traffic Table ====== -->
    <n-card :bordered="false" class="section-card">
      <template #header>
        <div class="section-header">
          <span>最近流量</span>
        </div>
      </template>

      <!-- Search & Filter Bar -->
      <n-space vertical size="small" class="mb-2">
        <n-grid :cols="5" :x-gap="12" responsive="screen">
          <n-grid-item>
            <n-form-item label="搜索 IP" label-placement="top" size="small">
              <n-input v-model:value="searchIp" placeholder="src 或 dst IP" size="small" clearable @keyup.enter="fetchTraffic" />
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="开始时间" label-placement="top" size="small">
              <n-input v-model:value="searchTimeStart" type="datetime-local" size="small" />
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="结束时间" label-placement="top" size="small">
              <n-input v-model:value="searchTimeEnd" type="datetime-local" size="small" />
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="event_type" label-placement="top" size="small">
              <n-select v-model:value="eventType" :options="eventTypeOptions" placeholder="全部" size="small" clearable />
            </n-form-item>
          </n-grid-item>
          <n-grid-item>
            <n-form-item label="&nbsp;" label-placement="top" size="small">
              <n-space>
                <n-button size="small" type="primary" @click="fetchTraffic">🔍 搜索</n-button>
                <n-button size="small" @click="resetFilters">🔄 重置</n-button>
              </n-space>
            </n-form-item>
          </n-grid-item>
        </n-grid>
      </n-space>

      <n-spin :show="loading">
        <p class="text-muted small mb-2">📦 总数：<b>{{ total }}</b> ｜ 📄 第 <b>{{ page }}</b> / <b>{{ totalPages || 1 }}</b> 页 ｜ 每页 {{ pageSize }} 条</p>

        <n-data-table :columns="columns" :data="items" :bordered="false" size="small" max-height="450" :scroll-x="1100" />

        <n-space justify="center" class="mt-2">
          <n-button size="small" :disabled="page <= 1" @click="page--; fetchTraffic()">⬅ 上一页</n-button>
          <n-input-number v-model:value="page" size="tiny" :min="1" :max="totalPages || 1" style="width:80px" @update:value="fetchTraffic" />
          <span class="text-muted small">/ {{ totalPages || 1 }}</span>
          <n-button size="small" @click="fetchTraffic">跳转</n-button>
          <n-button size="small" :disabled="page >= totalPages" @click="page++; fetchTraffic()">下一页 ➡</n-button>
        </n-space>
      </n-spin>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, h } from 'vue'
import { NButton, NTag, useMessage } from 'naive-ui'
import { useRouter } from 'vue-router'
import { getLiveStatus, getDumpcapInfo, startLiveCapture, stopLiveCapture, uploadPcap } from '@/api/traffic'
import type { UploadCustomRequestOptions } from 'naive-ui'

const router = useRouter()
const message = useMessage()

// ---- Capture State ----
const captureConfig = ref({
  iface: '',
  bpf: '',
  host_name: '',
  enable_analysis: true,
  dumpcap_path: '',
})
const dumpcapInfo = ref<any>({ found: false, dumpcap_path: '', interfaces: [] })
const liveRunning = ref(false)
const capturing = ref(false)
const stopping = ref(false)
const captureStatus = ref('')
const importStatus = ref('')

// ---- Upload State ----
const uploadHostName = ref('')
const uploading = ref(false)
const uploadMsg = ref('')
const uploadMsgType = ref<'success' | 'error' | 'info'>('info')

// ---- Table State ----
const loading = ref(false)
const items = ref<any[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const totalPages = ref(1)
const eventType = ref<string | null>(null)
const searchIp = ref('')
const searchTimeStart = ref('')
const searchTimeEnd = ref('')

const eventTypeOptions = [
  { label: '全部', value: '' },
  { label: '仅告警（suspected）', value: '__alert__' },
  { label: 'DNS 隧道（suspected）', value: 'dns_tunnel_suspected' },
  { label: 'HTTP 隧道（suspected）', value: 'http_tunnel_suspected' },
  { label: 'ICMP 隧道（suspected）', value: 'icmp_tunnel_suspected' },
  { label: 'DNS 查询', value: 'dns_query' },
  { label: 'TCP 连接', value: 'tcp_connection' },
]

const columns = [
  { title: 'ID', key: 'id', width: 70 },
  { title: 'create_time', key: 'create_time', width: 180, ellipsis: { tooltip: true } },
  { title: 'timestamp', key: 'timestamp', width: 180, ellipsis: { tooltip: true } },
  { title: 'src_ip', key: 'src_ip', width: 150 },
  { title: 'dst_ip', key: 'dst_ip', width: 150 },
  { title: 'protocol', key: 'protocol', width: 90 },
  {
    title: 'event_type', key: 'event_type', width: 180, ellipsis: { tooltip: true },
    render: (row: any) => {
      const t = row.event_type || ''
      return h(NTag, { type: t.includes('suspected') || t.includes('tunnel') ? 'error' : 'info', size: 'tiny' }, { default: () => t })
    },
  },
  { title: 'description', key: 'description', width: 200, ellipsis: { tooltip: true } },
  {
    title: '操作', key: 'actions', width: 80,
    render: (row: any) => h(NButton, { size: 'tiny', type: 'primary', onClick: () => router.push(`/traffic/${row.id}`) }, { default: () => '详情' }),
  },
]

// ---- API Calls ----
async function checkStatus() {
  try {
    const res = await getLiveStatus()
    if (res.data?.ok) {
      liveRunning.value = !!res.data.running
      const pcap = res.data.pcap_file || res.data.last_capture_file || '-'
      const err = res.data.last_error ? ` | last_error=${res.data.last_error}` : ''
      captureStatus.value = `状态：${liveRunning.value ? 'RUNNING' : 'STOPPED'} | pcap=${pcap}${err}`
      if (res.data.last_import) {
        const r = res.data.last_import
        importStatus.value = `最近一次导入：inserted=${r.inserted || 0} skipped=${r.skipped || 0} errors=${r.errors || 0} total_packets=${r.total_packets || 0}`
      }
    }
  } catch { captureStatus.value = '状态获取异常' }
}

function resetFilters() {
  searchIp.value = ''; searchTimeStart.value = ''; searchTimeEnd.value = ''
  eventType.value = null; page.value = 1; fetchTraffic()
}

async function fetchTraffic() {
  loading.value = true
  try {
    const axios = (await import('axios')).default
    const params: any = { page: page.value }
    if (eventType.value) params.event_type = eventType.value
    const res = await axios.get('/traffic/api/list', { params })
    let all: any[] = []
    if (res.data?.ok) {
      all = res.data.items || []
    }

    // Client-side filters for IP and time range
    if (searchIp.value) {
      const q = searchIp.value.toLowerCase()
      all = all.filter((it: any) =>
        (it.src_ip || '').toLowerCase().includes(q) || (it.dst_ip || '').toLowerCase().includes(q)
      )
    }
    if (searchTimeStart.value) {
      const ts = searchTimeStart.value
      all = all.filter((it: any) => (it.timestamp || it.create_time || '') >= ts)
    }
    if (searchTimeEnd.value) {
      const te = searchTimeEnd.value
      all = all.filter((it: any) => (it.timestamp || it.create_time || '') <= te)
    }

    // Sort by create_time descending
    all.sort((a, b) => (b.create_time || b.timestamp || '').localeCompare(a.create_time || a.timestamp || ''))

    total.value = all.length
    totalPages.value = Math.max(1, Math.ceil(total.value / pageSize.value))
    const start = (page.value - 1) * pageSize.value
    items.value = all.slice(start, start + pageSize.value)
  } catch {
    items.value = []; total.value = 0; totalPages.value = 1
  }
  finally { loading.value = false }
}

async function startCapture() {
  const iface = captureConfig.value.iface.trim()
  if (!iface) { message.warning('请填写网卡 iface（必填）'); return }
  capturing.value = true
  try {
    const res = await startLiveCapture({
      iface,
      bpf: captureConfig.value.bpf.trim() || undefined,
      host_name: captureConfig.value.host_name.trim() || undefined,
      dumpcap_path: captureConfig.value.dumpcap_path.trim() || undefined,
    })
    if (res.data?.ok) { liveRunning.value = true; message.success('抓包已启动'); checkStatus() }
    else { message.error(res.data?.error || '启动失败') }
  } catch (e: any) { message.error('启动失败: ' + (e?.message || 'unknown')) }
  finally { capturing.value = false }
}

async function stopCapture() {
  stopping.value = true
  try {
    const res = await stopLiveCapture({
      enable_analysis: captureConfig.value.enable_analysis,
      host_name: captureConfig.value.host_name.trim() || undefined,
    })
    if (res.data?.ok) {
      liveRunning.value = false; message.success('抓包已停止并导入入库')
      if (res.data.import) {
        const r = res.data.import
        importStatus.value = `导入完成：inserted=${r.inserted || 0} skipped=${r.skipped || 0} errors=${r.errors || 0} total_packets=${r.total_packets || 0}`
      }
      checkStatus(); fetchTraffic()
    } else { message.error(res.data?.error || '停止失败') }
  } catch (e: any) { message.error('停止失败: ' + (e?.message || 'unknown')) }
  finally { stopping.value = false }
}

async function handleUpload({ file, onFinish, onError }: UploadCustomRequestOptions) {
  uploading.value = true
  uploadMsg.value = '上传中并解析入库...'
  uploadMsgType.value = 'info'
  try {
    const formData = new FormData()
    formData.append('file', (file as any).file as File)
    formData.append('host_name', uploadHostName.value || 'pcap_import')
    formData.append('enable_analysis', '1')
    const res = await uploadPcap(formData)
    if (res.data?.ok) {
      const r = res.data.result || {}
      uploadMsg.value = `导入完成：inserted=${r.inserted || 0} skipped=${r.skipped || 0} errors=${r.errors || 0} total_packets=${r.total_packets || 0}`
      uploadMsgType.value = 'success'
      message.success('上传成功')
      onFinish()
      fetchTraffic()
    } else {
      uploadMsg.value = '上传失败：' + (res.data?.error || 'unknown')
      uploadMsgType.value = 'error'
      onError()
    }
  } catch (e: any) {
    uploadMsg.value = '上传异常：' + (e?.message || 'unknown')
    uploadMsgType.value = 'error'
    onError()
  }
  finally { uploading.value = false }
}

async function loadDumpcapInfo() {
  try {
    const res = await getDumpcapInfo()
    if (res.data?.ok) {
      dumpcapInfo.value = res.data
      captureConfig.value.dumpcap_path = res.data.dumpcap_path || ''
      // Auto-fill first available interface if empty
      if (!captureConfig.value.iface && res.data.interfaces?.length) {
        const vmnet = res.data.interfaces.find((i: any) => i.description?.includes('VMnet'))
        captureConfig.value.iface = vmnet ? vmnet.id : res.data.interfaces[0].id
      }
    }
  } catch {}
}

let pollTimer: ReturnType<typeof setInterval> | null = null
onMounted(() => { loadDumpcapInfo(); checkStatus(); fetchTraffic(); pollTimer = setInterval(checkStatus, 1500) })
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.tf-wrap { max-width: 1200px; margin: 0 auto; }
.tf-header { margin-bottom: 14px; }
.tf-header h2 { margin: 0 0 4px 0; }
.text-muted { color: #6b7280; font-size: 13px; }
.small { font-size: 12px; }
.mb-2 { margin-bottom: 10px; }
.mt-2 { margin-top: 12px; }
.section-card { border-radius: 14px; margin-bottom: 16px; }
.section-header { display: flex; align-items: center; justify-content: space-between; width: 100%; }
.tf-hint { font-size: 12px; color: #6b7280; }
.help { font-size: 11px; color: #94a3b8; }
code { background: #f1f5f9; padding: 1px 5px; border-radius: 3px; font-size: 11px; }
</style>
