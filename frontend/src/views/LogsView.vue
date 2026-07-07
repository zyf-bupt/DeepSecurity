<template>
  <div class="logs-wrap">
    <h2>主机日志分析</h2>
    <p class="text-muted">扫描服务器 Windows Event Log，归一化后写入 SQL Server（dbo.HostLogs）。支持按 host_name 精确筛选。</p>

    <!-- Toolbar -->
    <n-card size="small" :bordered="false" class="toolbar-card">
      <n-space vertical size="small">
        <!-- Row 1: Actions -->
        <n-space align="center" wrap>
          <n-button type="primary" size="small" @click="collectLogs" :loading="collecting">
            🖥️ 扫描服务器日志并入库
          </n-button>
          <n-divider vertical />
          <span class="text-muted" style="font-size:12px">主机筛选:</span>
          <n-select v-model:value="hostName" :options="hostOptions" placeholder="全部主机" size="small" clearable filterable style="width:200px" @update:value="fetchLogs" />
          <n-button size="small" @click="fetchLogs">🔍 筛选</n-button>
          <n-button size="small" @click="hostName = ''; fetchLogs()">清除</n-button>
          <n-divider vertical />
          <span class="text-muted" style="font-size:12px">DB:</span>
          <n-input v-model:value="dbServer" size="tiny" placeholder="localhost,1433" style="width:180px" />
          <n-button size="tiny" @click="setDb">应用</n-button>
          <n-divider vertical />
          <span class="text-muted" style="font-size:12px">📦 总数: <b>{{ total }}</b> ｜ 📄 <b>{{ page }}</b> / <b>{{ totalPages || 1 }}</b> 页</span>
        </n-space>

        <!-- Flash messages -->
        <n-alert v-if="flashMsg" :type="flashType" closable @close="flashMsg = ''">
          {{ flashMsg }}
        </n-alert>
      </n-space>
    </n-card>

    <!-- Table -->
    <n-card :bordered="false" class="section-card">
      <n-spin :show="loading">
        <n-data-table :columns="columns" :data="logs" :bordered="false" size="small" max-height="500" />
        <n-empty v-if="!loading && logs.length === 0" description="暂无数据。请点击上方「扫描服务器日志并入库」或调整筛选条件。" style="padding:40px" />

        <!-- Pagination -->
        <n-space justify="center" align="center" class="mt-2">
          <n-button size="small" :disabled="page <= 1" @click="page--; fetchLogs()">⬅ 上一页</n-button>
          <n-input-number v-model:value="page" size="tiny" :min="1" :max="totalPages || 1" style="width:80px" @update:value="fetchLogs" />
          <span class="text-muted" style="font-size:12px">/ {{ totalPages || 1 }}</span>
          <n-button size="small" @click="fetchLogs">跳转</n-button>
          <n-button size="small" :disabled="page >= totalPages" @click="page++; fetchLogs()">下一页 ➡</n-button>
        </n-space>
      </n-spin>
    </n-card>

    <!-- LogonTracer link -->
    <n-card size="small" :bordered="false" class="section-card mt-2">
      <n-space align="center">
        <n-button type="primary" size="small" @click="$router.push('/logs/logontracer')">
          登录会话可视化（LogonTracer）
        </n-button>
        <span class="text-muted" style="font-size:13px">进入可视化分析页面，按时间范围构建登录关系图、会话列表与时间线。</span>
      </n-space>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h } from 'vue'
import { NButton, NTag, useMessage } from 'naive-ui'
import { useRouter } from 'vue-router'
import axios from 'axios'

const router = useRouter()
const message = useMessage()
const loading = ref(false)
const collecting = ref(false)
const logs = ref<any[]>([])
const page = ref(1)
const total = ref(0)
const totalPages = ref(1)
const hostName = ref<string | null>(null)
const hostOptions = ref<{ label: string; value: string }[]>([])
const dbServer = ref('')
const flashMsg = ref('')
const flashType = ref<'success' | 'error' | 'info' | 'warning'>('info')

const columns = [
  { title: 'ID', key: 'id', width: 80 },
  { title: '时间', key: 'timestamp', width: 190, ellipsis: { tooltip: true } },
  { title: '主机', key: 'hostname', width: 200, ellipsis: { tooltip: true } },
  {
    title: '级别', key: 'level', width: 110,
    render: (row: any) => h(NTag, {
      type: row.level === 'ERROR' ? 'error' : (row.level === 'WARNING' ? 'warning' : 'info'),
      size: 'tiny'
    }, { default: () => row.level }),
  },
  { title: '事件ID', key: 'event_id', width: 110 },
  { title: '消息', key: 'message', ellipsis: { tooltip: true } },
  {
    title: '操作', key: 'actions', width: 90,
    render: (row: any) => h(NButton, { size: 'tiny', onClick: () => router.push(`/logs/${row.id}`) }, { default: () => '详情' }),
  },
]

async function fetchLogs() {
  loading.value = true
  try {
    const params: any = { page: page.value, format: 'json' }
    if (hostName.value) params.host_name = hostName.value
    const res = await axios.get('/logs/', { params })
    if (res.data?.ok) {
      logs.value = res.data.items || []
      total.value = res.data.total || 0
      totalPages.value = res.data.total_pages || 1
      hostOptions.value = (res.data.host_names || []).map((n: string) => ({ label: n, value: n }))
      dbServer.value = res.data.db_server || dbServer.value
    }
  } catch {
    logs.value = []
  }
  finally { loading.value = false }
}

async function collectLogs() {
  collecting.value = true
  flashMsg.value = ''
  try {
    const params: any = {}
    if (hostName.value) params.host_name = hostName.value
    const res = await axios.post('/logs/collect', null, { params })
    // Parse HTML response for flash messages
    flashMsg.value = '采集完成！刷新列表中...'
    flashType.value = 'success'
    await fetchLogs()
  } catch (e: any) {
    const msg = e?.response?.data || e?.message || ''
    if (typeof msg === 'string' && msg.includes('拒绝访问')) {
      flashMsg.value = '采集失败：需要管理员权限读取 Windows 安全日志。请以管理员身份运行 app_launcher.py。'
    } else {
      flashMsg.value = '采集失败：' + (msg || '未知错误')
    }
    flashType.value = 'error'
  }
  finally { collecting.value = false }
}

async function setDb() {
  try {
    await axios.post('/logs/db', `db_server=${encodeURIComponent(dbServer.value)}`)
    message.success('DB Server 设置成功')
    fetchLogs()
  } catch { message.error('设置失败') }
}

onMounted(() => fetchLogs())
</script>

<style scoped>
.logs-wrap { max-width: 1200px; margin: 0 auto; }
.logs-wrap h2 { margin: 0 0 4px 0; }
.text-muted { color: #6b7280; font-size: 13px; }
.toolbar-card { border-radius: 14px; margin-bottom: 16px; }
.section-card { border-radius: 14px; }
.mt-2 { margin-top: 12px; }
</style>
