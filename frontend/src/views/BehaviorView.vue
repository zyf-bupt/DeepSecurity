<template>
  <div class="bm-wrap">
    <div class="bm-header">
      <h2>主机行为分析（客户端 Agent 上报展示）</h2>
      <p class="text-muted">说明：客户端运行 <code>python utils/behavior_monitor/client_agent.py --server http://&lt;server_ip&gt;:5000 --verbose</code> 后，行为数据自动上报入库。</p>
    </div>

    <!-- Toolbar -->
    <n-card size="small" :bordered="false" class="toolbar-card">
      <n-space align="center" wrap>
        <span class="text-muted">主机筛选:</span>
        <n-select v-model:value="hostName" :options="hostOptions" placeholder="全部主机" size="small" clearable style="width: 200px" @update:value="fetchAll" />
        <n-button size="small" @click="fetchAll">🔄 刷新</n-button>
        <n-tag size="small" :type="status === 'connected' ? 'success' : 'default'">{{ status }}</n-tag>
      </n-space>
    </n-card>

    <!-- Data Table -->
    <n-card :bordered="false" class="section-card">
      <n-spin :show="loading">
        <n-data-table :columns="columns" :data="items" :bordered="false" size="small" max-height="350" :scroll-x="1200" />
        <n-pagination v-if="total > pageSize" :page="page" :page-size="pageSize" :item-count="total"
          @update:page="(p: number) => { page = p; fetchAll() }" class="mt-2" />
      </n-spin>
    </n-card>

    <!-- Process Tree + File Timeline -->
    <n-grid :cols="2" :x-gap="16" :y-gap="16" responsive="screen" class="mt-3">
      <n-grid-item>
        <n-card title="进程树 (Process Tree)" :bordered="false" class="section-card" size="small">
          <div class="tree-box">
            <div v-for="n in processNodes" :key="n.id" class="tree-node" :style="{ marginLeft: (n.depth || 0) * 20 + 'px' }">
              {{ n.label }}
            </div>
            <n-empty v-if="!processNodes.length" description="暂无进程树数据" />
          </div>
        </n-card>
      </n-grid-item>
      <n-grid-item>
        <n-card title="文件操作时间线 (File Timeline)" :bordered="false" class="section-card" size="small">
          <n-timeline v-if="fileEvents.length">
            <n-timeline-item v-for="ev in fileEvents" :key="ev.timestamp" :type="ev.event_type === 'file_delete' ? 'error' : 'info'"
              :title="ev.event_type" :time="ev.timestamp">
              {{ ev.process_name }} → {{ ev.file_path }}
            </n-timeline-item>
          </n-timeline>
          <n-empty v-else description="暂无文件操作记录" />
        </n-card>
      </n-grid-item>
    </n-grid>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { getBehaviorRecent, getProcessTree, getFileTimeline, getBehaviorHostNames, getBehaviorStatus } from '@/api/behavior'

const loading = ref(false)
const items = ref<any[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
const hostName = ref<string | null>(null)
const hostOptions = ref<{ label: string; value: string }[]>([])
const status = ref('standby')
const processNodes = ref<any[]>([])
const fileEvents = ref<any[]>([])

const columns = [
  { title: 'ID', key: 'id', width: 70 },
  { title: '时间', key: 'timestamp', width: 180, ellipsis: { tooltip: true } },
  { title: '主机', key: 'host', width: 160 },
  { title: '事件类型', key: 'event_type', width: 160 },
  { title: '操作', key: 'action', width: 110 },
  { title: '进程', key: 'process', width: 180, ellipsis: { tooltip: true } },
  { title: 'PID/PPID', key: 'pid_display', width: 110 },
  { title: '目标', key: 'target', ellipsis: { tooltip: true } },
]

async function fetchAll() {
  loading.value = true
  try {
    const [recentRes, treeRes, timelineRes] = await Promise.all([
      getBehaviorRecent({ page: page.value, page_size: pageSize.value, host_name: hostName.value || undefined }),
      getProcessTree({ limit: 500, host_name: hostName.value || undefined }),
      getFileTimeline({ limit: 500, host_name: hostName.value || undefined }),
    ])
    if (recentRes.data?.ok) {
      items.value = (recentRes.data.items || []).map((it: any) => ({
        ...it,
        pid_display: it.pid ? `${it.pid}${it.ppid ? '/' + it.ppid : ''}` : '-',
      }))
      total.value = recentRes.data.total || 0
    }
    if (treeRes.data?.ok) processNodes.value = treeRes.data.nodes || []
    if (timelineRes.data?.ok) fileEvents.value = timelineRes.data.events || []
  } catch {}
  finally { loading.value = false }
}

onMounted(async () => {
  try {
    const [hostsRes, statusRes] = await Promise.all([getBehaviorHostNames(), getBehaviorStatus()])
    hostOptions.value = (hostsRes.data?.host_names || []).map((n: string) => ({ label: n, value: n }))
    status.value = statusRes.data?.running ? 'connected' : 'standby'
  } catch {}
  fetchAll()
})
</script>

<style scoped>
.bm-wrap { max-width: 1200px; margin: 0 auto; }
.bm-header { margin-bottom: 12px; }
.bm-header h2 { margin: 0 0 4px 0; }
.text-muted { color: #6b7280; font-size: 13px; }
code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
.toolbar-card { border-radius: 14px; margin-bottom: 16px; }
.section-card { border-radius: 14px; }
.mt-2 { margin-top: 12px; }
.mt-3 { margin-top: 16px; }
.tree-box { max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 12px; }
.tree-node { padding: 3px 0; white-space: nowrap; }
</style>
