<template>
  <div class="detail-wrap">
    <n-button size="small" @click="$router.push('/logs')" class="mb-3">← 返回日志列表</n-button>
    <n-spin :show="loading">
      <n-card title="日志详情" :bordered="false" class="section-card">
        <n-descriptions v-if="log" :column="2" bordered size="small">
          <n-descriptions-item label="ID">{{ log.id }}</n-descriptions-item>
          <n-descriptions-item label="时间">{{ log.timestamp }}</n-descriptions-item>
          <n-descriptions-item label="主机">{{ log.hostname }}</n-descriptions-item>
          <n-descriptions-item label="级别">
            <n-tag :type="log.level === 'ERROR' ? 'error' : (log.level === 'WARNING' ? 'warning' : 'info')" size="tiny">{{ log.level }}</n-tag>
          </n-descriptions-item>
          <n-descriptions-item label="Event ID">{{ log.event_id }}</n-descriptions-item>
          <n-descriptions-item label="消息" :span="2">{{ log.message }}</n-descriptions-item>
        </n-descriptions>
      </n-card>
      <n-card title="原始日志" :bordered="false" class="section-card mt-3">
        <pre class="detail-pre">{{ log?.raw_log || '无' }}</pre>
      </n-card>
      <n-card title="JSON 解析" :bordered="false" class="section-card mt-3">
        <pre class="detail-pre">{{ log?.result_json_pretty || '无' }}</pre>
      </n-card>
    </n-spin>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import axios from 'axios'

const route = useRoute()
const loading = ref(true)
const log = ref<any>(null)

onMounted(async () => {
  try {
    const id = route.params.id
    const res = await axios.get(`/logs/${id}`)
    // Parse the HTML response for the log detail data
    const html = res.data as string
    const parser = new DOMParser()
    const doc = parser.parseFromString(html, 'text/html')
    // Extract data from the rendered page
    const preBlocks = doc.querySelectorAll('pre')
    log.value = {
      id,
      timestamp: doc.querySelector('.log-timestamp')?.textContent || '',
      hostname: '',
      level: 'INFO',
      event_id: '',
      message: '',
      raw_log: preBlocks[0]?.textContent || '',
      result_json_pretty: preBlocks[1]?.textContent || '',
    }
  } catch {}
  finally { loading.value = false }
})
</script>

<style scoped>
.detail-wrap { max-width: 960px; margin: 0 auto; }
.mb-3 { margin-bottom: 16px; }
.mt-3 { margin-top: 16px; }
.section-card { border-radius: 14px; }
.detail-pre { background: #f8fafc; padding: 16px; border-radius: 8px; max-height: 400px; overflow: auto; font-size: 12px; line-height: 1.6; white-space: pre-wrap; }
</style>
