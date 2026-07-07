<template>
  <div class="detail-wrap">
    <n-button size="small" @click="$router.push('/traffic')" class="mb-3">← 返回流量列表</n-button>
    <n-spin :show="loading">
      <n-card title="流量详情" :bordered="false" class="section-card">
        <n-descriptions v-if="traffic" :column="2" bordered size="small">
          <n-descriptions-item label="ID">{{ traffic.id }}</n-descriptions-item>
          <n-descriptions-item label="时间">{{ traffic.timestamp }}</n-descriptions-item>
          <n-descriptions-item label="源 IP">{{ traffic.src_ip }}</n-descriptions-item>
          <n-descriptions-item label="目标 IP">{{ traffic.dst_ip }}</n-descriptions-item>
          <n-descriptions-item label="协议">{{ traffic.protocol }}</n-descriptions-item>
          <n-descriptions-item label="事件类型">
            <n-tag :type="(traffic.event_type || '').includes('suspected') ? 'error' : 'info'" size="tiny">{{ traffic.event_type }}</n-tag>
          </n-descriptions-item>
          <n-descriptions-item label="描述" :span="2">{{ traffic.description }}</n-descriptions-item>
        </n-descriptions>
      </n-card>

      <n-card title="JSON 解析" :bordered="false" class="section-card mt-3">
        <n-code :code="traffic?.result_json_pretty || ''" language="json" word-wrap />
      </n-card>

      <n-card title="原始数据" :bordered="false" class="section-card mt-3">
        <pre class="detail-pre">{{ traffic?.raw_content || '无' }}</pre>
      </n-card>
    </n-spin>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { getTrafficDetail } from '@/api/traffic'

const route = useRoute()
const loading = ref(true)
const traffic = ref<any>(null)

onMounted(async () => {
  try {
    const id = Number(route.params.id)
    const res = await getTrafficDetail(id)
    if (res.data?.ok) {
      const row = res.data.row
      traffic.value = {
        id: row.id,
        timestamp: row.result?.timestamp || '',
        src_ip: row.result?.src_ip || '',
        dst_ip: row.result?.dst_ip || '',
        protocol: row.result?.protocol || '',
        event_type: row.result?.event_type || '',
        description: row.result?.description || '',
        raw_content: row.content || '',
        result_json_pretty: JSON.stringify(row.result, null, 2),
      }
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
