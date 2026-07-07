<template>
  <div class="dash-wrap">
    <div class="dash-top">
      <div>
        <h2>系统仪表盘</h2>
        <p class="text-muted">
          展示 SQL Server 入库情况与最近溯源报告（AttackReports）。<br/>
          快速入口：建议演示顺序 <b>仪表盘 → 攻击链 → 溯源分析</b>
        </p>
      </div>
      <n-space>
        <n-button type="primary" @click="$router.push('/traceback')">进入溯源分析</n-button>
        <n-button @click="$router.push('/attack')">攻击链</n-button>
        <n-button @click="$router.push('/logs')">日志分析</n-button>
      </n-space>
    </div>

    <n-spin :show="loading">
      <!-- KPI Cards -->
      <n-grid :cols="4" :x-gap="12" :y-gap="12" responsive="screen" class="mb-3">
        <n-grid-item>
          <n-card size="small" class="kpi-card">
            <n-statistic label="HostLogs 主机日志" :value="stats.log_count">
              <template #prefix><n-tag size="tiny">主机日志</n-tag></template>
            </n-statistic>
            <div class="text-muted small">最新入库：{{ freshness.HostLogs || '-' }}</div>
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card size="small" class="kpi-card">
            <n-statistic label="HostBehaviors 主机行为" :value="stats.process_count">
              <template #prefix><n-tag size="tiny">主机行为</n-tag></template>
            </n-statistic>
            <div class="text-muted small">最新入库：{{ freshness.HostBehaviors || '-' }}</div>
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card size="small" class="kpi-card">
            <n-statistic label="NetworkTraffic 网络流量" :value="stats.flow_count">
              <template #prefix><n-tag size="tiny">网络流量</n-tag></template>
            </n-statistic>
            <div class="text-muted small">最新入库：{{ freshness.NetworkTraffic || '-' }}</div>
          </n-card>
        </n-grid-item>
        <n-grid-item>
          <n-card size="small" class="kpi-card">
            <n-statistic label="AttackReports 溯源报告" :value="stats.attack_count">
              <template #prefix><n-tag size="tiny">溯源报告</n-tag></template>
            </n-statistic>
            <div class="text-muted small">最新生成：{{ freshness.AttackReports || '-' }}</div>
          </n-card>
        </n-grid-item>
      </n-grid>

      <!-- Recent Reports Table -->
      <n-card title="最近溯源报告（AttackReports）" :bordered="false" class="section-card">
        <template #header-extra>
          <span class="text-muted small">来源：dbo.AttackReports.report_json</span>
        </template>
        <n-empty v-if="reports.length === 0" description="暂无 AttackReports 数据" />
        <n-data-table
          v-else
          :columns="columns"
          :data="reports"
          :bordered="false"
          :single-line="false"
          size="small"
        />
      </n-card>
    </n-spin>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, h } from 'vue'
import { NButton, NTag } from 'naive-ui'
import { useRouter } from 'vue-router'
import { getDashboardOverview } from '@/api/dashboard'

const router = useRouter()
const loading = ref(true)
const stats = ref({ log_count: 0, process_count: 0, flow_count: 0, attack_count: 0 })
const freshness = ref<Record<string, string>>({})
const reports = ref<any[]>([])

const columns = [
  { title: 'created_at', key: 'created_at', width: 160 },
  { title: 'scenario_id', key: 'scenario_id', width: 120, render: (row: any) => h('code', {}, row.scenario_id) },
  { title: 'victim_ip', key: 'victim_ip', width: 140 },
  { title: 'attacker_ip', key: 'attacker_ip', width: 140 },
  { title: 'confidence', key: 'confidence', width: 90 },
  {
    title: '摘要', key: 'summary',
    render: (row: any) => h('div', [
      h('b', {}, row.attribution_name || ''),
      h('div', { class: 'text-muted small' }, row.trigger_technique || ''),
    ]),
  },
  {
    title: '操作', key: 'actions', width: 90,
    render: () => h(NButton, { size: 'tiny', onClick: () => router.push('/traceback') }, { default: () => '查看' }),
  },
]

onMounted(async () => {
  try {
    const res = await getDashboardOverview()
    if (res.data?.ok) {
      stats.value = res.data.stats
      freshness.value = res.data.freshness
      reports.value = res.data.recent_reports || []
    }
  } catch (e) {
    console.error('Dashboard load failed', e)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.dash-wrap { max-width: 1200px; margin: 0 auto; }
.dash-top { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; flex-wrap: wrap; margin-bottom: 16px; }
.dash-top h2 { margin: 0 0 6px 0; font-size: 20px; }
.text-muted { color: #6b7280; font-size: 13px; }
.small { font-size: 12px; }
.mb-3 { margin-bottom: 16px; }
.kpi-card { border-radius: 14px; }
.section-card { border-radius: 14px; margin-bottom: 16px; }
</style>
