<template>
  <div class="sc-wrap">
    <h2 class="page-title">&#9878; 攻击场景生成与管理 <small>2个分析场景 · 真实数据生成 · 全管线联动</small></h2>

    <n-grid :cols="3" :x-gap="16" :y-gap="16" responsive="screen" class="mb-3">
      <!-- Scenario 1: APT -->
      <n-grid-item>
        <n-card :bordered="false" class="sc-card" style="border-top: 4px solid #e74c3c">
          <template #header>
            <div class="sc-header">
              <span>🔴 场景一：APT全链条攻击</span>
              <n-tag :type="aptBadgeType" size="small">{{ aptStatus }}</n-tag>
            </div>
          </template>
          <p class="sc-desc">模拟 Lazarus Group 风格 APT 攻击，覆盖完整杀伤链的 8 个阶段</p>
          <n-space class="mb-2">
            <n-tag type="error" size="tiny">T1190 公网利用</n-tag>
            <n-tag type="warning" size="tiny">T1105 工具下载</n-tag>
            <n-tag type="info" size="tiny">T1059 命令执行</n-tag>
            <n-tag type="info" size="tiny">T1547 持久化</n-tag>
            <n-tag type="error" size="tiny">T1003 凭据窃取</n-tag>
            <n-tag type="error" size="tiny">T1021 横向移动</n-tag>
            <n-tag type="warning" size="tiny">T1071 DNS隧道</n-tag>
            <n-tag type="warning" size="tiny">T1048 数据外传</n-tag>
          </n-space>
          <div class="sc-path">
            <strong>攻击路径:</strong> 外部C2(45.33.22.11) → DMZ Web(192.168.86.10) → 跳板机(192.168.86.132) → Linux核心(192.168.86.130) → Windows域控(192.168.86.131) → C2外传
          </div>
          <template #footer>
            <n-progress type="line" :percentage="aptProgress" :color="aptProgress === 100 ? '#2ecc71' : '#e74c3c'" />
            <div class="sc-actions">
              <n-button type="error" size="small" @click="startScenario('apt_full_chain')" :loading="aptStarting">▶ 启动</n-button>
              <n-button type="warning" size="small" @click="stopScenario('apt_full_chain')">■ 停止</n-button>
              <small class="text-muted sc-stage">{{ aptStage }}</small>
            </div>
          </template>
        </n-card>
      </n-grid-item>

      <!-- Scenario 2: AI -->
      <n-grid-item>
        <n-card :bordered="false" class="sc-card" style="border-top: 4px solid #7c5cfc">
          <template #header>
            <div class="sc-header">
              <span>🔵 场景二：AI智能体滥用攻击</span>
              <n-tag :type="aiBadgeType" size="small">{{ aiStatus }}</n-tag>
            </div>
          </template>
          <p class="sc-desc">模拟利用 Claude Code / OpenCode 等 LLM Agent 发起的自动化攻击</p>
          <n-space class="mb-2">
            <n-tag type="info" size="tiny">AI自主侦察</n-tag>
            <n-tag type="info" size="tiny">LLM代码生成</n-tag>
            <n-tag type="info" size="tiny">工具链滥用</n-tag>
            <n-tag type="error" size="tiny">AI供应链</n-tag>
            <n-tag type="warning" size="tiny">模型污染</n-tag>
          </n-space>
          <div class="sc-path">
            <strong>攻击特征:</strong> LLM Agent在开发者工作站启动 → AI自主发现内网资产 → LLM生成攻击载荷(带注释+试错) → 多路径横向探索 → 通过AI基础设施外传
          </div>
          <template #footer>
            <n-progress type="line" :percentage="aiProgress" :color="aiProgress === 100 ? '#2ecc71' : '#7c5cfc'" />
            <div class="sc-actions">
              <n-button type="info" size="small" @click="startScenario('ai_agent_abuse')" :loading="aiStarting">▶ 启动</n-button>
              <n-button type="warning" size="small" @click="stopScenario('ai_agent_abuse')">■ 停止</n-button>
              <small class="text-muted sc-stage">{{ aiStage }}</small>
            </div>
          </template>
        </n-card>
      </n-grid-item>
      <!-- Scenario 3: Ransomware -->
      <n-grid-item>
        <n-card :bordered="false" class="sc-card" style="border-top: 4px solid #e67e22">
          <template #header>
            <div class="sc-header">
              <span>🟠 场景三：勒索软件攻击</span>
              <n-tag :type="rwBadgeType" size="small">{{ rwStatus }}</n-tag>
            </div>
          </template>
          <p class="sc-desc">模拟 Conti/LockBit 风格勒索软件攻击：钓鱼入口→凭证窃取→横向移动→数据外传→勒索部署</p>
          <n-space class="mb-2">
            <n-tag type="error" size="tiny">T1566.001 钓鱼宏</n-tag>
            <n-tag type="warning" size="tiny">T1003.001 LSASS转储</n-tag>
            <n-tag type="error" size="tiny">T1021.002 SMB横向</n-tag>
            <n-tag type="warning" size="tiny">T1041 数据外传</n-tag>
            <n-tag type="error" size="tiny">T1486 勒索加密</n-tag>
          </n-space>
          <div class="sc-path">
            <strong>攻击路径:</strong> 钓鱼邮件(203.0.113.51) → 端点(172.16.50.100) → C2(203.0.113.50) → 文件服务器(172.16.50.10) → 域控(172.16.50.1) → 勒索部署
          </div>
          <template #footer>
            <n-progress type="line" :percentage="rwProgress" :color="rwProgress === 100 ? '#2ecc71' : '#e67e22'" />
            <div class="sc-actions">
              <n-button type="warning" size="small" @click="startScenario('ransomware')" :loading="rwStarting">▶ 启动</n-button>
              <n-button size="small" @click="stopScenario('ransomware')" style="border-color:#e67e22;color:#e67e22">■ 停止</n-button>
              <small class="text-muted sc-stage">{{ rwStage }}</small>
            </div>
          </template>
        </n-card>
      </n-grid-item>
    </n-grid>

    <!-- Events Stream -->
    <n-card :bordered="false" class="section-card">
      <template #header>
        <div class="section-header">
          <span>📊 实时事件流 (Real-time Event Stream)</span>
          <n-space>
            <n-button size="small" @click="clearAll">🗑 清除全部</n-button>
            <n-button size="small" @click="pollEvents">🔄 刷新</n-button>
          </n-space>
        </div>
      </template>
      <n-data-table
        :columns="eventColumns"
        :data="events"
        :bordered="false"
        size="small"
        :scroll-x="800"
        max-height="380"
      />
      <n-empty v-if="events.length === 0" description="等待场景生成事件..." style="padding: 40px" />
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, h } from 'vue'
import { NTag, useMessage } from 'naive-ui'
import { startScenario as apiStart, stopScenario as apiStop, getAllStatus, getEvents, clearAllData } from '@/api/scenario'

const message = useMessage()

const aptProgress = ref(0)
const aiProgress = ref(0)
const aptStatus = ref('就绪')
const aiStatus = ref('就绪')
const aptStage = ref('')
const aiStage = ref('')
const aptStarting = ref(false)
const aiStarting = ref(false)
const rwProgress = ref(0)
const rwStatus = ref('就绪')
const rwStage = ref('')
const rwStarting = ref(false)
const rwBadgeType = computed(() => rwStatus.value === '运行中' ? 'warning' as const : 'default' as const)
const events = ref<any[]>([])

const aptBadgeType = computed(() => aptStatus.value === '运行中' ? 'error' as const : 'default' as const)
const aiBadgeType = computed(() => aiStatus.value === '运行中' ? 'info' as const : 'default' as const)

const eventColumns = [
  { title: '时间', key: 'display_time', width: 100, render: (row: any) => h('code', {}, (row.timestamp || '').substring(11, 19)) },
  { title: '数据源', key: 'data_source', width: 100, render: (row: any) => h(NTag, { size: 'tiny' }, { default: () => row.data_source || '' }) },
  { title: '事件类型', key: 'event_type', width: 140 },
  { title: '主机', key: 'host_ip', width: 140, render: (row: any) => h('code', {}, row.host_ip || '') },
  { title: '进程/详情', key: 'detail', ellipsis: { tooltip: true },
    render: (row: any) => (row.entities?.process_name || row.entities?.command_line || '').substring(0, 65) },
]

let pollTimer: ReturnType<typeof setInterval> | null = null

function pollStatus() {
  getAllStatus().then(res => {
    if (!res.data?.ok) return
    const sc = res.data.scenarios?.scenarios || {}
    updateUI(sc)
  }).catch(() => {})
}

function pollEvents() {
  getEvents(30).then(res => {
    if (res.data?.data) {
      events.value = [...res.data.data].reverse().slice(0, 30)
    }
  }).catch(() => {})
}

function updateUI(sc: Record<string, any>) {
  for (const [id, data] of Object.entries(sc)) {
    const s = data as any
    if (id === 'apt_full_chain') {
      aptProgress.value = s.progress || 0
      aptStatus.value = s.running ? '运行中' : (s.progress === 100 ? '已完成' : '就绪')
      aptStage.value = s.current_stage || ''
    }
    if (id === 'ai_agent_abuse') {
      aiProgress.value = s.progress || 0
      aiStatus.value = s.running ? '运行中' : (s.progress === 100 ? '已完成' : '就绪')
      aiStage.value = s.current_stage || ''
    }
    if (id === 'ransomware') {
      rwProgress.value = s.progress || 0
      rwStatus.value = s.running ? '运行中' : (s.progress === 100 ? '已完成' : '就绪')
      rwStage.value = s.current_stage || ''
    }
  }
}

async function startScenario(id: string) {
  if (id === 'apt_full_chain') aptStarting.value = true
  else aiStarting.value = true
  try {
    const res = await apiStart(id)
    message[res.data?.ok ? 'success' : 'error'](res.data?.message || 'OK')
    startPolling()
  } catch {
    message.error('启动失败')
  } finally {
    aptStarting.value = false
    aiStarting.value = false
  }
}

async function stopScenario(id: string) {
  try {
    const res = await apiStop(id)
    message[res.data?.ok ? 'success' : 'error'](res.data?.message || 'OK')
  } catch {
    message.error('停止失败')
  }
}

async function clearAll() {
  try {
    await clearAllData()
    message.info('已清除所有事件和告警')
    pollEvents()
  } catch { message.error('清除失败') }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer)
  pollTimer = setInterval(() => { pollStatus(); pollEvents() }, 2000)
}

onMounted(() => {
  pollStatus()
  pollEvents()
  startPolling()
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})

import { computed } from 'vue'
</script>

<style scoped>
.sc-wrap { max-width: 1200px; margin: 0 auto; }
.page-title { font-size: 20px; margin-bottom: 16px; }
.page-title small { font-size: 13px; color: #6b7280; font-weight: 400; }
.sc-card { border-radius: 14px; }
.sc-header { display: flex; align-items: center; justify-content: space-between; }
.sc-desc { color: #6b7280; font-size: 13px; margin-bottom: 10px; }
.sc-path { font-size: 12px; color: #6b7280; line-height: 1.8; }
.sc-actions { display: flex; gap: 8px; align-items: center; margin-top: 10px; }
.sc-stage { flex: 1; }
.text-muted { color: #6b7280; }
.mb-2 { margin-bottom: 10px; }
.mb-3 { margin-bottom: 16px; }
.section-card { border-radius: 14px; }
.section-header { display: flex; align-items: center; justify-content: space-between; width: 100%; }
</style>
