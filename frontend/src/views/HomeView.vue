<template>
  <div class="home-wrap">
    <!-- Hero -->
    <n-card class="hero-card" :bordered="false">
      <div class="hero">
        <h1>恶意攻击行为溯源分析系统</h1>
        <p>
          本系统面向内网真实攻防场景，融合 <b>主机日志</b>、<b>主机行为</b> 与 <b>网络流量</b> 等多源数据，
          通过时间对齐与关联分析，重建攻击链路并输出可解释的溯源结果（路径、关键证据、C2 线索与归因建议）。
        </p>
        <n-space class="hero-actions">
          <n-button type="primary" size="large" @click="$router.push('/dashboard')">进入仪表盘</n-button>
          <n-button type="info" size="large" @click="$router.push('/traceback')">溯源分析</n-button>
          <n-button size="large" @click="$router.push('/attack')">攻击链</n-button>
          <n-button size="large" @click="$router.push('/logs')">日志分析</n-button>
        </n-space>
        <n-space class="pill-row">
          <n-tag>ATT&CK 映射</n-tag>
          <n-tag>多源时间线关联</n-tag>
          <n-tag>实体关系图（Neo4j）</n-tag>
          <n-tag>路径重建</n-tag>
          <n-tag>C2 / IOC 线索</n-tag>
          <n-tag>APT 相似性匹配</n-tag>
        </n-space>
      </div>
    </n-card>

    <!-- Quick Links -->
    <n-card title="快速入口" class="section-card" :bordered="false">
      <n-grid :cols="6" :x-gap="12" :y-gap="12" responsive="screen">
        <n-grid-item v-for="link in quickLinks" :key="link.key">
          <n-card hoverable size="small" @click="$router.push(link.path)" class="quick-card">
            <div class="quick-label">{{ link.label }}</div>
            <div class="quick-desc">{{ link.desc }}</div>
          </n-card>
        </n-grid-item>
      </n-grid>
    </n-card>

    <!-- System Modules -->
    <n-card title="系统模块" class="section-card" :bordered="false">
      <n-grid :cols="3" :x-gap="16" :y-gap="16" responsive="screen">
        <n-grid-item v-for="mod in modules" :key="mod.key">
          <n-card size="small" :bordered="false" class="module-card">
            <template #header>
              <div class="module-title">
                {{ mod.title }}
                <n-tag size="small" :bordered="false">{{ mod.badge }}</n-tag>
              </div>
            </template>
            <p class="module-desc">{{ mod.desc }}</p>
            <n-space>
              <n-tag size="tiny" v-for="chip in mod.chips" :key="chip">{{ chip }}</n-tag>
            </n-space>
          </n-card>
        </n-grid-item>
      </n-grid>
    </n-card>

    <!-- Analysis Flow -->
    <n-card title="分析流程（可解释溯源）" class="section-card" :bordered="false">
      <template #header-extra>
        <span class="text-dim">每一步都能回溯到证据</span>
      </template>
      <n-grid :cols="4" :x-gap="12" :y-gap="12" responsive="screen">
        <n-grid-item v-for="step in steps" :key="step.num">
          <n-card size="small" class="step-card">
            <div class="step-num">{{ step.num }}</div>
            <div class="step-title">{{ step.title }}</div>
            <div class="step-desc">{{ step.desc }}</div>
          </n-card>
        </n-grid-item>
      </n-grid>
      <n-alert type="info" class="mt-3">
        提示：本首页保持"静态展示"，不会读取数据库；真正的动态数据请到「仪表盘」查看。
      </n-alert>
    </n-card>
  </div>
</template>

<script setup lang="ts">
const quickLinks = [
  { key: 'dashboard', label: '仪表盘', desc: '全局统计 / 最近报告', path: '/dashboard' },
  { key: 'logs', label: '日志分析', desc: 'HostLogs 入库与详情', path: '/logs' },
  { key: 'behavior', label: '行为分析', desc: 'HostBehaviors 展示', path: '/behavior' },
  { key: 'traffic', label: '流量分析', desc: 'NetworkTraffic 展示', path: '/traffic' },
  { key: 'attack', label: '攻击链', desc: 'ATT&CK + 图谱联动', path: '/attack' },
  { key: 'traceback', label: '溯源分析', desc: '路径 / IOC / AI 报告', path: '/traceback' },
]

const modules = [
  {
    key: 'hostlogs', title: '主机日志（HostLogs）', badge: 'SQL Server',
    desc: '归一化 Windows Event Log / 安全日志，提取用户、源 IP、会话等实体，为暴力破解、身份溯源提供证据基础。',
    chips: ['范式解析', '实体抽取', '会话重建'],
  },
  {
    key: 'hostbehaviors', title: '主机行为（HostBehaviors）', badge: 'Agent 上报',
    desc: '聚焦进程树与文件/注册表/网络行为链，支撑"执行→持久化→提权"的可解释路径还原。',
    chips: ['进程树', '敏感文件', '注入检测'],
  },
  {
    key: 'traffic', title: '网络流量（NetworkTraffic）', badge: 'Traffic',
    desc: '识别异常协议行为、DNS/ICMP 隧道与外传线索，为 C2/归因提供基础设施证据。',
    chips: ['会话重建', '隧道检测', 'IOC 关联'],
  },
]

const steps = [
  { num: 1, title: '采集与入库', desc: '多源数据进入 SQL Server：HostLogs / HostBehaviors / NetworkTraffic。' },
  { num: 2, title: '规则检测', desc: 'ATT&CK 规则映射触发 AttackEvent，并将证据实体写入 Neo4j。' },
  { num: 3, title: '关联与构图', desc: '构建实体拓扑与阶段因果链（NEXT_STAGE），形成攻击路径。' },
  { num: 4, title: '溯源输出', desc: '生成 AttackReports（SQL）：路径 + IOC + 归因结果，并支持 AI 研判报告。' },
]
</script>

<style scoped>
.home-wrap {
  max-width: 1200px;
  margin: 0 auto;
}

.hero-card {
  border-radius: 16px;
  margin-bottom: 16px;
  position: relative;
  overflow: hidden;
}

.hero h1 {
  margin: 0 0 10px 0;
  font-size: 26px;
  color: #111827;
}

.hero p {
  color: #6b7280;
  font-size: 13px;
  line-height: 1.8;
  max-width: 980px;
}

.hero-actions {
  margin-top: 16px;
}

.pill-row {
  margin-top: 14px;
}

.section-card {
  border-radius: 16px;
  margin-bottom: 16px;
}

.quick-card {
  cursor: pointer;
  border-radius: 14px;
}
.quick-label {
  font-weight: 800;
  font-size: 14px;
  margin-bottom: 4px;
}
.quick-desc {
  color: #6b7280;
  font-size: 12px;
}

.module-card {
  background: linear-gradient(180deg, #fff 0%, #fbfbfb 100%);
  border-radius: 14px;
}
.module-title {
  font-weight: 900;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.module-desc {
  color: #374151;
  font-size: 13px;
  line-height: 1.7;
  margin-bottom: 10px;
}

.step-card {
  border-radius: 14px;
  position: relative;
  overflow: hidden;
}
.step-num {
  width: 28px;
  height: 28px;
  border-radius: 10px;
  background: #111827;
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 900;
  font-size: 13px;
  margin-bottom: 8px;
}
.step-title {
  font-weight: 900;
  margin-bottom: 6px;
}
.step-desc {
  color: #374151;
  font-size: 13px;
  line-height: 1.7;
}

.text-dim { color: #6b7280; font-size: 12px; }
.mt-3 { margin-top: 16px; }
</style>
