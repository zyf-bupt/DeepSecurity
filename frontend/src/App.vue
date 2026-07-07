<template>
  <n-config-provider :theme-overrides="themeOverrides" :locale="zhCN" :date-locale="dateZhCN">
    <n-notification-provider>
      <n-message-provider>
        <n-layout has-sider class="app-layout">
          <!-- ====== Sidebar ====== -->
          <n-layout-sider
            bordered
            :collapsed="appStore.sidebarCollapsed"
            collapse-mode="width"
            :collapsed-width="64"
            :width="240"
            class="app-sider"
          >
            <div class="sidebar-brand" :class="{ collapsed: appStore.sidebarCollapsed }">
              <span class="sidebar-logo">🛡</span>
              <span v-if="!appStore.sidebarCollapsed" class="sidebar-title">SecTrace</span>
              <span v-if="!appStore.sidebarCollapsed" class="sidebar-sub">LLM-Powered Detection</span>
            </div>

            <n-menu
              :value="activeMenu"
              :collapsed="appStore.sidebarCollapsed"
              :collapsed-width="64"
              :collapsed-icon-size="22"
              :options="menuOptions"
              :root-indent="20"
              :indent="12"
              @update:value="onMenuSelect"
            />

            <div v-if="!appStore.sidebarCollapsed" class="sidebar-footer">
              <small>SecTrace v2.0 &copy; 2026</small>
            </div>
          </n-layout-sider>

          <!-- ====== Main Area ====== -->
          <n-layout>
            <!-- Top Bar -->
            <n-layout-header bordered class="app-header">
              <div class="header-left">
                <n-button
                  quaternary
                  size="large"
                  @click="appStore.toggleSidebar()"
                >
                  <template #icon>
                    <n-icon size="20"><menu-outline /></n-icon>
                  </template>
                </n-button>
                <span class="header-title">{{ pageTitle }}</span>
              </div>
              <div class="header-right">
                <n-tag
                  :type="appStore.systemStatus === 'running' ? 'error' : 'success'"
                  size="small"
                  round
                >
                  <template #icon>
                    <n-icon><ellipse-icon /></n-icon>
                  </template>
                  {{ appStore.systemStatus === 'running' ? '攻击场景运行中' : '系统就绪' }}
                </n-tag>
              </div>
            </n-layout-header>

            <!-- Content Area -->
            <n-layout-content class="app-content">
              <router-view />
            </n-layout-content>
          </n-layout>
        </n-layout>
      </n-message-provider>
    </n-notification-provider>
  </n-config-provider>
</template>

<script setup lang="ts">
import { computed, h, onMounted, onUnmounted, type Component } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { NIcon } from 'naive-ui'
import { zhCN, dateZhCN } from 'naive-ui'
import { useAppStore } from '@/stores/app'
import {
  HomeOutline,
  GridOutline,
  FlaskOutline,
  SearchOutline,
  ShieldCheckmarkOutline,
  CodeSlashOutline,
  GitNetworkOutline,
  DocumentTextOutline,
  PulseOutline,
  CloudOutline,
  HardwareChipOutline,
} from '@vicons/ionicons5'
import { MenuOutline, Ellipse } from '@vicons/ionicons5'

const EllipseIcon = Ellipse

const router = useRouter()
const route = useRoute()
const appStore = useAppStore()

// ---- Menu Options ----
function renderIcon(icon: Component) {
  return () => h(NIcon, null, { default: () => h(icon) })
}

const menuOptions = [
  { label: '系统首页', key: 'home', icon: renderIcon(HomeOutline) },
  { label: '仪表盘', key: 'dashboard', icon: renderIcon(GridOutline) },
  { type: 'divider' as const, key: 'd1' },
  { label: '—— 核心功能 ——', key: 's1', type: 'group' as const },
  { label: '场景管理', key: 'scenario', icon: renderIcon(FlaskOutline) },
  { label: '攻击检测', key: 'detection', icon: renderIcon(SearchOutline) },
  { label: '溯源归因', key: 'attribution', icon: renderIcon(ShieldCheckmarkOutline) },
  { type: 'divider' as const, key: 'd2' },
  { label: '—— 数据分析 ——', key: 's2', type: 'group' as const },
  { label: '攻击链分析', key: 'attack', icon: renderIcon(CodeSlashOutline) },
  { label: '溯源分析', key: 'traceback', icon: renderIcon(GitNetworkOutline) },
  { label: '日志分析', key: 'logs', icon: renderIcon(DocumentTextOutline) },
  { label: '行为监控', key: 'behavior', icon: renderIcon(PulseOutline) },
  { label: '流量分析', key: 'traffic', icon: renderIcon(CloudOutline) },
  { label: '网络拓扑', key: 'network-topology', icon: renderIcon(HardwareChipOutline) },
]

// ---- Active menu based on current route ----
const activeMenu = computed(() => {
  const path = route.path
  if (path === '/') return 'home'
  if (path.startsWith('/dashboard')) return 'dashboard'
  if (path.startsWith('/scenario/network')) return 'network-topology'
  if (path.startsWith('/scenario')) return 'scenario'
  if (path.startsWith('/detection')) return 'detection'
  if (path.startsWith('/attribution')) return 'attribution'
  if (path.startsWith('/attack')) return 'attack'
  if (path.startsWith('/traceback')) return 'traceback'
  if (path.startsWith('/logs/logontracer')) return 'logs'
  if (path.startsWith('/logs')) return 'logs'
  if (path.startsWith('/behavior')) return 'behavior'
  if (path.startsWith('/traffic')) return 'traffic'
  return 'home'
})

// ---- Page title from route meta or default ----
const pageTitle = computed(() => {
  const map: Record<string, string> = {
    home: 'SecTrace 安全分析平台',
    dashboard: '仪表盘',
    scenario: '场景管理',
    'network-topology': '网络拓扑',
    detection: '攻击检测',
    attribution: '溯源归因',
    attack: '攻击链分析',
    traceback: '溯源分析',
    logs: '日志分析',
    logontracer: '登录追踪',
    behavior: '行为监控',
    traffic: '流量分析',
  }
  return map[activeMenu.value] || 'SecTrace 安全分析平台'
})

function onMenuSelect(key: string) {
  const routeMap: Record<string, string> = {
    home: '/',
    dashboard: '/dashboard',
    scenario: '/scenario',
    'network-topology': '/scenario/network',
    detection: '/detection',
    attribution: '/attribution',
    attack: '/attack',
    traceback: '/traceback',
    logs: '/logs',
    behavior: '/behavior',
    traffic: '/traffic',
  }
  const path = routeMap[key]
  if (path) {
    router.push(path)
  }
}

// ---- Theme overrides for a clean light look ----
const themeOverrides = {
  common: {
    primaryColor: '#3b6df0',
    primaryColorHover: '#2563eb',
    borderRadius: '8px',
  },
  Layout: {
    siderBorderColor: '#e5e7eb',
  },
}

// ---- Poll system status ----
let statusTimer: ReturnType<typeof setInterval> | null = null

onMounted(() => {
  statusTimer = setInterval(async () => {
    try {
      const { getAllStatus } = await import('@/api/scenario')
      const res = await getAllStatus()
      if (res.data?.ok) {
        const scenarios = res.data.scenarios?.scenarios || {}
        const running = Object.values(scenarios).some((s: any) => s.running)
        appStore.setSystemStatus(running ? 'running' : 'ready')
      }
    } catch {
      // ignore poll errors
    }
  }, 5000)
})

onUnmounted(() => {
  if (statusTimer) clearInterval(statusTimer)
})
</script>

<style>
/* ====== Global Reset ====== */
*,
*::before,
*::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html, body, #app {
  height: 100%;
  font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
  font-size: 14px;
  background: #f0f4f8;
  color: #2c3e50;
}

a {
  color: #3b6df0;
  text-decoration: none;
}
a:hover {
  color: #2050d0;
}

code, pre {
  font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
}

/* ====== App Layout ====== */
.app-layout {
  height: 100vh;
}

/* ====== Sidebar ====== */
.app-sider {
  position: sticky !important;
  top: 0;
  height: 100vh;
}

.sidebar-brand {
  padding: 22px 18px 14px;
  text-align: center;
  border-bottom: 1px solid #e5e7eb;
}
.sidebar-brand.collapsed {
  padding: 14px 8px;
}

.sidebar-logo {
  font-size: 32px;
  display: block;
  margin-bottom: 4px;
}
.sidebar-brand.collapsed .sidebar-logo {
  font-size: 24px;
  margin-bottom: 0;
}

.sidebar-title {
  font-size: 20px;
  font-weight: 800;
  color: #3b6df0;
  letter-spacing: 0.5px;
  display: block;
}

.sidebar-sub {
  font-size: 11px;
  color: #7f8fa4;
  margin-top: 2px;
  display: block;
}

.sidebar-footer {
  padding: 14px;
  border-top: 1px solid #e5e7eb;
  font-size: 11px;
  color: #7f8fa4;
  text-align: center;
}

/* ====== Header ====== */
.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 24px;
  height: 56px;
  position: sticky;
  top: 0;
  z-index: 50;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.header-title {
  font-size: 16px;
  font-weight: 700;
  color: #1a2530;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

/* ====== Content ====== */
.app-content {
  padding: 24px 28px;
  min-height: calc(100vh - 56px);
  background: #f0f4f8;
}

/* ====== Scrollbar ====== */
::-webkit-scrollbar {
  width: 5px;
  height: 5px;
}
::-webkit-scrollbar-track {
  background: #f0f4f8;
}
::-webkit-scrollbar-thumb {
  background: #d0d6e0;
  border-radius: 3px;
}
::-webkit-scrollbar-thumb:hover {
  background: #b0b8c4;
}
</style>
