import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useAppStore = defineStore('app', () => {
  const sidebarCollapsed = ref(false)
  const systemStatus = ref<'ready' | 'running'>('ready')

  function toggleSidebar() {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }

  function setSystemStatus(status: 'ready' | 'running') {
    systemStatus.value = status
  }

  return { sidebarCollapsed, systemStatus, toggleSidebar, setSystemStatus }
})
