import client from './client'

export function getBehaviorRecent(params?: { page?: number; page_size?: number; host_name?: string }) {
  return client.get('/behavior/recent', { params })
}

export function getProcessTree(params?: { limit?: number; host_name?: string }) {
  return client.get('/behavior/process_tree', { params })
}

export function getFileTimeline(params?: { limit?: number; host_name?: string }) {
  return client.get('/behavior/file_timeline', { params })
}

export function getBehaviorHostNames() {
  return client.get('/behavior/host_names')
}

export function getBehaviorStatus() {
  return client.get('/behavior/status')
}
