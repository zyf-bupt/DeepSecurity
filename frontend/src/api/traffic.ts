import client from './client'

export function getTrafficList(params?: { page?: number; event_type?: string }) {
  return client.get('/traffic/api/list', { params })
}

export function getDumpcapInfo() {
  return client.get('/traffic/api/dumpcap/info')
}

export function getTrafficDetail(id: number) {
  return client.get(`/traffic/api/detail/${id}`)
}

export function getTrafficDetailPage(id: number, eventType?: string) {
  return client.get(`/traffic/detail/${id}`, { params: { event_type: eventType } })
}

export function getLiveStatus() {
  return client.get('/traffic/api/live/status')
}

export function startLiveCapture(params: { iface: string; bpf?: string; host_name?: string; dumpcap_path?: string }) {
  return client.post('/traffic/api/live/start', params)
}

export function stopLiveCapture(params?: { enable_analysis?: boolean; host_name?: string }) {
  return client.post('/traffic/api/live/stop', params)
}

export function uploadPcap(formData: FormData) {
  return client.post('/traffic/api/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
}
