import client from './client'

export function getScenarios() {
  return client.get('/scenario/api/scenarios')
}

export function startScenario(id: string) {
  return client.post(`/scenario/api/scenarios/${id}/start`)
}

export function stopScenario(id: string) {
  return client.post(`/scenario/api/scenarios/${id}/stop`)
}

export function stopAllScenarios() {
  return client.post('/scenario/api/scenarios/stop_all')
}

export function getScenarioStatus(id: string) {
  return client.get(`/scenario/api/scenarios/${id}/status`)
}

export function getAllStatus() {
  return client.get('/scenario/api/status')
}

export function getEvents(limit = 100, type?: string) {
  return client.get('/scenario/api/events', { params: { limit, type } })
}

export function clearAllData() {
  return client.post('/scenario/api/clear')
}

export function getNetworkTopology() {
  return client.get('/scenario/api/network')
}

export function getNetworkNode(nodeId: string) {
  return client.get(`/scenario/api/network/node/${nodeId}`)
}
