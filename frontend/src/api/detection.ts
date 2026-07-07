import client from './client'

export function getDetectionStats() {
  return client.get('/detection/api/stats')
}

export function getAlerts(limit = 50, severity?: string, scenario?: string) {
  return client.get('/detection/api/alerts', { params: { limit, severity, scenario } })
}

export function getAlertsLive() {
  return client.get('/detection/api/alerts/live')
}

export function getEventsLive() {
  return client.get('/detection/api/events/live')
}

export function runFullAnalysis() {
  return client.post('/detection/api/analyze')
}

export function getReport() {
  return client.get('/detection/api/report')
}

export function ragSearch(q: string) {
  return client.get('/detection/api/rag/search', { params: { q } })
}

export function getKnowledgeBase() {
  return client.get('/detection/api/knowledge')
}
