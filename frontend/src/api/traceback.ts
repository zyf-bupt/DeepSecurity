import client from './client'

export function getHighAlerts() {
  return client.get('/traceback/api/high_alerts')
}

export function runTracebackAnalysis(params?: { mock_mode?: boolean; use_cache?: boolean }) {
  return client.post('/traceback/api/analyze', params)
}

export function generateAIReport(reportData: any) {
  return client.post('/traceback/api/generate_report_ai', { report_data: reportData })
}
