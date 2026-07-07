import client from './client'

export interface DashboardOverview {
  ok: boolean
  stats: {
    log_count: number
    process_count: number
    flow_count: number
    attack_count: number
  }
  freshness: Record<string, string>
  recent_reports: any[]
}

export function getDashboardOverview(): Promise<{ data: DashboardOverview }> {
  return client.get('/dashboard/api/overview')
}
