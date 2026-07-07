import client from './client'

export function getLogs(params?: { page?: number; host_name?: string }) {
  return client.get('/logs/', { params })
}

export function getLogDetail(id: number) {
  return client.get(`/logs/${id}`)
}

export function setDbServer(dbServer: string, hostName?: string) {
  const params = new URLSearchParams()
  params.append('db_server', dbServer)
  if (hostName) params.append('host_name', hostName)
  return client.post('/logs/db', params)
}
