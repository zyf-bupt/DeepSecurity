import client from './client'

export function getLatestAttribution() {
  return client.get('/attribution/api/latest')
}

export function runAttribute(data?: any) {
  return client.post('/attribution/api/attribute', { data })
}

export function getAttributionReport() {
  return client.get('/attribution/api/report')
}

export function getAptGroups() {
  return client.get('/attribution/api/apt/groups')
}

export function getAttckTechniques() {
  return client.get('/attribution/api/attck/techniques')
}
