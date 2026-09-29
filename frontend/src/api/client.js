import axios from 'axios'

const api = axios.create({
  baseURL: 'https://unilogx-sih26156.onrender.com/api/v1',
  timeout: 30000
})
export const getMetrics = () => api.get('/metrics').then(r => r.data)
export const getEvents = (params = {}) => api.get('/events', { params }).then(r => r.data)
export const getEvent = id => api.get(`/events/${id}`).then(r => r.data)
export const getParsers = () => api.get('/parsers').then(r => r.data)
export const getParserDetail = name => api.get(`/parsers/${name}`).then(r => r.data)
export const uploadLog = file => {
  const fd = new FormData()
  fd.append('file', file)
  return api.post('/upload', fd).then(r => r.data)
}

// Quarantine endpoints
export const getQuarantines = (limit = 100) => api.get('/quarantine', { params: { limit } }).then(r => r.data)
export const getQuarantine = id => api.get(`/quarantine/${id}`).then(r => r.data)
export const reprocessQuarantine = id => api.post(`/quarantine/${id}/reprocess`).then(r => r.data)
export const reprocessAllQuarantine = () => api.post('/quarantine/reprocess').then(r => r.data)

export default api
