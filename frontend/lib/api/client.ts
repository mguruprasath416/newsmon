import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const apiClient = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
});

// Pass default auth header if needed, but errors won't force redirect to login
apiClient.interceptors.response.use(
  (res) => res,
  (error) => {
    return Promise.reject(error);
  }
);

// ── API functions ─────────────────────────────────────────────────────────────

export const authApi = {
  login:    (email: string, password: string) => apiClient.post('/auth/login', { email, password }),
  register: (email: string, password: string, full_name: string) => apiClient.post('/auth/register', { email, password, full_name }),
  logout:   () => apiClient.post('/auth/logout'),
  me:       () => apiClient.get('/auth/me'),
};

export const feedApi = {
  list:       (params: any) => apiClient.get('/feed', { params }),
  get:        (id: string)  => apiClient.get(`/feed/${id}`),
  stats:      ()            => apiClient.get('/feed/stats'),
  bookmark:   (id: string)  => apiClient.post(`/feed/${id}/bookmark`),
  unbookmark: (id: string)  => apiClient.delete(`/feed/${id}/bookmark`),
  addNote:    (id: string, note: string) => apiClient.post(`/feed/${id}/notes`, null, { params: { note } }),
  bookmarks:  ()            => apiClient.get('/feed/bookmarks/me'),
};

export const lensApi = {
  analyze: (input_type: string, value: string, tlp_level = 'white') =>
    apiClient.post('/lens/analyze', { input_type, value, tlp_level }),
  analyzeFile: (file: File, tlp_level = 'white') => {
    const form = new FormData();
    form.append('file', file);
    form.append('tlp_level', tlp_level);
    return apiClient.post('/lens/analyze/file', form, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
  jobStatus: (jobId: string) => apiClient.get(`/lens/jobs/${jobId}`),
};

export const reportsApi = {
  list:   (params: any) => apiClient.get('/reports', { params }),
  get:    (id: string)  => apiClient.get(`/reports/${id}`),
  delete: (id: string)  => apiClient.delete(`/reports/${id}`),
  share:  (id: string)  => apiClient.post(`/reports/${id}/share`),
  export: (id: string, format: string) => apiClient.post(`/reports/${id}/export`, null, { params: { format }, responseType: 'blob' }),
};

export const kevApi = {
  list:   (params: any) => apiClient.get('/kev', { params }),
  get:    (cveId: string) => apiClient.get(`/kev/${cveId}`),
  stats:  ()            => apiClient.get('/kev/stats'),
  recent: (days = 30)   => apiClient.get('/kev/recent', { params: { days } }),
  sync:   ()            => apiClient.post('/kev/sync'),
};

export const searchApi = {
  search:    (params: any) => apiClient.post('/search', null, { params }),
  suggest:   (q: string)   => apiClient.get('/search/suggest', { params: { q } }),
  iocLookup: (value: string) => apiClient.post(`/search/ioc/${encodeURIComponent(value)}`),
};

export const digestApi = {
  latest:   () => apiClient.get('/digest/latest'),
  list:     () => apiClient.get('/digest'),
  get:      (id: string) => apiClient.get(`/digest/${id}`),
  generate: () => apiClient.post('/digest/generate'),
};




export const malwareApi = {
  list: (params: any) => apiClient.get('/malware', { params }),
  get:  (id: string)  => apiClient.get(`/malware/${id}`),
};

export const campaignsApi = {
  list: (params: any) => apiClient.get('/campaigns', { params }),
  get:  (id: string)  => apiClient.get(`/campaigns/${id}`),
};

export const sourcesApi = {
  list:   (params: any) => apiClient.get('/sources', { params }),
  health: (id: string)  => apiClient.get(`/sources/${id}/health`),
  addUrl: (data: any)   => apiClient.post('/sources/add-url', data),
};

export const analyticsApi = {
  overview: () => apiClient.get('/analytics/overview'),
  threats:  () => apiClient.get('/analytics/threats'),
};

export const clustersApi = {
  list:   (params?: any) => apiClient.get('/clusters', { params }),
  get:    (slug: string, params?: any) => apiClient.get(`/clusters/${slug}`, { params }),
  create: (data: any) => apiClient.post('/clusters', data),
  update: (id: string, data: any) => apiClient.put(`/clusters/${id}`, data),
  delete: (id: string) => apiClient.delete(`/clusters/${id}`),
  feed:   (id: string, limit = 50) => apiClient.get(`/clusters/${id}/feed`, { params: { limit } }),
};

export const clusterRulesApi = {
  list:      ()                         => apiClient.get('/clusters/rules'),
  create:    (data: any)                => apiClient.post('/clusters/rules', data),
  update:    (id: string, data: any)    => apiClient.put(`/clusters/rules/${id}`, data),
  remove:    (id: string)               => apiClient.delete(`/clusters/rules/${id}`),
  run:       (id: string)               => apiClient.post(`/clusters/rules/${id}/run`),
};

export const threatActorsApi = {
  list:   (params: any) => apiClient.get('/threat-actors', { params }),
  get:    (id: string)  => apiClient.get(`/threat-actors/${id}`),
  aiFill: (data: any)   => apiClient.post('/threat-actors/ai-fill', data),
};

export const teamsApi = {
  getConfig:          ()          => apiClient.get('/teams/config'),
  saveWebhook:        (data: any) => apiClient.post('/teams/webhook', data),
  sendTodaysNews:     ()          => apiClient.post('/teams/send-todays-news'),
  sendCompanyBreaches:()          => apiClient.post('/teams/send-company-breaches'),
};

export const cyberpulseApi = {
  list:         (params?: any) => apiClient.get('/viral-events', { params }),
  heatMap:      (min_sources?: number, params?: any) => apiClient.get('/viral-events/heat-map', { params: { min_sources, ...params } }),
  trending:     (limit?: number, params?: any) => apiClient.get('/viral-events/trending', { params: { limit, ...params } }),
  highPriority: (limit?: number, params?: any) => apiClient.get('/viral-events/high-priority', { params: { limit, ...params } }),
  get:          (id: string) => apiClient.get(`/viral-events/${id}`),
  sources:      (id: string) => apiClient.get(`/viral-events/${id}/sources`),
  articles:     (id: string, limit?: number) => apiClient.get(`/viral-events/${id}/articles`, { params: { limit } }),
  timeline:     (id: string) => apiClient.get(`/viral-events/${id}/timeline`),
  recalculate:  (hours?: number) => apiClient.post('/viral-events/recalculate', null, { params: { hours } }),
};




