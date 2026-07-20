const BASE = 'http://localhost:8080/api/v1'

function getToken(): string | null {
  return sessionStorage.getItem('rampart_token')
}

function setToken(token: string): void {
  sessionStorage.setItem('rampart_token', token)
}

function clearToken(): void {
  sessionStorage.removeItem('rampart_token')
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const res = await fetch(`${BASE}${path}`, { ...options, headers })

  if (res.status === 401) {
    clearToken()
    window.location.reload()
    throw new Error('Unauthorized')
  }

  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || res.statusText)
  }

  return res.json()
}

export interface HealthResponse {
  status: string
}

export interface LoginResponse {
  token: string
}

export interface Server {
  name: string
  server_type: string
  ip: string
  port: number
  status: string
  online_players: number
  max_players: number
  tps: number
  last_heartbeat: string
}

export interface BlacklistEntry {
  target: string
  type: string
  reason: string
  created: string
  expires: string
}

export interface Node {
  id: string
  role: string
  ip: string
  status: string
  last_heartbeat: string
}

export async function login(password: string): Promise<LoginResponse> {
  const res = await fetch(`${BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || res.statusText)
  }
  const data: LoginResponse = await res.json()
  setToken(data.token)
  return data
}

export function logout(): void {
  clearToken()
  window.location.reload()
}

export async function fetchServers(): Promise<Server[]> {
  return apiFetch<Server[]>('/servers')
}

export async function fetchBlacklist(): Promise<BlacklistEntry[]> {
  return apiFetch<BlacklistEntry[]>('/blacklist')
}

export async function addBlacklist(
  target: string,
  type: string,
  reason: string,
  durationSecs: number
): Promise<void> {
  await apiFetch('/blacklist', {
    method: 'POST',
    body: JSON.stringify({ target, type, reason, duration_secs: durationSecs }),
  })
}

export async function fetchNodes(): Promise<Node[]> {
  return apiFetch<Node[]>('/nodes')
}

export async function fetchHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>('/health')
}
