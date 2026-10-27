import { getLang, tr } from './i18n'

export type Proto = 'tcp' | 'udp' | 'both'
export type Backend = 'builtin' | 'realm' | 'iptables' | 'nftables'

export interface RuleStatus {
  state: 'running' | 'stopped' | 'error' | 'applied'
  message?: string
  pids?: number[]
  restarts?: number
}

export interface Rule {
  id: string
  name: string
  proto: Proto
  listen_port: number
  target: string
  enabled: boolean
  remark: string
  created_at?: string
  status?: RuleStatus
}

export interface ProbeItem {
  proto: string
  addr: string
  state: 'ok' | 'fail' | 'unknown' | 'skipped'
  latency_ms: number
  message: string
}

export interface ProbeResult {
  local: ProbeItem[]
  target: ProbeItem[]
}

export interface Tool {
  name: string
  binary: string
  package: string
  installed: boolean
  path: string
  version: string
}

export interface SystemInfo {
  info: {
    os_id: string
    os_like: string
    os_name: string
    family: string
    package_manager: string
    kernel: string
    is_root: boolean
    ip_forward: boolean
    init_system: string
    tools: Tool[]
    install_command: string
  }
  backend: Backend
  backend_mode: '' | 'map' | 'linear'
  sync_error: string
  config_path: string
  listen: string
}

export interface Conflict {
  type: 'rule' | 'panel' | 'system'
  proto: string
  message: string
}

export interface Listener {
  proto: string
  addr: string
  port: number
  pid?: number
  process?: string
}

export interface Settings {
  backend: Backend
  backends: Backend[]
  listen: string
  username: string
}

export interface InstallResult {
  command: string
  output: string
  ok: boolean
  error?: string
}

export class UnauthorizedError extends Error {}

// 接口地址用相对路径，面板经反向代理挂在子路径（如 /lport/）下时同样可用
async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method,
    credentials: 'same-origin',
    // 后端按 X-Lport-Lang 返回对应语言的错误与状态消息
    headers: body !== undefined ? { 'Content-Type': 'application/json', 'X-Lport-Lang': getLang() } : { 'X-Lport-Lang': getLang() },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  let data: unknown = null
  try {
    data = await res.json()
  } catch {
    /* 非 JSON 响应 */
  }
  if (res.status === 401 && url !== 'api/login') {
    window.dispatchEvent(new Event('lport:unauthorized'))
    throw new UnauthorizedError(tr('api.unauthorized'))
  }
  if (!res.ok) {
    const msg = (data as { error?: string } | null)?.error ?? tr('api.failed', { status: res.status })
    throw new Error(msg)
  }
  return data as T
}

export const api = {
  login: (username: string, password: string) =>
    request<{ username: string }>('POST', 'api/login', { username, password }),
  logout: () => request('POST', 'api/logout'),
  me: () => request<{ username: string }>('GET', 'api/me'),
  system: () => request<SystemInfo>('GET', 'api/system'),
  install: (tools: string[]) => request<InstallResult>('POST', 'api/system/install', { tools }),
  settings: () => request<Settings>('GET', 'api/settings'),
  setBackend: (backend: Backend) => request<Settings>('PUT', 'api/settings', { backend }),
  changePassword: (old_password: string, new_password: string) =>
    request('PUT', 'api/settings/password', { old_password, new_password }),
  rules: () => request<Rule[]>('GET', 'api/rules'),
  createRule: (r: Partial<Rule>) => request<Rule>('POST', 'api/rules', r),
  updateRule: (id: string, r: Partial<Rule>) => request<Rule>('PUT', `api/rules/${id}`, r),
  deleteRule: (id: string) => request('DELETE', `api/rules/${id}`),
  toggleRule: (id: string, enabled: boolean) => request('POST', `api/rules/${id}/toggle`, { enabled }),
  probeRule: (id: string) => request<ProbeResult>('POST', `api/rules/${id}/probe`),
  checkPort: (proto: Proto, port: number, exclude?: string) =>
    request<{ available: boolean; conflicts: Conflict[] }>(
      'GET',
      `api/ports/check?proto=${proto}&port=${port}&exclude=${encodeURIComponent(exclude ?? '')}`,
    ),
  listening: () => request<Listener[]>('GET', 'api/ports/listening'),
}


// 后端依赖的外部工具；内置转发不依赖任何工具
export const toolForBackend: Record<Backend, string | null> = {
  builtin: null,
  realm: 'realm',
  iptables: 'iptables',
  nftables: 'nftables',
}
