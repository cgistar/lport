import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

export type Lang = 'zh' | 'en'

const zh = {
  'app.title': 'lport 端口转发',
  'nav.dashboard': '概览',
  'nav.rules': '转发规则',
  'nav.settings': '设置',

  'common.save': '保存',
  'common.create': '创建',
  'common.delete': '删除',
  'common.close': '关闭',
  'common.notInstalled': '未安装',
  'common.colon': '：',
  'common.cancel': '取消',
  'common.confirm': '确定',
  'common.edit': '编辑',
  'common.refresh': '刷新',
  'common.copy': '复制',
  'common.copied': '已复制',
  'common.required': '此项为必填',
  'common.all': '全部',
  'common.previous': '上一页',
  'common.next': '下一页',
  'common.range': '第 {from}-{to} 条，共 {total} 条',
  'common.logout': '退出登录',
  'common.language': '语言',

  'api.unauthorized': '未登录',
  'api.failed': '请求失败 ({status})',

  'backend.socat': 'socat（用户态进程）',
  'backend.iptables': 'iptables（内核 NAT）',
  'backend.nftables': 'nftables（内核 NAT）',

  'login.title': 'lport 端口转发管理',
  'login.username': '用户名',
  'login.usernameRequired': '请输入用户名',
  'login.password': '密码',
  'login.passwordRequired': '请输入密码',
  'login.submit': '登录',

  'dash.installDone': '安装完成',
  'dash.syncError': '转发规则应用失败',
  'dash.backendMissing': '当前后端 {backend} 依赖的工具未安装，转发规则不会生效，请先安装或在设置中切换后端。',
  'dash.notRoot': 'lport 未以 root 运行，内核转发后端与软件安装不可用。',
  'dash.system': '系统信息',
  'dash.os': '系统',
  'dash.unknown': '未知',
  'dash.kernel': '内核',
  'dash.packageManager': '包管理器',
  'dash.notDetected': '未识别',
  'dash.initSystem': '服务管理',
  'dash.ipForward': 'IP 转发',
  'dash.on': '已开启',
  'dash.off': '未开启',
  'dash.ipForwardHint': '内核后端启用时自动开启',
  'dash.backend': '当前后端',
  'dash.mapMode': 'map 查找模式',
  'dash.linearMode': '兼容模式',
  'dash.linearTip': '当前 nft 或内核版本不支持 map 方式 DNAT（需 nft ≥ 0.9.4、内核 ≥ 5.6），规则逐条匹配',
  'dash.listen': '管理地址',
  'dash.config': '配置文件',
  'dash.tools': '依赖工具',
  'dash.installAll': '全部安装',
  'dash.tool': '工具',
  'dash.status': '状态',
  'dash.install': '安装',
  'dash.manualCommand': '手动安装命令（{pm}）：',
  'dash.noPackageManager': '无法识别包管理器，请手动安装缺失工具。',
  'dash.installOk': '安装成功',
  'dash.installFailed': '安装失败',
  'dash.command': '执行命令：',
  'dash.noOutput': '(无输出)',

  'state.running': '运行中',
  'state.applied': '已生效',
  'state.stopped': '已停用',
  'state.error': '异常',

  'rules.title': '转发规则',
  'rules.saved': '已保存',
  'rules.created': '已创建',
  'rules.deleted': '已删除',
  'rules.edit': '编辑规则',
  'rules.new': '新建转发规则',
  'rules.newButton': '新建规则',
  'rules.probeAll': '全部检测',
  'rules.name': '名称',
  'rules.namePlaceholder': '留空自动生成',
  'rules.proto': '协议',
  'rules.listenPort': '监听端口',
  'rules.portHelp': '本机监听端口',
  'rules.portChecking': '正在检查端口...',
  'rules.portFree': '端口可用',
  'rules.portRequired': '请输入端口',
  'rules.portRange': '端口必须在 1-65535 之间',
  'rules.portPlaceholder': '如 8080',
  'rules.forwardTo': '转发到',
  'rules.targetRequired': '请输入目标地址',
  'rules.targetFormat': '格式为 IP:端口 或 域名:端口',
  'rules.targetPlaceholder': '10.0.0.5:80 或 example.com:80',
  'rules.remark': '备注',
  'rules.enabled': '启用',
  'rules.errorCount': '{n} 条规则运行异常，鼠标悬停状态查看原因',
  'rules.empty': '暂无规则，点击右上角「新建规则」添加',
  'rules.target': '目标',
  'rules.connectivity': '连通性',
  'rules.status': '状态',
  'rules.restarts': '，已重启 {n} 次',
  'rules.actions': '操作',
  'rules.confirmDelete': '删除规则「{name}」？',

  'probe.tooltip': '检测本机监听端口与目标端口的连通性',
  'probe.failed': '检测失败',
  'probe.failedTip': '{error}，点击重试',
  'probe.local': '本机',
  'probe.target': '目标',
  'probe.checking': '检测中...',
  'probe.retest': '点击重新检测',
  'probe.hintForwardFail': '目标可达但经本机转发失败：请检查规则状态、转发后端与防火墙。',
  'probe.hintLocalOk': '本机检测不经过 FORWARD 链；若外部仍无法访问，请检查云安全组与 FORWARD 防火墙规则。',
  'probe.hintTargetFail': '本机无法直连目标：目标服务未启动、地址错误或目标防火墙拦截。',

  'settings.configNote': '所有配置保存在 YAML 配置文件中，也可手动编辑后重启服务生效（界面保存会覆盖文件中的注释）。',
  'settings.backend': '转发后端',
  'settings.recommended': '推荐',
  'settings.switchTitle': '切换到 {backend}？',
  'settings.switchContent': '将先清除当前后端的所有转发，再用新后端重新应用全部规则；失败时自动回滚。',
  'settings.switched': '已切换到 {backend}',
  'settings.desc.socat': '每条规则一个 socat 进程，支持转发到域名和本机回环地址，配置简单；性能低于内核转发。',
  'settings.desc.iptables': '内核 DNAT，性能高；目标可为 IP 或域名（每 60 秒重新解析）。仅操作 LPORT_* 自有链。',
  'settings.desc.nftables':
    '内核 DNAT，性能最好；使用 map 哈希查找，规则数量多时匹配开销不变（老版本自动降级为逐条匹配）。目标可为 IP 或域名（每 60 秒重新解析），仅操作独立的 ip lport 表。',
  'settings.password': '修改密码',
  'settings.passwordChanged': '密码已修改，请重新登录',
  'settings.oldPassword': '原密码',
  'settings.newPassword': '新密码',
  'settings.minLength': '至少 6 位',
  'settings.confirmPassword': '确认新密码',
  'settings.mismatch': '两次输入不一致',
  'settings.listening': '系统已占用端口',
  'settings.search': '端口 / 进程',
  'settings.proto': '协议',
  'settings.port': '端口',
  'settings.address': '地址',
  'settings.process': '进程',
}

export type MessageKey = keyof typeof zh

const en: Record<MessageKey, string> = {
  'app.title': 'lport Port Forwarding',
  'nav.dashboard': 'Overview',
  'nav.rules': 'Rules',
  'nav.settings': 'Settings',

  'common.save': 'Save',
  'common.create': 'Create',
  'common.delete': 'Delete',
  'common.close': 'Close',
  'common.notInstalled': 'Not installed',
  'common.colon': ': ',
  'common.cancel': 'Cancel',
  'common.confirm': 'Confirm',
  'common.edit': 'Edit',
  'common.refresh': 'Refresh',
  'common.copy': 'Copy',
  'common.copied': 'Copied',
  'common.required': 'This field is required',
  'common.all': 'All',
  'common.previous': 'Previous page',
  'common.next': 'Next page',
  'common.range': '{from}–{to} of {total}',
  'common.logout': 'Log out',
  'common.language': 'Language',

  'api.unauthorized': 'Not logged in',
  'api.failed': 'Request failed ({status})',

  'backend.socat': 'socat (user-space process)',
  'backend.iptables': 'iptables (kernel NAT)',
  'backend.nftables': 'nftables (kernel NAT)',

  'login.title': 'lport Port Forwarding',
  'login.username': 'Username',
  'login.usernameRequired': 'Enter your username',
  'login.password': 'Password',
  'login.passwordRequired': 'Enter your password',
  'login.submit': 'Log in',

  'dash.installDone': 'Installation complete',
  'dash.syncError': 'Failed to apply forwarding rules',
  'dash.backendMissing':
    'The tool required by the current backend {backend} is not installed, so forwarding rules will not take effect. Install it, or switch backends in Settings.',
  'dash.notRoot': 'lport is not running as root; kernel backends and package installation are unavailable.',
  'dash.system': 'System',
  'dash.os': 'OS',
  'dash.unknown': 'Unknown',
  'dash.kernel': 'Kernel',
  'dash.packageManager': 'Package manager',
  'dash.notDetected': 'Not detected',
  'dash.initSystem': 'Init system',
  'dash.ipForward': 'IP forwarding',
  'dash.on': 'Enabled',
  'dash.off': 'Disabled',
  'dash.ipForwardHint': 'Enabled automatically by kernel backends',
  'dash.backend': 'Backend',
  'dash.mapMode': 'map lookup mode',
  'dash.linearMode': 'Compatibility mode',
  'dash.linearTip':
    'This nft or kernel version does not support map-based DNAT (requires nft ≥ 0.9.4 and kernel ≥ 5.6), so rules are matched one by one',
  'dash.listen': 'Admin address',
  'dash.config': 'Config file',
  'dash.tools': 'Dependencies',
  'dash.installAll': 'Install all',
  'dash.tool': 'Tool',
  'dash.status': 'Status',
  'dash.install': 'Install',
  'dash.manualCommand': 'Manual install command ({pm}):',
  'dash.noPackageManager': 'Could not detect the package manager; install the missing tools manually.',
  'dash.installOk': 'Installation succeeded',
  'dash.installFailed': 'Installation failed',
  'dash.command': 'Command: ',
  'dash.noOutput': '(no output)',

  'state.running': 'Running',
  'state.applied': 'Applied',
  'state.stopped': 'Stopped',
  'state.error': 'Error',

  'rules.title': 'Forwarding rules',
  'rules.saved': 'Saved',
  'rules.created': 'Created',
  'rules.deleted': 'Deleted',
  'rules.edit': 'Edit rule',
  'rules.new': 'New forwarding rule',
  'rules.newButton': 'New rule',
  'rules.probeAll': 'Probe all',
  'rules.name': 'Name',
  'rules.namePlaceholder': 'Leave empty to generate',
  'rules.proto': 'Protocol',
  'rules.listenPort': 'Listen port',
  'rules.portHelp': 'Port to listen on locally',
  'rules.portChecking': 'Checking port...',
  'rules.portFree': 'Port is available',
  'rules.portRequired': 'Enter a port',
  'rules.portRange': 'Port must be between 1 and 65535',
  'rules.portPlaceholder': 'e.g. 8080',
  'rules.forwardTo': 'Forward to',
  'rules.targetRequired': 'Enter a target address',
  'rules.targetFormat': 'Use IP:port or domain:port',
  'rules.targetPlaceholder': '10.0.0.5:80 or example.com:80',
  'rules.remark': 'Note',
  'rules.enabled': 'Enabled',
  'rules.errorCount': '{n} rule(s) failing; hover over the status to see why',
  'rules.empty': 'No rules yet. Click "New rule" in the top right to add one.',
  'rules.target': 'Target',
  'rules.connectivity': 'Connectivity',
  'rules.status': 'Status',
  'rules.restarts': ', restarted {n} time(s)',
  'rules.actions': 'Actions',
  'rules.confirmDelete': 'Delete rule "{name}"?',

  'probe.tooltip': 'Check connectivity of the local listen port and the target',
  'probe.failed': 'Probe failed',
  'probe.failedTip': '{error}. Click to retry',
  'probe.local': 'Local',
  'probe.target': 'Target',
  'probe.checking': 'Checking...',
  'probe.retest': 'Click to probe again',
  'probe.hintForwardFail': 'The target is reachable but forwarding through this host fails: check the rule status, backend, and firewall.',
  'probe.hintLocalOk':
    'Local checks bypass the FORWARD chain; if external clients still cannot connect, check cloud security groups and FORWARD firewall rules.',
  'probe.hintTargetFail':
    'This host cannot reach the target directly: the service is down, the address is wrong, or a firewall on the target blocks it.',

  'settings.configNote':
    'All settings are stored in a YAML config file. You can also edit it by hand and restart the service to apply (saving from the UI overwrites comments in the file).',
  'settings.backend': 'Forwarding backend',
  'settings.recommended': 'Recommended',
  'settings.switchTitle': 'Switch to {backend}?',
  'settings.switchContent':
    'All forwards from the current backend are cleared first, then every rule is reapplied with the new backend. Changes roll back automatically on failure.',
  'settings.switched': 'Switched to {backend}',
  'settings.desc.socat':
    'One socat process per rule. Can forward to domain names and local loopback addresses and is simple to set up, but slower than in-kernel forwarding.',
  'settings.desc.iptables':
    'In-kernel DNAT with high performance. Targets can be IPs or domain names (re-resolved every 60 seconds). Only touches its own LPORT_* chains.',
  'settings.desc.nftables':
    'In-kernel DNAT with the best performance. Uses map lookups, so matching cost stays flat as rules grow (falls back to per-rule matching on older versions). Targets can be IPs or domain names (re-resolved every 60 seconds). Only touches its own ip lport table.',
  'settings.password': 'Change password',
  'settings.passwordChanged': 'Password changed. Please log in again.',
  'settings.oldPassword': 'Current password',
  'settings.newPassword': 'New password',
  'settings.minLength': 'At least 6 characters',
  'settings.confirmPassword': 'Confirm new password',
  'settings.mismatch': 'Passwords do not match',
  'settings.listening': 'Ports in use',
  'settings.search': 'Port / process',
  'settings.proto': 'Protocol',
  'settings.port': 'Port',
  'settings.address': 'Address',
  'settings.process': 'Process',
}

const dicts: Record<Lang, Record<MessageKey, string>> = { zh, en }

export const langNames: Record<Lang, string> = { zh: '中文', en: 'English' }

const storageKey = 'lport.lang'

function initialLang(): Lang {
  try {
    const saved = localStorage.getItem(storageKey)
    if (saved === 'zh' || saved === 'en') return saved
  } catch {
    /* 存储不可用时按浏览器语言 */
  }
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'
}

let current: Lang = initialLang()

/** 当前语言，供组件外（如 api.ts）使用。 */
export const getLang = () => current

export type Vars = Record<string, string | number>

function translate(lang: Lang, key: MessageKey, vars?: Vars) {
  const s = dicts[lang][key]
  return vars ? s.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m)) : s
}

/** 组件外使用的翻译函数，按当前语言。 */
export const tr = (key: MessageKey, vars?: Vars) => translate(current, key, vars)

interface I18n {
  lang: Lang
  setLang: (l: Lang) => void
  t: (key: MessageKey, vars?: Vars) => string
}

const I18nContext = createContext<I18n>({ lang: current, setLang: () => {}, t: tr })

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(current)

  const setLang = useCallback((l: Lang) => {
    current = l
    try {
      localStorage.setItem(storageKey, l)
    } catch {
      /* 忽略，仅本次会话生效 */
    }
    setLangState(l)
  }, [])

  useEffect(() => {
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en'
    document.title = translate(lang, 'app.title')
  }, [lang])

  const value = useMemo<I18n>(() => ({ lang, setLang, t: (key, vars) => translate(lang, key, vars) }), [lang, setLang])
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export const useI18n = () => useContext(I18nContext)
