import { useEffect, useState } from 'react'
import { ArrowLeftRight, LayoutDashboard, LogOut, Settings as SettingsIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Spinner } from '@/components/ui/spinner'
import { cn } from '@/lib/utils'
import { api } from './api'
import { useI18n } from './i18n'
import LangSwitch from './LangSwitch'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Rules from './pages/Rules'
import Settings from './pages/Settings'

type Page = 'dashboard' | 'rules' | 'settings'

function pageFromHash(): Page {
  const h = window.location.hash.replace('#', '')
  return h === 'rules' || h === 'settings' ? h : 'dashboard'
}

const nav = [
  { key: 'dashboard', icon: LayoutDashboard, label: 'nav.dashboard' },
  { key: 'rules', icon: ArrowLeftRight, label: 'nav.rules' },
  { key: 'settings', icon: SettingsIcon, label: 'nav.settings' },
] as const

export default function App() {
  const [user, setUser] = useState<string | null | undefined>(undefined)
  const [page, setPage] = useState<Page>(pageFromHash)
  const { lang, t } = useI18n()

  useEffect(() => {
    api.me().then((r) => setUser(r.username)).catch(() => setUser(null))
    const onUnauthorized = () => setUser(null)
    const onHash = () => setPage(pageFromHash())
    window.addEventListener('lport:unauthorized', onUnauthorized)
    window.addEventListener('hashchange', onHash)
    return () => {
      window.removeEventListener('lport:unauthorized', onUnauthorized)
      window.removeEventListener('hashchange', onHash)
    }
  }, [])

  if (user === undefined) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner className="size-6 text-muted-foreground" />
      </div>
    )
  }
  if (user === null) {
    return <Login onLogin={setUser} />
  }

  const logout = async () => {
    await api.logout().catch(() => {})
    setUser(null)
  }

  return (
    <div className="min-h-screen bg-muted/40">
      <header className="sticky top-0 z-10 border-b bg-background">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-2 px-4 sm:gap-6">
          <div className="flex items-center gap-2 font-semibold">
            <ArrowLeftRight className="size-5" />
            lport
          </div>
          <nav className="flex flex-1 items-center gap-1">
            {nav.map(({ key, icon: Icon, label }) => (
              <a
                key={key}
                href={`#${key}`}
                aria-current={page === key ? 'page' : undefined}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm transition-colors',
                  page === key ? 'bg-muted font-medium text-foreground' : 'text-muted-foreground hover:text-foreground',
                )}
              >
                <Icon className="size-4" />
                <span className="hidden sm:inline">{t(label)}</span>
              </a>
            ))}
          </nav>
          <LangSwitch />
          <Button variant="ghost" onClick={logout} aria-label={t('common.logout')}>
            <LogOut />
            <span className="hidden sm:inline">{user}</span>
          </Button>
        </div>
      </header>
      {/* 切换语言时重新挂载页面，使后端返回的消息也按新语言重新获取 */}
      <main key={lang} className="mx-auto max-w-6xl px-4 py-6">
        {page === 'dashboard' && <Dashboard />}
        {page === 'rules' && <Rules />}
        {page === 'settings' && <Settings />}
      </main>
    </div>
  )
}
