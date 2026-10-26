import { useEffect, useState } from 'react'
import { Button, Menu, Spin } from 'antd'
import { DashboardOutlined, LogoutOutlined, SettingOutlined, SwapOutlined } from '@ant-design/icons'
import { api } from './api'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Rules from './pages/Rules'
import Settings from './pages/Settings'

type Page = 'dashboard' | 'rules' | 'settings'

function pageFromHash(): Page {
  const h = window.location.hash.replace('#', '')
  return h === 'rules' || h === 'settings' ? h : 'dashboard'
}

export default function App() {
  const [user, setUser] = useState<string | null | undefined>(undefined)
  const [page, setPage] = useState<Page>(pageFromHash)

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
      <div className="login-wrap">
        <Spin />
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
    <>
      <div className="app-header">
        <div className="app-logo">
          <SwapOutlined style={{ color: '#1677ff' }} />
          lport
        </div>
        <Menu
          mode="horizontal"
          selectedKeys={[page]}
          onClick={(e) => {
            window.location.hash = e.key
          }}
          items={[
            { key: 'dashboard', icon: <DashboardOutlined />, label: '概览' },
            { key: 'rules', icon: <SwapOutlined />, label: '转发规则' },
            { key: 'settings', icon: <SettingOutlined />, label: '设置' },
          ]}
        />
        <Button type="text" icon={<LogoutOutlined />} onClick={logout}>
          {user}
        </Button>
      </div>
      <div className="app-content">
        {page === 'dashboard' && <Dashboard />}
        {page === 'rules' && <Rules />}
        {page === 'settings' && <Settings />}
      </div>
    </>
  )
}
