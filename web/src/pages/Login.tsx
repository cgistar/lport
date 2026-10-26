import { useState } from 'react'
import { Alert, Button, Card, Form, Input } from 'antd'
import { LockOutlined, SwapOutlined, UserOutlined } from '@ant-design/icons'
import { api } from '../api'

export default function Login({ onLogin }: { onLogin: (user: string) => void }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const submit = async (v: { username: string; password: string }) => {
    setLoading(true)
    setError('')
    try {
      const r = await api.login(v.username, v.password)
      onLogin(r.username)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-wrap">
      <Card style={{ width: 360, maxWidth: '100%' }}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <SwapOutlined style={{ fontSize: 32, color: '#1677ff' }} />
          <h2 style={{ margin: '8px 0 0' }}>lport 端口转发管理</h2>
        </div>
        {error && <Alert type="error" title={error} showIcon style={{ marginBottom: 16 }} />}
        <Form onFinish={submit} size="large" initialValues={{ username: 'admin' }}>
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码" autoComplete="current-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={loading}>
            登录
          </Button>
        </Form>
      </Card>
    </div>
  )
}
