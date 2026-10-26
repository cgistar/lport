import { useCallback, useEffect, useMemo, useState } from 'react'
import { Alert, App, Button, Card, Col, Form, Input, Radio, Row, Space, Table, Tag, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { api, backendLabels, toolForBackend, type Backend, type Listener, type Settings as S, type Tool } from '../api'

const backendDesc: Record<Backend, string> = {
  socat: '每条规则一个 socat 进程，支持转发到域名和本机回环地址，配置简单；性能低于内核转发。',
  iptables: '内核 DNAT，性能高；目标可为 IP 或域名（每 60 秒重新解析）。仅操作 LPORT_* 自有链。',
  nftables: '内核 DNAT，性能最好；使用 map 哈希查找，规则数量多时匹配开销不变（老版本自动降级为逐条匹配）。目标可为 IP 或域名（每 60 秒重新解析），仅操作独立的 ip lport 表。',
}

function BackendCard() {
  const { message, modal } = App.useApp()
  const [settings, setSettings] = useState<S | null>(null)
  const [tools, setTools] = useState<Tool[]>([])
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    api.settings().then(setSettings).catch((e) => message.error(e.message))
    api.system().then((s) => setTools(s.info.tools)).catch(() => {})
  }, [message])

  const installed = (b: Backend) => tools.find((t) => t.name === toolForBackend[b])?.installed ?? false

  const change = (b: Backend) => {
    modal.confirm({
      title: `切换到 ${b}？`,
      content: '将先清除当前后端的所有转发，再用新后端重新应用全部规则；失败时自动回滚。',
      onOk: async () => {
        setSaving(true)
        try {
          setSettings(await api.setBackend(b))
          message.success(`已切换到 ${b}`)
        } catch (e) {
          message.error((e as Error).message)
        } finally {
          setSaving(false)
        }
      },
    })
  }

  return (
    <Card title="转发后端" loading={!settings}>
      {settings && (
        <Radio.Group value={settings.backend} disabled={saving} onChange={(e) => change(e.target.value)} style={{ width: '100%' }}>
          <Space orientation="vertical" style={{ width: '100%' }}>
            {settings.backends.map((b) => (
              <Radio key={b} value={b} disabled={!installed(b)}>
                <b>{backendLabels[b]}</b> {b === 'nftables' && <Tag color="green">推荐</Tag>}
                {!installed(b) && <Tag color="red">未安装</Tag>}
                <div>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {backendDesc[b]}
                  </Typography.Text>
                </div>
              </Radio>
            ))}
          </Space>
        </Radio.Group>
      )}
    </Card>
  )
}

function PasswordCard() {
  const { message } = App.useApp()
  const [form] = Form.useForm()
  const [saving, setSaving] = useState(false)

  const submit = async (v: { old_password: string; new_password: string }) => {
    setSaving(true)
    try {
      await api.changePassword(v.old_password, v.new_password)
      message.success('密码已修改，请重新登录')
      form.resetFields()
      setTimeout(() => window.dispatchEvent(new Event('lport:unauthorized')), 800)
    } catch (e) {
      message.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="修改密码">
      <Form form={form} layout="vertical" onFinish={submit}>
        <Form.Item name="old_password" label="原密码" rules={[{ required: true }]}>
          <Input.Password autoComplete="current-password" />
        </Form.Item>
        <Form.Item name="new_password" label="新密码" rules={[{ required: true }, { min: 6, message: '至少 6 位' }]}>
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Form.Item
          name="confirm"
          label="确认新密码"
          dependencies={['new_password']}
          rules={[
            { required: true },
            ({ getFieldValue }) => ({
              validator: (_, v) => (v === getFieldValue('new_password') ? Promise.resolve() : Promise.reject(new Error('两次输入不一致'))),
            }),
          ]}
        >
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={saving}>
          修改密码
        </Button>
      </Form>
    </Card>
  )
}

function ListeningCard() {
  const { message } = App.useApp()
  const [data, setData] = useState<Listener[]>([])
  const [loading, setLoading] = useState(false)
  const [q, setQ] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setData(await api.listening())
    } catch (e) {
      message.error((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [message])

  useEffect(() => {
    load()
  }, [load])

  const filtered = useMemo(
    () => (q ? data.filter((l) => String(l.port).includes(q) || (l.process ?? '').includes(q)) : data),
    [data, q],
  )

  return (
    <Card
      title="系统已占用端口"
      extra={
        <Space>
          <Input.Search placeholder="端口 / 进程" allowClear onChange={(e) => setQ(e.target.value)} style={{ width: 180 }} />
          <Button icon={<ReloadOutlined />} onClick={load} loading={loading} />
        </Space>
      }
    >
      <Table<Listener>
        rowKey={(l) => `${l.proto}-${l.addr}-${l.port}-${l.pid ?? ''}`}
        size="small"
        loading={loading}
        dataSource={filtered}
        pagination={{ pageSize: 15, hideOnSinglePage: true, showSizeChanger: false }}
        scroll={{ x: true }}
        columns={[
          { title: '协议', dataIndex: 'proto', width: 80, render: (p: string) => <Tag>{p.toUpperCase()}</Tag> },
          { title: '端口', dataIndex: 'port', width: 90, render: (p: number) => <span className="mono">{p}</span> },
          { title: '地址', dataIndex: 'addr', render: (a: string) => <span className="mono">{a}</span> },
          { title: '进程', render: (_, l) => (l.process ? `${l.process} (${l.pid})` : '-') },
        ]}
      />
    </Card>
  )
}

export default function Settings() {
  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <Alert
        type="info"
        showIcon
        title="所有配置保存在 YAML 配置文件中，也可手动编辑后重启服务生效（界面保存会覆盖文件中的注释）。"
      />
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <BackendCard />
        </Col>
        <Col xs={24} lg={10}>
          <PasswordCard />
        </Col>
      </Row>
      <ListeningCard />
    </Space>
  )
}
