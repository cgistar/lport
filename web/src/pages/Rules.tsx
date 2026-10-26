import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  App,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Radio,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { ApiOutlined, DeleteOutlined, EditOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons'
import { api, type Conflict, type Proto, type Rule } from '../api'
import ProbeCell, { type ProbeState } from './ProbeCell'

const stateTag: Record<string, { color: string; text: string }> = {
  running: { color: 'green', text: '运行中' },
  applied: { color: 'green', text: '已生效' },
  stopped: { color: 'default', text: '已停用' },
  error: { color: 'red', text: '异常' },
}

const targetPattern = /^[A-Za-z0-9.-]+:\d{1,5}$/

type PortCheck = { loading: boolean; conflicts: Conflict[] | null }

function RuleModal({ rule, open, onClose, onSaved }: { rule: Rule | null; open: boolean; onClose: () => void; onSaved: () => void }) {
  const { message } = App.useApp()
  const [form] = Form.useForm<Rule>()
  const [saving, setSaving] = useState(false)
  const [check, setCheck] = useState<PortCheck>({ loading: false, conflicts: null })
  const proto = Form.useWatch('proto', form) as Proto | undefined
  const port = Form.useWatch('listen_port', form) as number | undefined
  const seq = useRef(0)

  useEffect(() => {
    if (!open) return
    form.resetFields()
    form.setFieldsValue(rule ?? { proto: 'tcp', enabled: true, name: '', target: '', remark: '' })
    setCheck({ loading: false, conflicts: null })
  }, [open, rule, form])

  // 端口实时冲突检查（防抖）
  useEffect(() => {
    if (!open || !proto || !port || port < 1 || port > 65535) {
      setCheck({ loading: false, conflicts: null })
      return
    }
    const id = ++seq.current
    setCheck((c) => ({ ...c, loading: true }))
    const t = setTimeout(async () => {
      try {
        const r = await api.checkPort(proto, port, rule?.id)
        if (id === seq.current) setCheck({ loading: false, conflicts: r.conflicts })
      } catch {
        if (id === seq.current) setCheck({ loading: false, conflicts: null })
      }
    }, 350)
    return () => clearTimeout(t)
  }, [open, proto, port, rule?.id])

  const submit = async () => {
    const v = await form.validateFields()
    setSaving(true)
    try {
      if (rule) await api.updateRule(rule.id, v)
      else await api.createRule(v)
      message.success(rule ? '已保存' : '已创建')
      onSaved()
      onClose()
    } catch (e) {
      message.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  let portHelp: React.ReactNode = '本机监听端口'
  let portStatus: '' | 'error' | 'success' | 'validating' = ''
  if (check.loading) {
    portHelp = '正在检查端口...'
    portStatus = 'validating'
  } else if (check.conflicts) {
    if (check.conflicts.length === 0) {
      portHelp = <Typography.Text type="success">端口可用</Typography.Text>
      portStatus = 'success'
    } else {
      portHelp = (
        <>
          {check.conflicts.map((c, i) => (
            <div key={i}>{c.message}</div>
          ))}
        </>
      )
      portStatus = 'error'
    }
  }

  return (
    <Modal
      open={open}
      title={rule ? '编辑规则' : '新建转发规则'}
      onCancel={onClose}
      onOk={submit}
      confirmLoading={saving}
      okText={rule ? '保存' : '创建'}
      destroyOnHidden
    >
      <Form form={form} layout="vertical" requiredMark="optional">
        <Form.Item name="name" label="名称">
          <Input placeholder="留空自动生成" maxLength={64} />
        </Form.Item>
        <Form.Item name="proto" label="协议" rules={[{ required: true }]}>
          <Radio.Group
            optionType="button"
            buttonStyle="solid"
            options={[
              { label: 'TCP', value: 'tcp' },
              { label: 'UDP', value: 'udp' },
              { label: 'TCP + UDP', value: 'both' },
            ]}
          />
        </Form.Item>
        <Space.Compact block style={{ alignItems: 'flex-start' }}>
          <Form.Item
            name="listen_port"
            label="监听端口"
            style={{ width: '40%' }}
            rules={[{ required: true, message: '请输入端口' }]}
            validateStatus={portStatus}
            help={portHelp}
            hasFeedback={portStatus !== ''}
          >
            <InputNumber min={1} max={65535} style={{ width: '100%' }} placeholder="如 8080" />
          </Form.Item>
          <Form.Item
            name="target"
            label="转发到"
            style={{ width: '60%', marginLeft: 8 }}
            rules={[
              { required: true, message: '请输入目标地址' },
              { pattern: targetPattern, message: '格式为 IP:端口 或 域名:端口' },
            ]}
          >
            <Input placeholder="10.0.0.5:80 或 example.com:80" className="mono" />
          </Form.Item>
        </Space.Compact>
        <Form.Item name="remark" label="备注">
          <Input.TextArea rows={2} maxLength={200} />
        </Form.Item>
        <Form.Item name="enabled" label="启用" valuePropName="checked">
          <Switch />
        </Form.Item>
      </Form>
    </Modal>
  )
}

export default function Rules() {
  const { message } = App.useApp()
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(false)
  const [editing, setEditing] = useState<Rule | null>(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [toggling, setToggling] = useState<string | null>(null)
  const [probes, setProbes] = useState<Record<string, ProbeState>>({})

  const probe = useCallback(async (id: string) => {
    setProbes((p) => ({ ...p, [id]: { ...p[id], loading: true, error: undefined } }))
    try {
      const result = await api.probeRule(id)
      setProbes((p) => ({ ...p, [id]: { loading: false, result } }))
    } catch (e) {
      setProbes((p) => ({ ...p, [id]: { loading: false, error: (e as Error).message } }))
    }
  }, [])

  // 规则变更后旧的检测结果不再有效
  const clearProbe = (id: string) =>
    setProbes((p) => {
      const { [id]: _, ...rest } = p
      return rest
    })

  const load = useCallback(
    async (quiet = false) => {
      if (!quiet) setLoading(true)
      try {
        setRules(await api.rules())
      } catch (e) {
        if (!quiet) message.error((e as Error).message)
      } finally {
        if (!quiet) setLoading(false)
      }
    },
    [message],
  )

  useEffect(() => {
    load()
    const t = setInterval(() => load(true), 5000)
    return () => clearInterval(t)
  }, [load])

  const toggle = async (r: Rule, enabled: boolean) => {
    setToggling(r.id)
    try {
      await api.toggleRule(r.id, enabled)
      clearProbe(r.id)
      await load(true)
    } catch (e) {
      message.error((e as Error).message)
    } finally {
      setToggling(null)
    }
  }

  const remove = async (r: Rule) => {
    try {
      await api.deleteRule(r.id)
      message.success('已删除')
      await load(true)
    } catch (e) {
      message.error((e as Error).message)
    }
  }

  const errors = rules.filter((r) => r.status?.state === 'error')

  return (
    <Card
      title="转发规则"
      extra={
        <Space>
          <Button icon={<ApiOutlined />} disabled={rules.length === 0} onClick={() => rules.forEach((r) => probe(r.id))}>
            全部检测
          </Button>
          <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading} />
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setEditing(null)
              setModalOpen(true)
            }}
          >
            新建规则
          </Button>
        </Space>
      }
    >
      {errors.length > 0 && (
        <Alert type="error" showIcon style={{ marginBottom: 16 }} title={`${errors.length} 条规则运行异常，鼠标悬停状态查看原因`} />
      )}
      <Table<Rule>
        rowKey="id"
        loading={loading}
        dataSource={rules}
        pagination={{ pageSize: 20, hideOnSinglePage: true }}
        scroll={{ x: 900 }}
        locale={{ emptyText: '暂无规则，点击右上角「新建规则」添加' }}
        columns={[
          {
            title: '名称',
            dataIndex: 'name',
            render: (n: string, r) => (
              <div>
                <b>{n}</b>
                {r.remark && (
                  <div>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {r.remark}
                    </Typography.Text>
                  </div>
                )}
              </div>
            ),
          },
          {
            title: '协议',
            dataIndex: 'proto',
            width: 110,
            filters: [
              { text: 'TCP', value: 'tcp' },
              { text: 'UDP', value: 'udp' },
              { text: 'TCP+UDP', value: 'both' },
            ],
            onFilter: (v, r) => r.proto === v,
            render: (p: Proto) => <Tag color={p === 'tcp' ? 'blue' : p === 'udp' ? 'purple' : 'cyan'}>{p === 'both' ? 'TCP+UDP' : p.toUpperCase()}</Tag>,
          },
          {
            title: '监听端口',
            dataIndex: 'listen_port',
            width: 110,
            sorter: (a, b) => a.listen_port - b.listen_port,
            render: (p: number) => <span className="mono">:{p}</span>,
          },
          {
            title: '目标',
            dataIndex: 'target',
            render: (t: string) => <span className="mono">{t}</span>,
          },
          {
            title: '连通性',
            width: 140,
            render: (_, r) => <ProbeCell state={probes[r.id]} onProbe={() => probe(r.id)} />,
          },
          {
            title: '状态',
            width: 100,
            render: (_, r) => {
              const s = r.status ?? { state: 'stopped' }
              const tag = stateTag[s.state] ?? stateTag.stopped
              const tip = s.message || (s.pids?.length ? `PID ${s.pids.join(', ')}${s.restarts ? `，已重启 ${s.restarts} 次` : ''}` : '')
              return (
                <Tooltip title={tip}>
                  <Tag color={tag.color}>{tag.text}</Tag>
                </Tooltip>
              )
            },
          },
          {
            title: '启用',
            dataIndex: 'enabled',
            width: 80,
            render: (e: boolean, r) => <Switch size="small" checked={e} loading={toggling === r.id} onChange={(v) => toggle(r, v)} />,
          },
          {
            title: '操作',
            width: 110,
            render: (_, r) => (
              <Space>
                <Button
                  size="small"
                  type="text"
                  icon={<EditOutlined />}
                  onClick={() => {
                    setEditing(r)
                    setModalOpen(true)
                  }}
                />
                <Popconfirm title={`删除规则「${r.name}」？`} okText="删除" okButtonProps={{ danger: true }} onConfirm={() => remove(r)}>
                  <Button size="small" type="text" danger icon={<DeleteOutlined />} />
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
      <RuleModal
        rule={editing}
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onSaved={() => {
          if (editing) clearProbe(editing.id)
          load(true)
        }}
      />
    </Card>
  )
}
