import { useCallback, useEffect, useState } from 'react'
import { Alert, App, Button, Card, Col, Descriptions, Modal, Row, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { CheckCircleFilled, CloseCircleFilled, DownloadOutlined, ReloadOutlined } from '@ant-design/icons'
import { api, backendLabels, type InstallResult, type SystemInfo, type Tool } from '../api'

export default function Dashboard() {
  const { message } = App.useApp()
  const [data, setData] = useState<SystemInfo | null>(null)
  const [loading, setLoading] = useState(false)
  const [installing, setInstalling] = useState<string | null>(null)
  const [result, setResult] = useState<InstallResult | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setData(await api.system())
    } catch (e) {
      message.error((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [message])

  useEffect(() => {
    load()
  }, [load])

  const install = async (tools: string[], key: string) => {
    setInstalling(key)
    try {
      const r = await api.install(tools)
      setResult(r)
      if (r.ok) message.success('安装完成')
      await load()
    } catch (e) {
      message.error((e as Error).message)
    } finally {
      setInstalling(null)
    }
  }

  if (!data) return <Card loading />
  const { info } = data
  const missing = info.tools.filter((t) => !t.installed)
  const backendTool = info.tools.find((t) => t.name === data.backend)

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      {data.sync_error && <Alert type="error" showIcon title="转发规则应用失败" description={data.sync_error} />}
      {backendTool && !backendTool.installed && (
        <Alert
          type="warning"
          showIcon
          title={`当前后端 ${data.backend} 依赖的工具未安装，转发规则不会生效，请先安装或在设置中切换后端。`}
        />
      )}
      {!info.is_root && <Alert type="warning" showIcon title="lport 未以 root 运行，内核转发后端与软件安装不可用。" />}

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={10}>
          <Card
            title="系统信息"
            extra={<Button type="text" icon={<ReloadOutlined />} loading={loading} onClick={load} />}
            style={{ height: '100%' }}
          >
            <Descriptions column={1} size="small">
              <Descriptions.Item label="系统">{info.os_name || info.os_id || '未知'}</Descriptions.Item>
              <Descriptions.Item label="内核">{info.kernel}</Descriptions.Item>
              <Descriptions.Item label="包管理器">{info.package_manager || '未识别'}</Descriptions.Item>
              <Descriptions.Item label="服务管理">{info.init_system}</Descriptions.Item>
              <Descriptions.Item label="IP 转发">
                {info.ip_forward ? <Tag color="green">已开启</Tag> : <Tag>未开启</Tag>}
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  内核后端启用时自动开启
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="当前后端">
                <Tag color="blue">{backendLabels[data.backend]}</Tag>
                {data.backend_mode === 'map' && <Tag color="green">map 查找模式</Tag>}
                {data.backend_mode === 'linear' && (
                  <Tooltip title="当前 nft 或内核版本不支持 map 方式 DNAT（需 nft ≥ 0.9.4、内核 ≥ 5.6），规则逐条匹配">
                    <Tag color="orange">兼容模式</Tag>
                  </Tooltip>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="管理地址">
                <span className="mono">{data.listen}</span>
              </Descriptions.Item>
              <Descriptions.Item label="配置文件">
                <Typography.Text className="mono" copyable>
                  {data.config_path}
                </Typography.Text>
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col xs={24} lg={14}>
          <Card
            title="依赖工具"
            style={{ height: '100%' }}
            extra={
              missing.length > 1 && (
                <Button
                  type="primary"
                  icon={<DownloadOutlined />}
                  loading={installing === 'all'}
                  disabled={!info.is_root || !info.package_manager || installing !== null}
                  onClick={() => install(missing.map((t) => t.name), 'all')}
                >
                  全部安装
                </Button>
              )
            }
          >
            <Table<Tool>
              rowKey="name"
              size="small"
              pagination={false}
              dataSource={info.tools}
              scroll={{ x: true }}
              columns={[
                {
                  title: '工具',
                  dataIndex: 'name',
                  render: (n: string, t) => (
                    <Space>
                      {t.installed ? (
                        <CheckCircleFilled style={{ color: '#52c41a' }} />
                      ) : (
                        <CloseCircleFilled style={{ color: '#ff4d4f' }} />
                      )}
                      <b>{n}</b>
                    </Space>
                  ),
                },
                {
                  title: '状态',
                  render: (_, t) =>
                    t.installed ? (
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {t.version || t.path}
                      </Typography.Text>
                    ) : (
                      <Tag color="red">未安装</Tag>
                    ),
                },
                {
                  title: '',
                  width: 100,
                  render: (_, t) =>
                    !t.installed && (
                      <Button
                        size="small"
                        icon={<DownloadOutlined />}
                        loading={installing === t.name}
                        disabled={!info.is_root || !info.package_manager || installing !== null}
                        onClick={() => install([t.name], t.name)}
                      >
                        安装
                      </Button>
                    ),
                },
              ]}
            />
            {info.install_command && (
              <div style={{ marginTop: 16 }}>
                <Typography.Text type="secondary">手动安装命令（{info.package_manager}）：</Typography.Text>
                <Typography.Paragraph copyable className="install-output" style={{ marginTop: 8, marginBottom: 0 }}>
                  {info.install_command}
                </Typography.Paragraph>
              </div>
            )}
            {!info.package_manager && missing.length > 0 && (
              <Alert type="warning" showIcon style={{ marginTop: 16 }} title="无法识别包管理器，请手动安装缺失工具。" />
            )}
          </Card>
        </Col>
      </Row>

      <Modal
        open={result !== null}
        title={result?.ok ? '安装成功' : '安装失败'}
        width={720}
        footer={<Button onClick={() => setResult(null)}>关闭</Button>}
        onCancel={() => setResult(null)}
      >
        {result?.error && <Alert type="error" showIcon title={result.error} style={{ marginBottom: 12 }} />}
        {result?.command && (
          <Typography.Paragraph>
            执行命令：<span className="mono">{result.command}</span>
          </Typography.Paragraph>
        )}
        <pre className="install-output">{result?.output || '(无输出)'}</pre>
      </Modal>
    </Space>
  )
}
