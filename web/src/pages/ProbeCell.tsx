import { Badge, Button, Space, Tooltip } from 'antd'
import { ApiOutlined } from '@ant-design/icons'
import type { ProbeItem, ProbeResult } from '../api'

export interface ProbeState {
  loading: boolean
  result?: ProbeResult
  error?: string
}

type Agg = ProbeItem['state']

const badgeStatus: Record<Agg, 'success' | 'error' | 'warning' | 'default'> = {
  ok: 'success',
  fail: 'error',
  unknown: 'warning',
  skipped: 'default',
}

function aggregate(items: ProbeItem[]): Agg {
  if (items.some((i) => i.state === 'fail')) return 'fail'
  if (items.every((i) => i.state === 'ok')) return 'ok'
  if (items.every((i) => i.state === 'skipped')) return 'skipped'
  return 'unknown'
}

function details(items: ProbeItem[], hint?: string) {
  return (
    <div>
      {items.map((i) => (
        <div key={i.proto}>
          {i.proto.toUpperCase()} <span className="mono">{i.addr}</span>：{i.message}
          {i.state !== 'skipped' && i.state !== 'unknown' && ` · ${i.latency_ms}ms`}
        </div>
      ))}
      {hint && <div style={{ marginTop: 4, opacity: 0.85 }}>{hint}</div>}
      <div style={{ marginTop: 4, opacity: 0.65 }}>点击重新检测</div>
    </div>
  )
}

function Dot({ label, status, tip, onClick }: { label: string; status: Agg | 'processing'; tip: React.ReactNode; onClick: () => void }) {
  return (
    <Tooltip title={tip}>
      <Button type="text" size="small" onClick={onClick} style={{ paddingInline: 4 }}>
        <Badge status={status === 'processing' ? 'processing' : badgeStatus[status]} text={label} />
      </Button>
    </Tooltip>
  )
}

/** 规则连通性检测：本机（经转发路径）与目标（直连）两个状态点。 */
export default function ProbeCell({ state, onProbe }: { state?: ProbeState; onProbe: () => void }) {
  if (!state || (!state.result && !state.loading && !state.error)) {
    return (
      <Tooltip title="检测本机监听端口与目标端口的连通性">
        <Button type="text" size="small" icon={<ApiOutlined />} onClick={onProbe} />
      </Tooltip>
    )
  }
  if (state.error) {
    return <Dot label="检测失败" status="fail" tip={`${state.error}，点击重试`} onClick={onProbe} />
  }
  if (state.loading || !state.result) {
    return (
      <Space size={0}>
        <Dot label="本机" status="processing" tip="检测中..." onClick={() => {}} />
        <Dot label="目标" status="processing" tip="检测中..." onClick={() => {}} />
      </Space>
    )
  }
  const local = aggregate(state.result.local)
  const target = aggregate(state.result.target)
  let localHint: string | undefined
  if (local === 'fail' && target === 'ok') localHint = '目标可达但经本机转发失败：请检查规则状态、转发后端与防火墙。'
  if (local === 'ok') localHint = '本机检测不经过 FORWARD 链；若外部仍无法访问，请检查云安全组与 FORWARD 防火墙规则。'
  const targetHint = target === 'fail' ? '本机无法直连目标：目标服务未启动、地址错误或目标防火墙拦截。' : undefined
  return (
    <Space size={0}>
      <Dot label="本机" status={local} tip={details(state.result.local, localHint)} onClick={onProbe} />
      <Dot label="目标" status={target} tip={details(state.result.target, targetHint)} onClick={onProbe} />
    </Space>
  )
}
