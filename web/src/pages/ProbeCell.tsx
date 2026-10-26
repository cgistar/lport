import type { ReactNode } from 'react'
import { Activity } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import type { ProbeItem, ProbeResult } from '../api'
import { tr, useI18n } from '../i18n'

export interface ProbeState {
  loading: boolean
  result?: ProbeResult
  error?: string
}

type Agg = ProbeItem['state']

const dotColor: Record<Agg | 'processing', string> = {
  ok: 'bg-emerald-500',
  fail: 'bg-red-500',
  unknown: 'bg-amber-500',
  skipped: 'bg-neutral-300',
  processing: 'bg-sky-500 animate-pulse',
}

function aggregate(items: ProbeItem[]): Agg {
  if (items.some((i) => i.state === 'fail')) return 'fail'
  if (items.every((i) => i.state === 'ok')) return 'ok'
  if (items.every((i) => i.state === 'skipped')) return 'skipped'
  return 'unknown'
}

function details(items: ProbeItem[], hint?: string) {
  return (
    <div className="flex max-w-sm flex-col gap-1">
      {items.map((i) => (
        <div key={i.proto}>
          {i.proto.toUpperCase()} <span className="font-mono">{i.addr}</span>
          {tr('common.colon')}
          {i.message}
          {i.state !== 'skipped' && i.state !== 'unknown' && ` · ${i.latency_ms}ms`}
        </div>
      ))}
      {hint && <div className="opacity-85">{hint}</div>}
      <div className="opacity-65">{tr('probe.retest')}</div>
    </div>
  )
}

function Dot({ label, status, tip, onClick }: { label: string; status: Agg | 'processing'; tip: ReactNode; onClick?: () => void }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="xs" onClick={onClick} className="font-normal">
          <span className={cn('size-1.5 rounded-full', dotColor[status])} />
          {label}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{tip}</TooltipContent>
    </Tooltip>
  )
}

/** 规则连通性检测：本机（经转发路径）与目标（直连）两个状态点。 */
export default function ProbeCell({ state, onProbe }: { state?: ProbeState; onProbe: () => void }) {
  const { t } = useI18n()
  if (!state || (!state.result && !state.loading && !state.error)) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="ghost" size="icon-xs" aria-label={t('probe.tooltip')} onClick={onProbe}>
            <Activity />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{t('probe.tooltip')}</TooltipContent>
      </Tooltip>
    )
  }
  if (state.error) {
    return <Dot label={t('probe.failed')} status="fail" tip={t('probe.failedTip', { error: state.error })} onClick={onProbe} />
  }
  if (state.loading || !state.result) {
    return (
      <div className="flex">
        <Dot label={t('probe.local')} status="processing" tip={t('probe.checking')} />
        <Dot label={t('probe.target')} status="processing" tip={t('probe.checking')} />
      </div>
    )
  }
  const local = aggregate(state.result.local)
  const target = aggregate(state.result.target)
  let localHint: string | undefined
  if (local === 'fail' && target === 'ok') localHint = t('probe.hintForwardFail')
  if (local === 'ok') localHint = t('probe.hintLocalOk')
  const targetHint = target === 'fail' ? t('probe.hintTargetFail') : undefined
  return (
    <div className="flex">
      <Dot label={t('probe.local')} status={local} tip={details(state.result.local, localHint)} onClick={onProbe} />
      <Dot label={t('probe.target')} status={target} tip={details(state.result.target, targetHint)} onClick={onProbe} />
    </div>
  )
}
