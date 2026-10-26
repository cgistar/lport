import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { Activity, ArrowDown, ArrowUp, ArrowUpDown, Filter, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import Notice from '@/components/notice'
import Pager, { clampPage } from '@/components/pager'
import { cn } from '@/lib/utils'
import { api, type Conflict, type Proto, type Rule, type RuleStatus } from '../api'
import { useI18n } from '../i18n'
import ProbeCell, { type ProbeState } from './ProbeCell'

const stateBadge: Record<RuleStatus['state'], string> = {
  running: 'bg-emerald-50 text-emerald-700',
  applied: 'bg-emerald-50 text-emerald-700',
  stopped: 'bg-muted text-muted-foreground',
  error: 'bg-red-50 text-red-700',
}

const protoBadge: Record<Proto, string> = {
  tcp: 'bg-sky-50 text-sky-700',
  udp: 'bg-violet-50 text-violet-700',
  both: 'bg-teal-50 text-teal-700',
}

const protoLabel: Record<Proto, string> = { tcp: 'TCP', udp: 'UDP', both: 'TCP+UDP' }

const targetPattern = /^[A-Za-z0-9.-]+:\d{1,5}$/

const pageSize = 20

type PortCheck = { loading: boolean; conflicts: Conflict[] | null }

interface FormValues {
  name: string
  proto: Proto
  listen_port: string
  target: string
  remark: string
  enabled: boolean
}

const emptyForm: FormValues = { name: '', proto: 'tcp', listen_port: '', target: '', remark: '', enabled: true }

function RuleDialog({ rule, open, onClose, onSaved }: { rule: Rule | null; open: boolean; onClose: () => void; onSaved: () => void }) {
  const { t } = useI18n()
  const [v, setV] = useState<FormValues>(emptyForm)
  const [submitted, setSubmitted] = useState(false)
  const [saving, setSaving] = useState(false)
  const [check, setCheck] = useState<PortCheck>({ loading: false, conflicts: null })
  const seq = useRef(0)
  const port = Number(v.listen_port)
  const portValid = Number.isInteger(port) && port >= 1 && port <= 65535

  useEffect(() => {
    if (!open) return
    setV(rule ? { ...rule, listen_port: String(rule.listen_port), remark: rule.remark ?? '' } : emptyForm)
    setSubmitted(false)
    setCheck({ loading: false, conflicts: null })
  }, [open, rule])

  // 端口实时冲突检查（防抖）
  useEffect(() => {
    if (!open || !portValid) {
      setCheck({ loading: false, conflicts: null })
      return
    }
    const id = ++seq.current
    setCheck((c) => ({ ...c, loading: true }))
    const timer = setTimeout(async () => {
      try {
        const r = await api.checkPort(v.proto, port, rule?.id)
        if (id === seq.current) setCheck({ loading: false, conflicts: r.conflicts })
      } catch {
        if (id === seq.current) setCheck({ loading: false, conflicts: null })
      }
    }, 350)
    return () => clearTimeout(timer)
  }, [open, v.proto, port, portValid, rule?.id])

  const set = <K extends keyof FormValues>(k: K, val: FormValues[K]) => setV((s) => ({ ...s, [k]: val }))

  const portError = !v.listen_port ? t('rules.portRequired') : !portValid ? t('rules.portRange') : ''
  const targetError = !v.target.trim() ? t('rules.targetRequired') : !targetPattern.test(v.target.trim()) ? t('rules.targetFormat') : ''

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setSubmitted(true)
    if (portError || targetError) return
    setSaving(true)
    const body = { ...v, listen_port: port, target: v.target.trim() }
    try {
      if (rule) await api.updateRule(rule.id, body)
      else await api.createRule(body)
      toast.success(rule ? t('rules.saved') : t('rules.created'))
      onSaved()
      onClose()
    } catch (err) {
      toast.error((err as Error).message)
    } finally {
      setSaving(false)
    }
  }

  let portHelp = <FieldDescription>{t('rules.portHelp')}</FieldDescription>
  if (submitted && portError) {
    portHelp = <FieldError>{portError}</FieldError>
  } else if (check.loading) {
    portHelp = <FieldDescription>{t('rules.portChecking')}</FieldDescription>
  } else if (check.conflicts?.length === 0) {
    portHelp = <FieldDescription className="text-emerald-600">{t('rules.portFree')}</FieldDescription>
  } else if (check.conflicts) {
    portHelp = <FieldError errors={check.conflicts} />
  }
  const portInvalid = (submitted && !!portError) || !!check.conflicts?.length

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <form onSubmit={submit} noValidate className="flex flex-col gap-6">
          <DialogHeader>
            <DialogTitle>{rule ? t('rules.edit') : t('rules.new')}</DialogTitle>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="rule-name">{t('rules.name')}</FieldLabel>
              <Input id="rule-name" maxLength={64} placeholder={t('rules.namePlaceholder')} value={v.name} onChange={(e) => set('name', e.target.value)} />
            </Field>
            <Field>
              <FieldLabel>{t('rules.proto')}</FieldLabel>
              <ToggleGroup type="single" variant="outline" value={v.proto} onValueChange={(p) => p && set('proto', p as Proto)} className="justify-start">
                {(['tcp', 'udp', 'both'] as const).map((p) => (
                  <ToggleGroupItem key={p} value={p} className="data-[state=on]:bg-primary data-[state=on]:text-primary-foreground">
                    {p === 'both' ? 'TCP + UDP' : p.toUpperCase()}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
            </Field>
            <div className="grid gap-4 sm:grid-cols-[2fr_3fr]">
              <Field data-invalid={portInvalid}>
                <FieldLabel htmlFor="rule-port">{t('rules.listenPort')}</FieldLabel>
                <Input
                  id="rule-port"
                  inputMode="numeric"
                  placeholder={t('rules.portPlaceholder')}
                  value={v.listen_port}
                  aria-invalid={portInvalid}
                  onChange={(e) => set('listen_port', e.target.value.replace(/\D/g, '').slice(0, 5))}
                />
                {portHelp}
              </Field>
              <Field data-invalid={submitted && !!targetError}>
                <FieldLabel htmlFor="rule-target">{t('rules.forwardTo')}</FieldLabel>
                <Input
                  id="rule-target"
                  className="font-mono"
                  placeholder={t('rules.targetPlaceholder')}
                  value={v.target}
                  aria-invalid={submitted && !!targetError}
                  onChange={(e) => set('target', e.target.value)}
                />
                {submitted && targetError && <FieldError>{targetError}</FieldError>}
              </Field>
            </div>
            <Field>
              <FieldLabel htmlFor="rule-remark">{t('rules.remark')}</FieldLabel>
              <Textarea id="rule-remark" rows={2} maxLength={200} value={v.remark} onChange={(e) => set('remark', e.target.value)} />
            </Field>
            <Field orientation="horizontal">
              <Switch id="rule-enabled" checked={v.enabled} onCheckedChange={(c) => set('enabled', c)} />
              <FieldLabel htmlFor="rule-enabled">{t('rules.enabled')}</FieldLabel>
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" disabled={saving}>
              {saving && <Spinner />}
              {rule ? t('common.save') : t('common.create')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default function Rules() {
  const { t } = useI18n()
  const [rules, setRules] = useState<Rule[]>([])
  const [loading, setLoading] = useState(false)
  const [editing, setEditing] = useState<Rule | null>(null)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [deleting, setDeleting] = useState<Rule | null>(null)
  const [toggling, setToggling] = useState<string | null>(null)
  const [probes, setProbes] = useState<Record<string, ProbeState>>({})
  const [protoFilter, setProtoFilter] = useState<Proto | 'all'>('all')
  const [portSort, setPortSort] = useState<'asc' | 'desc' | null>(null)
  const [page, setPage] = useState(1)

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

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    try {
      setRules(await api.rules())
    } catch (e) {
      if (!quiet) toast.error((e as Error).message)
    } finally {
      if (!quiet) setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const timer = setInterval(() => load(true), 5000)
    return () => clearInterval(timer)
  }, [load])

  const toggle = async (r: Rule, enabled: boolean) => {
    setToggling(r.id)
    try {
      await api.toggleRule(r.id, enabled)
      clearProbe(r.id)
      await load(true)
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setToggling(null)
    }
  }

  const remove = async (r: Rule) => {
    try {
      await api.deleteRule(r.id)
      toast.success(t('rules.deleted'))
      await load(true)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const view = useMemo(() => {
    const list = protoFilter === 'all' ? rules : rules.filter((r) => r.proto === protoFilter)
    if (!portSort) return list
    return [...list].sort((a, b) => (portSort === 'asc' ? a.listen_port - b.listen_port : b.listen_port - a.listen_port))
  }, [rules, protoFilter, portSort])
  const current = clampPage(page, pageSize, view.length)
  const pageRows = view.slice((current - 1) * pageSize, current * pageSize)

  const errors = rules.filter((r) => r.status?.state === 'error')
  const SortIcon = portSort === 'asc' ? ArrowUp : portSort === 'desc' ? ArrowDown : ArrowUpDown

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('rules.title')}</CardTitle>
        <CardAction className="flex gap-2">
          <Button variant="outline" disabled={rules.length === 0} onClick={() => rules.forEach((r) => probe(r.id))}>
            <Activity />
            <span className="hidden sm:inline">{t('rules.probeAll')}</span>
          </Button>
          <Button variant="outline" size="icon" aria-label={t('common.refresh')} disabled={loading} onClick={() => load()}>
            {loading ? <Spinner /> : <RefreshCw />}
          </Button>
          <Button
            onClick={() => {
              setEditing(null)
              setDialogOpen(true)
            }}
          >
            <Plus />
            {t('rules.newButton')}
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {errors.length > 0 && <Notice type="error" title={t('rules.errorCount', { n: errors.length })} />}
        <Table className="min-w-[860px]">
          <TableHeader>
            <TableRow>
              <TableHead>{t('rules.name')}</TableHead>
              <TableHead className="w-32">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="sm" className="-ml-2.5 text-sm">
                      {t('rules.proto')}
                      <Filter className={cn(protoFilter !== 'all' && 'text-foreground fill-current')} />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start">
                    <DropdownMenuRadioGroup
                      value={protoFilter}
                      onValueChange={(f) => {
                        setProtoFilter(f as Proto | 'all')
                        setPage(1)
                      }}
                    >
                      <DropdownMenuRadioItem value="all">{t('common.all')}</DropdownMenuRadioItem>
                      {(Object.keys(protoLabel) as Proto[]).map((p) => (
                        <DropdownMenuRadioItem key={p} value={p}>
                          {protoLabel[p]}
                        </DropdownMenuRadioItem>
                      ))}
                    </DropdownMenuRadioGroup>
                  </DropdownMenuContent>
                </DropdownMenu>
              </TableHead>
              <TableHead className="w-32">
                <Button
                  variant="ghost"
                  size="sm"
                  className="-ml-2.5 text-sm"
                  onClick={() => setPortSort((s) => (s === null ? 'asc' : s === 'asc' ? 'desc' : null))}
                >
                  {t('rules.listenPort')}
                  <SortIcon className={cn(!portSort && 'text-muted-foreground')} />
                </Button>
              </TableHead>
              <TableHead>{t('rules.target')}</TableHead>
              <TableHead className="w-40">{t('rules.connectivity')}</TableHead>
              <TableHead className="w-24">{t('rules.status')}</TableHead>
              <TableHead className="w-20">{t('rules.enabled')}</TableHead>
              <TableHead className="w-24">{t('rules.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {pageRows.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center text-muted-foreground">
                  {loading ? <Spinner className="mx-auto" /> : t('rules.empty')}
                </TableCell>
              </TableRow>
            )}
            {pageRows.map((r) => {
              const s = r.status ?? { state: 'stopped' as const }
              const state = s.state in stateBadge ? s.state : 'stopped'
              const tip =
                s.message || (s.pids?.length ? `PID ${s.pids.join(', ')}${s.restarts ? t('rules.restarts', { n: s.restarts }) : ''}` : '')
              const badge = <Badge className={stateBadge[state]}>{t(`state.${state}`)}</Badge>
              return (
                <TableRow key={r.id}>
                  <TableCell className="whitespace-normal">
                    <div className="font-medium">{r.name}</div>
                    {r.remark && <div className="text-xs text-muted-foreground">{r.remark}</div>}
                  </TableCell>
                  <TableCell>
                    <Badge className={protoBadge[r.proto]}>{protoLabel[r.proto]}</Badge>
                  </TableCell>
                  <TableCell className="font-mono">:{r.listen_port}</TableCell>
                  <TableCell className="font-mono">{r.target}</TableCell>
                  <TableCell>
                    <ProbeCell state={probes[r.id]} onProbe={() => probe(r.id)} />
                  </TableCell>
                  <TableCell>
                    {tip ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="cursor-default">{badge}</span>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-sm">{tip}</TooltipContent>
                      </Tooltip>
                    ) : (
                      badge
                    )}
                  </TableCell>
                  <TableCell>
                    <Switch checked={r.enabled} disabled={toggling === r.id} onCheckedChange={(c) => toggle(r, c)} />
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={t('common.edit')}
                        onClick={() => {
                          setEditing(r)
                          setDialogOpen(true)
                        }}
                      >
                        <Pencil />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={t('common.delete')}
                        className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                        onClick={() => setDeleting(r)}
                      >
                        <Trash2 />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
        <Pager page={current} pageSize={pageSize} total={view.length} onChange={setPage} />
      </CardContent>

      <RuleDialog
        rule={editing}
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        onSaved={() => {
          if (editing) clearProbe(editing.id)
          load(true)
        }}
      />
      <AlertDialog open={deleting !== null} onOpenChange={(o) => !o && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('rules.confirmDelete', { name: deleting?.name ?? '' })}</AlertDialogTitle>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => deleting && remove(deleting)}>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}
