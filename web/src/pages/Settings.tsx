import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { RefreshCw, Search } from 'lucide-react'
import { toast } from 'sonner'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Field, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import Notice from '@/components/notice'
import Pager, { clampPage } from '@/components/pager'
import { cn } from '@/lib/utils'
import { api, toolForBackend, type Backend, type Listener, type Settings as S, type Tool } from '../api'
import { useI18n } from '../i18n'

function BackendCard() {
  const { t } = useI18n()
  const [settings, setSettings] = useState<S | null>(null)
  const [tools, setTools] = useState<Tool[]>([])
  const [pending, setPending] = useState<Backend | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    api.settings().then(setSettings).catch((e) => toast.error(e.message))
    api.system().then((s) => setTools(s.info.tools)).catch(() => {})
  }, [])

  const installed = (b: Backend) =>
    toolForBackend[b] === null || (tools.find((tool) => tool.name === toolForBackend[b])?.installed ?? false)

  const confirm = async () => {
    if (!pending) return
    const b = pending
    setPending(null)
    setSaving(true)
    try {
      setSettings(await api.setBackend(b))
      toast.success(t('settings.switched', { backend: b }))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>{t('settings.backend')}</CardTitle>
        {saving && (
          <CardAction>
            <Spinner />
          </CardAction>
        )}
      </CardHeader>
      <CardContent>
        {!settings ? (
          <Skeleton className="h-48" />
        ) : (
          <RadioGroup value={settings.backend} disabled={saving} onValueChange={(b) => setPending(b as Backend)} className="gap-2">
            {settings.backends.map((b) => (
              <Label
                key={b}
                htmlFor={`backend-${b}`}
                className={cn(
                  'flex items-start gap-3 rounded-lg border p-3 font-normal transition-colors has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-muted/50',
                  installed(b) ? 'cursor-pointer hover:bg-muted/30' : 'opacity-60',
                )}
              >
                <RadioGroupItem id={`backend-${b}`} value={b} disabled={!installed(b)} className="mt-0.5" />
                <div className="flex flex-col gap-1">
                  <div className="flex flex-wrap items-center gap-2 font-medium">
                    {t(`backend.${b}`)}
                    {b === 'nftables' && <Badge className="bg-emerald-50 text-emerald-700">{t('settings.recommended')}</Badge>}
                    {!installed(b) && <Badge variant="destructive">{t('common.notInstalled')}</Badge>}
                  </div>
                  <p className="text-xs leading-relaxed text-muted-foreground">{t(`settings.desc.${b}`)}</p>
                </div>
              </Label>
            ))}
          </RadioGroup>
        )}
      </CardContent>
      <AlertDialog open={pending !== null} onOpenChange={(o) => !o && setPending(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('settings.switchTitle', { backend: pending ?? '' })}</AlertDialogTitle>
            <AlertDialogDescription>{t('settings.switchContent')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={confirm}>{t('common.confirm')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}

function PasswordCard() {
  const { t } = useI18n()
  const [v, setV] = useState({ old: '', next: '', confirm: '' })
  const [submitted, setSubmitted] = useState(false)
  const [saving, setSaving] = useState(false)

  const errors = {
    old: !v.old ? t('common.required') : '',
    next: !v.next ? t('common.required') : v.next.length < 6 ? t('settings.minLength') : '',
    confirm: !v.confirm ? t('common.required') : v.confirm !== v.next ? t('settings.mismatch') : '',
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setSubmitted(true)
    if (errors.old || errors.next || errors.confirm) return
    setSaving(true)
    try {
      await api.changePassword(v.old, v.next)
      toast.success(t('settings.passwordChanged'))
      setV({ old: '', next: '', confirm: '' })
      setSubmitted(false)
      setTimeout(() => window.dispatchEvent(new Event('lport:unauthorized')), 800)
    } catch (err) {
      toast.error((err as Error).message)
    } finally {
      setSaving(false)
    }
  }

  const fields = [
    { key: 'old', label: t('settings.oldPassword'), autoComplete: 'current-password' },
    { key: 'next', label: t('settings.newPassword'), autoComplete: 'new-password' },
    { key: 'confirm', label: t('settings.confirmPassword'), autoComplete: 'new-password' },
  ] as const

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>{t('settings.password')}</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} noValidate>
          <FieldGroup>
            {fields.map(({ key, label, autoComplete }) => {
              const invalid = submitted && !!errors[key]
              return (
                <Field key={key} data-invalid={invalid}>
                  <FieldLabel htmlFor={`pw-${key}`}>{label}</FieldLabel>
                  <Input
                    id={`pw-${key}`}
                    type="password"
                    autoComplete={autoComplete}
                    value={v[key]}
                    aria-invalid={invalid}
                    onChange={(e) => setV((s) => ({ ...s, [key]: e.target.value }))}
                  />
                  {invalid && <FieldError>{errors[key]}</FieldError>}
                </Field>
              )
            })}
            <div>
              <Button type="submit" disabled={saving}>
                {saving && <Spinner />}
                {t('settings.password')}
              </Button>
            </div>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  )
}

const pageSize = 15

function ListeningCard() {
  const { t } = useI18n()
  const [data, setData] = useState<Listener[]>([])
  const [loading, setLoading] = useState(false)
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setData(await api.listening())
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const filtered = useMemo(
    () => (q ? data.filter((l) => String(l.port).includes(q) || (l.process ?? '').includes(q)) : data),
    [data, q],
  )
  const current = clampPage(page, pageSize, filtered.length)

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('settings.listening')}</CardTitle>
        <CardAction className="flex gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder={t('settings.search')}
              className="w-40 pl-8 sm:w-52"
              value={q}
              onChange={(e) => {
                setQ(e.target.value)
                setPage(1)
              }}
            />
          </div>
          <Button variant="outline" size="icon" aria-label={t('common.refresh')} disabled={loading} onClick={load}>
            {loading ? <Spinner /> : <RefreshCw />}
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-24">{t('settings.proto')}</TableHead>
              <TableHead className="w-24">{t('settings.port')}</TableHead>
              <TableHead>{t('settings.address')}</TableHead>
              <TableHead>{t('settings.process')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.slice((current - 1) * pageSize, current * pageSize).map((l) => (
              <TableRow key={`${l.proto}-${l.addr}-${l.port}-${l.pid ?? ''}`}>
                <TableCell>
                  <Badge variant="secondary">{l.proto.toUpperCase()}</Badge>
                </TableCell>
                <TableCell className="font-mono">{l.port}</TableCell>
                <TableCell className="font-mono">{l.addr}</TableCell>
                <TableCell>{l.process ? `${l.process} (${l.pid})` : '-'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <Pager page={current} pageSize={pageSize} total={filtered.length} onChange={setPage} />
      </CardContent>
    </Card>
  )
}

export default function Settings() {
  const { t } = useI18n()
  return (
    <div className="flex flex-col gap-4">
      <Notice type="info" title={t('settings.configNote')} />
      <div className="grid gap-4 lg:grid-cols-[7fr_5fr]">
        <BackendCard />
        <PasswordCard />
      </div>
      <ListeningCard />
    </div>
  )
}
