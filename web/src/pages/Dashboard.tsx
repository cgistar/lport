import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { CircleCheck, CircleX, Download, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import CopyButton from '@/components/copy-button'
import Notice from '@/components/notice'
import { api, type InstallResult, type SystemInfo, type Tool } from '../api'
import { useI18n } from '../i18n'

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[8.5rem_1fr] items-center gap-2 py-1.5 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="flex min-w-0 flex-wrap items-center gap-2">{children}</dd>
    </div>
  )
}

export default function Dashboard() {
  const { t } = useI18n()
  const [data, setData] = useState<SystemInfo | null>(null)
  const [loading, setLoading] = useState(false)
  const [installing, setInstalling] = useState<string | null>(null)
  const [result, setResult] = useState<InstallResult | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setData(await api.system())
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const install = async (tools: string[], key: string) => {
    setInstalling(key)
    try {
      const r = await api.install(tools)
      setResult(r)
      if (r.ok) toast.success(t('dash.installDone'))
      await load()
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setInstalling(null)
    }
  }

  if (!data) {
    return (
      <div className="grid gap-4 lg:grid-cols-[5fr_7fr]">
        <Skeleton className="h-80 rounded-xl" />
        <Skeleton className="h-80 rounded-xl" />
      </div>
    )
  }
  const { info } = data
  const missing = info.tools.filter((tool) => !tool.installed)
  const backendTool = info.tools.find((tool) => tool.name === data.backend)
  // 没有 package 的工具（realm）从发布页下载，不依赖包管理器
  const canInstall = (tool: Tool) => info.is_root && installing === null && (!!info.package_manager || !tool.package)

  return (
    <div className="flex flex-col gap-4">
      {data.sync_error && (
        <Notice type="error" title={t('dash.syncError')}>
          {data.sync_error}
        </Notice>
      )}
      {backendTool && !backendTool.installed && <Notice type="warning" title={t('dash.backendMissing', { backend: data.backend })} />}
      {!info.is_root && <Notice type="warning" title={t('dash.notRoot')} />}

      <div className="grid gap-4 lg:grid-cols-[5fr_7fr]">
        <Card>
          <CardHeader>
            <CardTitle>{t('dash.system')}</CardTitle>
            <CardAction>
              <Button variant="ghost" size="icon-sm" aria-label={t('common.refresh')} disabled={loading} onClick={load}>
                {loading ? <Spinner /> : <RefreshCw />}
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <dl>
              <Row label={t('dash.os')}>{info.os_name || info.os_id || t('dash.unknown')}</Row>
              <Row label={t('dash.kernel')}>{info.kernel}</Row>
              <Row label={t('dash.packageManager')}>{info.package_manager || t('dash.notDetected')}</Row>
              <Row label={t('dash.initSystem')}>{info.init_system}</Row>
              <Row label={t('dash.ipForward')}>
                {info.ip_forward ? (
                  <Badge className="bg-emerald-50 text-emerald-700">{t('dash.on')}</Badge>
                ) : (
                  <Badge variant="secondary">{t('dash.off')}</Badge>
                )}
                <span className="text-xs text-muted-foreground">{t('dash.ipForwardHint')}</span>
              </Row>
              <Row label={t('dash.backend')}>
                <Badge variant="outline">{t(`backend.${data.backend}`)}</Badge>
                {data.backend_mode === 'map' && <Badge className="bg-emerald-50 text-emerald-700">{t('dash.mapMode')}</Badge>}
                {data.backend_mode === 'linear' && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Badge className="bg-amber-50 text-amber-700">{t('dash.linearMode')}</Badge>
                    </TooltipTrigger>
                    <TooltipContent className="max-w-xs">{t('dash.linearTip')}</TooltipContent>
                  </Tooltip>
                )}
              </Row>
              <Row label={t('dash.listen')}>
                <span className="font-mono">{data.listen}</span>
              </Row>
              <Row label={t('dash.config')}>
                <span className="font-mono break-all">{data.config_path}</span>
                <CopyButton text={data.config_path} />
              </Row>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t('dash.tools')}</CardTitle>
            {missing.length > 1 && (
              <CardAction>
                <Button disabled={!missing.every(canInstall)} onClick={() => install(missing.map((tool) => tool.name), 'all')}>
                  {installing === 'all' ? <Spinner /> : <Download />}
                  {t('dash.installAll')}
                </Button>
              </CardAction>
            )}
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('dash.tool')}</TableHead>
                  <TableHead>{t('dash.status')}</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {info.tools.map((tool) => (
                  <TableRow key={tool.name}>
                    <TableCell>
                      <span className="flex items-center gap-2 font-medium">
                        {tool.installed ? <CircleCheck className="size-4 text-emerald-600" /> : <CircleX className="size-4 text-red-500" />}
                        {tool.name}
                      </span>
                    </TableCell>
                    <TableCell className="whitespace-normal">
                      {tool.installed ? (
                        <span className="text-xs text-muted-foreground">{tool.version || tool.path}</span>
                      ) : (
                        <Badge variant="destructive">{t('common.notInstalled')}</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {!tool.installed && (
                        <Button size="sm" variant="outline" disabled={!canInstall(tool)} onClick={() => install([tool.name], tool.name)}>
                          {installing === tool.name ? <Spinner /> : <Download />}
                          {t('dash.install')}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {info.install_command && (
              <div className="flex flex-col gap-2">
                <span className="text-sm text-muted-foreground">{t('dash.manualCommand', { pm: info.package_manager || 'shell' })}</span>
                <div className="flex items-start gap-2 rounded-lg bg-neutral-900 p-3 font-mono text-xs break-all text-neutral-100">
                  <span className="flex-1">{info.install_command}</span>
                  <CopyButton text={info.install_command} className="text-neutral-300 hover:bg-neutral-800 hover:text-white" />
                </div>
              </div>
            )}
            {!info.package_manager && missing.some((tool) => tool.package) && <Notice type="warning" title={t('dash.noPackageManager')} />}
          </CardContent>
        </Card>
      </div>

      <Dialog open={result !== null} onOpenChange={(open) => !open && setResult(null)}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{result?.ok ? t('dash.installOk') : t('dash.installFailed')}</DialogTitle>
          </DialogHeader>
          {result?.error && <Notice type="error" title={result.error} />}
          {result?.command && (
            <p className="text-sm">
              {t('dash.command')}
              <span className="font-mono">{result.command}</span>
            </p>
          )}
          <pre className="max-h-96 overflow-auto rounded-lg bg-neutral-900 p-3 text-xs break-all whitespace-pre-wrap text-neutral-100">
            {result?.output || t('dash.noOutput')}
          </pre>
          <DialogFooter>
            <Button variant="outline" onClick={() => setResult(null)}>
              {t('common.close')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
