import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'

/** 简单分页：只有一页时不显示。page 从 1 开始。 */
export default function Pager({
  page,
  pageSize,
  total,
  onChange,
}: {
  page: number
  pageSize: number
  total: number
  onChange: (page: number) => void
}) {
  const { t } = useI18n()
  const pages = Math.ceil(total / pageSize)
  if (pages <= 1) return null
  const from = (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, total)
  return (
    <div className="flex items-center justify-end gap-2 pt-3 text-sm text-muted-foreground">
      <span>{t('common.range', { from, to, total })}</span>
      <Button variant="outline" size="icon-sm" aria-label={t('common.previous')} disabled={page <= 1} onClick={() => onChange(page - 1)}>
        <ChevronLeft />
      </Button>
      <Button variant="outline" size="icon-sm" aria-label={t('common.next')} disabled={page >= pages} onClick={() => onChange(page + 1)}>
        <ChevronRight />
      </Button>
    </div>
  )
}

/** 数据变化后页码可能越界，夹到有效范围。 */
export function clampPage(page: number, pageSize: number, total: number) {
  return Math.min(page, Math.max(1, Math.ceil(total / pageSize)))
}
