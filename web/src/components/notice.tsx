import type { ReactNode } from 'react'
import { CircleAlert, Info, TriangleAlert } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { cn } from '@/lib/utils'

const styles = {
  info: { icon: Info, className: 'border-sky-200 bg-sky-50 text-sky-900' },
  warning: { icon: TriangleAlert, className: 'border-amber-200 bg-amber-50 text-amber-900' },
  error: { icon: CircleAlert, className: 'border-red-200 bg-red-50 text-red-900' },
}

/** 页面内的提示条：信息 / 警告 / 错误。 */
export default function Notice({
  type,
  title,
  children,
  className,
}: {
  type: keyof typeof styles
  title: ReactNode
  children?: ReactNode
  className?: string
}) {
  const { icon: Icon, className: color } = styles[type]
  return (
    <Alert className={cn(color, className)}>
      <Icon />
      <AlertTitle className="font-normal">{title}</AlertTitle>
      {children && <AlertDescription className="text-current/80 whitespace-pre-wrap">{children}</AlertDescription>}
    </Alert>
  )
}
