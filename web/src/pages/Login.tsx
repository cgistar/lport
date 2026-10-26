import { useState, type FormEvent } from 'react'
import { ArrowLeftRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Field, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import Notice from '@/components/notice'
import { api } from '../api'
import { useI18n } from '../i18n'
import LangSwitch from '../LangSwitch'

export default function Login({ onLogin }: { onLogin: (user: string) => void }) {
  const { t } = useI18n()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [touched, setTouched] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setTouched(true)
    if (!username || !password) return
    setLoading(true)
    setError('')
    try {
      const r = await api.login(username, password)
      onLogin(r.username)
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40 p-4">
      <div className="fixed top-3 right-4">
        <LangSwitch />
      </div>
      <Card className="w-full max-w-sm">
        <CardHeader className="items-center text-center">
          <ArrowLeftRight className="mx-auto size-8" />
          <CardTitle className="text-lg">{t('login.title')}</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} noValidate>
            <FieldGroup>
              {error && <Notice type="error" title={error} />}
              <Field data-invalid={touched && !username}>
                <FieldLabel htmlFor="username">{t('login.username')}</FieldLabel>
                <Input
                  id="username"
                  autoComplete="username"
                  value={username}
                  aria-invalid={touched && !username}
                  onChange={(e) => setUsername(e.target.value)}
                />
                {touched && !username && <FieldError>{t('login.usernameRequired')}</FieldError>}
              </Field>
              <Field data-invalid={touched && !password}>
                <FieldLabel htmlFor="password">{t('login.password')}</FieldLabel>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  autoFocus
                  value={password}
                  aria-invalid={touched && !password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                {touched && !password && <FieldError>{t('login.passwordRequired')}</FieldError>}
              </Field>
              <Button type="submit" size="lg" disabled={loading}>
                {loading && <Spinner />}
                {t('login.submit')}
              </Button>
            </FieldGroup>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
