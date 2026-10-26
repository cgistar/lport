import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import App from './App'
import { I18nProvider } from './i18n'
import './style.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <I18nProvider>
      <TooltipProvider delayDuration={200}>
        <App />
        <Toaster position="top-center" richColors />
      </TooltipProvider>
    </I18nProvider>
  </StrictMode>,
)
