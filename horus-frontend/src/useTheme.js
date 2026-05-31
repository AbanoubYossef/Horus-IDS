import { useState, useEffect } from 'react'

const stored = localStorage.getItem('horus-theme') || 'light'
document.documentElement.setAttribute('data-theme', stored)

export function useTheme() {
  const [theme, setTheme] = useState(stored)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('horus-theme', theme)
  }, [theme])

  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark')

  return [theme, toggle]
}
