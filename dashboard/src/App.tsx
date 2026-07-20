import { useState } from 'react'
import Login from './components/Login'
import Layout from './components/Layout'

function App() {
  const [token, setToken] = useState<string | null>(
    () => sessionStorage.getItem('rampart_token')
  )

  if (!token) {
    return <Login onLogin={(t) => setToken(t)} />
  }

  return <Layout />
}

export default App
