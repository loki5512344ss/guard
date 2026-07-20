import { useState, useEffect } from 'react'
import { fetchServers, type Server } from '../api'

function Servers() {
  const [servers, setServers] = useState<Server[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const data = await fetchServers()
        if (!cancelled) {
          setServers(data)
          setError('')
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load servers')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    const interval = setInterval(load, 10000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  if (loading) return <div className="spinner" />

  return (
    <>
      <h1>Servers</h1>
      {error && <div className="error-msg">{error}</div>}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>IP:Port</th>
              <th>Status</th>
              <th>Online/Max</th>
              <th>TPS</th>
              <th>Last Heartbeat</th>
            </tr>
          </thead>
          <tbody>
            {servers.length === 0 && (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                  No servers found
                </td>
              </tr>
            )}
            {servers.map((s) => (
              <tr key={s.name}>
                <td>{s.name}</td>
                <td>{s.server_type}</td>
                <td>{s.ip}:{s.port}</td>
                <td>
                  <span className="status-badge">
                    <span className={`status-dot ${s.status === 'online' ? 'online' : 'offline'}`} />
                    {s.status}
                  </span>
                </td>
                <td>{s.online_players}/{s.max_players}</td>
                <td>{s.tps.toFixed(1)}</td>
                <td>{new Date(s.last_heartbeat).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

export default Servers
