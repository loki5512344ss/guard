import { useState, useEffect } from 'react'
import { fetchNodes, type Node } from '../api'

function Nodes() {
  const [nodes, setNodes] = useState<Node[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const data = await fetchNodes()
        if (!cancelled) {
          setNodes(data)
          setError('')
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load nodes')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    const interval = setInterval(load, 15000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  if (loading) return <div className="spinner" />

  return (
    <>
      <h1>Edge Nodes</h1>
      {error && <div className="error-msg">{error}</div>}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Role</th>
              <th>IP</th>
              <th>Status</th>
              <th>Last Heartbeat</th>
            </tr>
          </thead>
          <tbody>
            {nodes.length === 0 && (
              <tr>
                <td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                  No nodes found
                </td>
              </tr>
            )}
            {nodes.map((n) => (
              <tr key={n.id}>
                <td>{n.id}</td>
                <td>{n.role}</td>
                <td>{n.ip}</td>
                <td>
                  <span className="status-badge">
                    <span className={`status-dot ${n.status === 'online' ? 'online' : 'offline'}`} />
                    {n.status}
                  </span>
                </td>
                <td>{new Date(n.last_heartbeat).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

export default Nodes
