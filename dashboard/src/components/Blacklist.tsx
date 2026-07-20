import { useState, useEffect, FormEvent } from 'react'
import { fetchBlacklist, addBlacklist, type BlacklistEntry } from '../api'

function Blacklist() {
  const [entries, setEntries] = useState<BlacklistEntry[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const [target, setTarget] = useState('')
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState('3600')
  const [adding, setAdding] = useState(false)
  const [addError, setAddError] = useState('')
  const [addSuccess, setAddSuccess] = useState('')

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const data = await fetchBlacklist()
        if (!cancelled) {
          setEntries(data)
          setError('')
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load blacklist')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    const interval = setInterval(load, 30000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  async function handleAdd(e: FormEvent) {
    e.preventDefault()
    setAddError('')
    setAddSuccess('')
    setAdding(true)

    try {
      await addBlacklist(target, 'ip', reason, parseInt(duration, 10))
      setAddSuccess(`Added ${target} to blacklist`)
      setTarget('')
      setReason('')
      setDuration('3600')
      const data = await fetchBlacklist()
      setEntries(data)
    } catch (err: unknown) {
      setAddError(err instanceof Error ? err.message : 'Failed to add entry')
    } finally {
      setAdding(false)
    }
  }

  if (loading) return <div className="spinner" />

  return (
    <>
      <h1>Blacklist</h1>

      <form className="blacklist-form" onSubmit={handleAdd}>
        <input
          type="text"
          placeholder="IP Address"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="Reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          required
        />
        <input
          type="number"
          placeholder="Duration (seconds)"
          value={duration}
          onChange={(e) => setDuration(e.target.value)}
          min={1}
          required
        />
        <button type="submit" disabled={adding}>
          {adding ? 'Adding...' : 'Add to Blacklist'}
        </button>
      </form>

      {addError && <div className="error-msg">{addError}</div>}
      {addSuccess && <div className="success-msg">{addSuccess}</div>}
      {error && <div className="error-msg">{error}</div>}

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Target</th>
              <th>Type</th>
              <th>Reason</th>
              <th>Created</th>
              <th>Expires</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && (
              <tr>
                <td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                  No blacklist entries
                </td>
              </tr>
            )}
            {entries.map((e, i) => (
              <tr key={i}>
                <td>{e.target}</td>
                <td>{e.type}</td>
                <td>{e.reason}</td>
                <td>{new Date(e.created).toLocaleString()}</td>
                <td>{new Date(e.expires).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

export default Blacklist
