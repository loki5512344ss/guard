import { useState } from 'react'
import { logout } from '../api'
import Servers from './Servers'
import Blacklist from './Blacklist'
import Nodes from './Nodes'

type Page = 'servers' | 'blacklist' | 'nodes'

const navItems: { key: Page; label: string }[] = [
  { key: 'servers', label: 'Servers' },
  { key: 'blacklist', label: 'Blacklist' },
  { key: 'nodes', label: 'Nodes' },
]

function Layout() {
  const [page, setPage] = useState<Page>('servers')

  function renderPage() {
    switch (page) {
      case 'servers':
        return <Servers />
      case 'blacklist':
        return <Blacklist />
      case 'nodes':
        return <Nodes />
    }
  }

  return (
    <div className="layout">
      <aside className="sidebar">
        <h2>Rampart Manager</h2>
        <nav>
          {navItems.map((item) => (
            <button
              key={item.key}
              className={page === item.key ? 'active' : ''}
              onClick={() => setPage(item.key)}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <button className="logout-btn" onClick={logout}>
          Logout
        </button>
      </aside>
      <main className="main-content">{renderPage()}</main>
    </div>
  )
}

export default Layout
