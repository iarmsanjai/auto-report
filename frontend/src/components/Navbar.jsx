import { useState, useEffect } from 'react'
import { checkHealth } from '../services/api'

const NAV_GROUPS = [
  {
    label: 'Workspace',
    items: [
      { id: 'dashboard',  icon: '◈', label: 'Dashboard' },
      { id: 'editor',     icon: '✎', label: 'Editor' },
      { id: 'findings',   icon: '◉', label: 'Findings' },
      { id: 'preview',    icon: '⊙', label: 'Preview' },
    ]
  },
  {
    label: 'Platform',
    items: [
      { id: 'reports', icon: '☁', label: 'Cloud Reports' },
    ]
  }
]

export default function Navbar({ activePage, setPage, findingCount, meta, authUser }) {
  const [apiOk, setApiOk] = useState(null)

  useEffect(() => {
    checkHealth()
      .then(() => setApiOk(true))
      .catch(() => setApiOk(false))
  }, [])

  return (
    <aside className="app-sidebar">
      <div className="sidebar-scrollable">
        {NAV_GROUPS.map((group, gIdx) => (
          <div key={group.label} className="nav-group">
            {!(authUser?.role === 'viewer' && group.label === 'Workspace') && (
              <div className="nav-group-label">{group.label}</div>
            )}
            {group.items.map(item => {
              if (authUser?.role === 'viewer' && group.label === 'Workspace') return null
              const isActive = activePage === item.id
              return (
                <button
                  key={item.id}
                  className={`nav-btn ${isActive ? 'active' : ''}`}
                  onClick={() => setPage(item.id)}
                >
                  <span className="nav-icon">{item.icon}</span>
                  <span className="nav-label" style={{ fontWeight: isActive ? 600 : 400 }}>{item.label}</span>
                  {item.id === 'findings' && findingCount > 0 && (
                    <span className="nav-badge">
                      {findingCount}
                    </span>
                  )}
                </button>
              )
            })}
            
            {group.label === 'Platform' && authUser?.role === 'admin' && (
              <button
                className={`nav-btn ${activePage === 'admin' ? 'active' : ''}`}
                onClick={() => setPage('admin')}
              >
                <span className="nav-icon" style={{ color: 'var(--purple)' }}>⚙</span>
                <span className="nav-label" style={{ fontWeight: activePage === 'admin' ? 600 : 400 }}>Admin Panel</span>
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="sidebar-footer">
        {meta?.client_name && (
          <div className="sidebar-client">{meta.client_name}</div>
        )}
        <div className="api-status">
          <span className={`api-dot ${apiOk === null ? 'checking' : apiOk ? 'online' : 'offline'}`} />
          <span className="api-text">
            {apiOk === null ? 'Checking API...' : apiOk ? 'API Connected' : 'API Offline'}
          </span>
        </div>
      </div>
    </aside>
  )
}
