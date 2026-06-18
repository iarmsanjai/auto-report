import { useState, useEffect } from 'react'
import { listUsers, createUser, updateUser, deleteUser } from '../services/api'

export default function AdminPanel({ toast, authUser }) {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)

  const [showAdd, setShowAdd] = useState(false)
  const [addForm, setAddForm] = useState({ username: '', password: '', role: 'viewer' })

  const [editUser, setEditUser] = useState(null)
  const [editForm, setEditForm] = useState({ role: '', new_password: '' })

  const loadUsers = async () => {
    try {
      const data = await listUsers()
      setUsers(data)
    } catch (err) {
      toast('Failed to load users', 'error')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadUsers()
  }, [])

  const handleAddSubmit = async (e) => {
    e.preventDefault()
    try {
      await createUser(addForm.username, addForm.password, addForm.role)
      toast('User created successfully')
      setShowAdd(false)
      setAddForm({ username: '', password: '', role: 'viewer' })
      loadUsers()
    } catch (err) {
      toast(err?.response?.data?.detail || 'Failed to create user', 'error')
    }
  }

  const handleEditSubmit = async (e) => {
    e.preventDefault()
    try {
      await updateUser(editUser.username, editForm.role, editForm.new_password || null)
      toast('User updated successfully')
      setEditUser(null)
      loadUsers()
    } catch (err) {
      toast(err?.response?.data?.detail || 'Failed to update user', 'error')
    }
  }

  const handleDelete = async (username) => {
    // Soft delete in UI first
    const userToDelete = users.find(u => u.username === username)
    if (!userToDelete) return
    
    setUsers(prev => prev.filter(u => u.username !== username))
    
    let undone = false
    toast(`User '${username}' removed`, 'warn', () => {
      undone = true
      setUsers(prev => [...prev, userToDelete])
      toast('User restored', 'ok')
    })

    // Commit deletion after 10 seconds
    setTimeout(async () => {
      if (!undone) {
        try {
          await deleteUser(username)
        } catch (err) {
          // If it fails, refresh the list to fix the state
          loadUsers()
        }
      }
    }, 10000)
  }

  if (authUser?.role !== 'admin') {
    return <div className="card">Access denied: Admins only</div>
  }

  return (
    <div>
      <div className="page-title">⚙ Admin Panel — User Management</div>

      <div className="card mb-20" style={{ overflowX: 'auto' }}>
        <div className="flex justify-between items-center mb-16">
          <div className="section-label" style={{ marginBottom: 0 }}>System Users</div>
          <button className="btn btn-primary btn-sm" onClick={() => setShowAdd(!showAdd)}>
            {showAdd ? '✕ Cancel' : '+ Add User'}
          </button>
        </div>

        {/* Add User Form */}
        {showAdd && (
          <div style={{ background: 'var(--bg)', padding: 16, borderRadius: 8, marginBottom: 20, border: '1px solid var(--border)' }}>
            <div style={{ color: 'var(--cyan)', fontWeight: 700, marginBottom: 12, fontSize: 12 }}>Create New User</div>
            <form onSubmit={handleAddSubmit} className="grid-3" style={{ gap: 16, alignItems: 'end' }}>
              <div className="form-group">
                <label className="form-label">Username</label>
                <input
                  required
                  type="text"
                  className="form-input"
                  value={addForm.username}
                  onChange={e => setAddForm(prev => ({ ...prev, username: e.target.value }))}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Password</label>
                <input
                  required
                  type="password"
                  minLength={6}
                  className="form-input"
                  value={addForm.password}
                  onChange={e => setAddForm(prev => ({ ...prev, password: e.target.value }))}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Role</label>
                <select
                  className="form-select"
                  value={addForm.role}
                  onChange={e => setAddForm(prev => ({ ...prev, role: e.target.value }))}
                >
                  <option value="admin">Admin</option>
                  <option value="editor">Editor</option>
                  <option value="viewer">Viewer</option>
                </select>
              </div>
              <button type="submit" className="btn btn-primary">Create</button>
            </form>
          </div>
        )}

        {/* Edit User Form */}
        {editUser && (
          <div style={{ background: 'rgba(255,122,0,0.05)', padding: 16, borderRadius: 8, marginBottom: 20, border: '1px solid var(--orange)' }}>
            <div className="flex justify-between items-center mb-12">
              <div style={{ color: 'var(--orange)', fontWeight: 700, fontSize: 12 }}>
                Edit User: <span style={{ color: 'var(--text)' }}>{editUser.username}</span>
              </div>
              <button type="button" className="btn btn-sm" onClick={() => setEditUser(null)}>✕ Close</button>
            </div>
            <form onSubmit={handleEditSubmit} className="grid-3" style={{ gap: 16, alignItems: 'end' }}>
              <div className="form-group">
                <label className="form-label">Role</label>
                <select
                  className="form-select"
                  value={editForm.role}
                  onChange={e => setEditForm(prev => ({ ...prev, role: e.target.value }))}
                >
                  <option value="admin">Admin</option>
                  <option value="editor">Editor</option>
                  <option value="viewer">Viewer</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">New Password (leave blank to keep current)</label>
                <input
                  type="password"
                  minLength={6}
                  className="form-input"
                  value={editForm.new_password}
                  onChange={e => setEditForm(prev => ({ ...prev, new_password: e.target.value }))}
                />
              </div>
              <button type="submit" className="btn" style={{ background: 'var(--orange)', color: '#000', fontWeight: 700, border: 'none' }}>
                Save Changes
              </button>
            </form>
          </div>
        )}

        {/* Users Table */}
        {loading ? (
          <div className="spinner" />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Username</th>
                <th style={{ width: 120 }}>Role</th>
                <th style={{ width: 150, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.username}>
                  <td>{u.username} {u.username === authUser.username && <span style={{ color: 'var(--dim)', fontSize: 10, marginLeft: 8 }}>(You)</span>}</td>
                  <td>
                    <span className={`sev-badge ${u.role === 'admin' ? 'sev-critical' : u.role === 'editor' ? 'sev-high' : 'sev-info'}`}>
                      {u.role}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-sm mr-8"
                      onClick={() => {
                        setEditUser(u)
                        setEditForm({ role: u.role, new_password: '' })
                        setShowAdd(false)
                      }}
                    >
                      ✎ Edit
                    </button>
                    <button
                      className="btn btn-sm"
                      style={{ color: 'var(--red)', borderColor: 'var(--red)' }}
                      onClick={() => handleDelete(u.username)}
                      disabled={u.username === authUser.username}
                    >
                      ✕ Delete
                    </button>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={3} style={{ textAlign: 'center', color: 'var(--dim)', padding: 20 }}>No users found</td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
