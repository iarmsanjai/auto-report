import { useState } from 'react'
import { loginUser, TOKEN_KEY } from '../services/api'
import ThemeToggle from './ThemeToggle'
import { Eye, EyeOff, Lock, User } from 'lucide-react'

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    if (!username.trim() || !password) { setError('Username and password are required'); return }
    setError('')
    setLoading(true)
    try {
      const data = await loginUser(username.trim(), password)
      localStorage.setItem(TOKEN_KEY, data.access_token)
      onLogin({ username: data.username, role: data.role })
    } catch (err) {
      setError(err?.response?.data?.detail || 'Login failed — check credentials')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      height: '100vh',
      width: '100vw',
      background: 'var(--bg)',
      display: 'flex',
      fontFamily: "'Inter', 'PT Sans', sans-serif",
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Theme Toggle in top right */}
      <div style={{ position: 'absolute', top: 24, right: 24, zIndex: 10 }}>
        <ThemeToggle />
      </div>

      {/* Left Branding Panel (Hidden on very small screens) */}
      <div className="login-brand-panel" style={{
        flex: 1,
        position: 'relative',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        padding: '60px',
        background: 'var(--bg2)',
        borderRight: '1px solid var(--border)',
        overflow: 'hidden'
      }}>
        {/* Animated grid background */}
        <div style={{
          position: 'absolute', inset: 0,
          backgroundImage: `
            linear-gradient(rgba(0,212,255,0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,212,255,0.04) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
          pointerEvents: 'none',
        }} />
        <div style={{
          position: 'absolute',
          top: '50%', left: '50%',
          transform: 'translate(-50%,-50%)',
          width: '120%', height: '120%',
          background: 'radial-gradient(circle, rgba(0,212,255,0.06) 0%, transparent 60%)',
          pointerEvents: 'none',
        }} />

        <div style={{ position: 'relative', zIndex: 1, maxWidth: 500 }}>
          <div style={{ fontSize: 48, color: 'var(--cyan)', marginBottom: 20 }}>⬡</div>
          <h1 style={{ fontSize: 42, fontWeight: 800, color: 'var(--text)', marginBottom: 16, lineHeight: 1.1, letterSpacing: -1 }}>
            Enterprise <br />
            <span style={{ color: 'var(--cyan)' }}>Security Platform</span>
          </h1>
          <p style={{ fontSize: 16, color: 'var(--dim)', lineHeight: 1.6, marginBottom: 40 }}>
            Automate and manage your vulnerability assessments, source code reviews, and web penetration tests from a single pane of glass.
          </p>
          
          <div style={{ display: 'flex', gap: 32 }}>
            <div>
              <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--text)' }}>10k+</div>
              <div style={{ fontSize: 12, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: 1 }}>Findings Managed</div>
            </div>
            <div>
              <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--text)' }}>3</div>
              <div style={{ fontSize: 12, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: 1 }}>Supported Scanners</div>
            </div>
          </div>
        </div>
      </div>

      {/* Right Login Form Panel */}
      <div style={{
        width: 480,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px',
        background: 'var(--bg)',
        flexShrink: 0
      }}>
        <div style={{ width: '100%', maxWidth: 360 }}>
          <div style={{ marginBottom: 40 }}>
            <div style={{
              fontWeight: 700,
              color: 'var(--cyan)',
              fontSize: 14,
              letterSpacing: 2,
              marginBottom: 8,
            }}>
              <span style={{ color: 'var(--red)' }}>IARM</span> VAPT REPORTS
            </div>
            <h2 style={{ fontSize: 28, fontWeight: 700, color: 'var(--text)', marginBottom: 8 }}>Sign in</h2>
            <div style={{ fontSize: 14, color: 'var(--dim)' }}>Enter your credentials to continue.</div>
          </div>

          <form onSubmit={submit} autoComplete="on">
            {/* Username */}
            <div style={{ marginBottom: 20 }}>
              <label style={{
                display: 'block', fontSize: 11, color: 'var(--dim)', fontWeight: 600,
                letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 8,
              }}>Username</label>
              <div style={{ position: 'relative' }}>
                <span style={{
                  position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)',
                  color: 'var(--dim)', display: 'flex', alignItems: 'center'
                }}>
                  <User size={16} />
                </span>
                <input
                  id="login-username"
                  type="text"
                  autoComplete="username"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  placeholder="user_id"
                  style={{
                    width: '100%', background: 'var(--input-bg)',
                    border: '1px solid var(--border)', borderRadius: 8,
                    padding: '12px 14px 12px 40px',
                    color: 'var(--text)', fontFamily: "'Inter', sans-serif",
                    fontSize: 14, outline: 'none',
                    transition: 'border-color 0.15s, box-shadow 0.15s',
                    boxSizing: 'border-box',
                  }}
                  onFocus={e => {
                    e.target.style.borderColor = 'var(--cyan)'
                    e.target.style.boxShadow = '0 0 0 3px rgba(0,212,255,0.1)'
                  }}
                  onBlur={e => {
                    e.target.style.borderColor = 'var(--border)'
                    e.target.style.boxShadow = 'none'
                  }}
                />
              </div>
            </div>

            {/* Password */}
            <div style={{ marginBottom: 28 }}>
              <label style={{
                display: 'block', fontSize: 11, color: 'var(--dim)', fontWeight: 600,
                letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 8,
              }}>Password</label>
              <div style={{ position: 'relative' }}>
                <span style={{
                  position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)',
                  color: 'var(--dim)', display: 'flex', alignItems: 'center'
                }}>
                  <Lock size={16} />
                </span>
                <input
                  id="login-password"
                  type={showPass ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  style={{
                    width: '100%', background: 'var(--input-bg)',
                    border: '1px solid var(--border)', borderRadius: 8,
                    padding: '12px 40px 12px 40px',
                    color: 'var(--text)', fontFamily: "'Inter', sans-serif",
                    fontSize: 14, outline: 'none',
                    transition: 'border-color 0.15s, box-shadow 0.15s',
                    boxSizing: 'border-box',
                  }}
                  onFocus={e => {
                    e.target.style.borderColor = 'var(--cyan)'
                    e.target.style.boxShadow = '0 0 0 3px rgba(0,212,255,0.1)'
                  }}
                  onBlur={e => {
                    e.target.style.borderColor = 'var(--border)'
                    e.target.style.boxShadow = 'none'
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPass(p => !p)}
                  style={{
                    position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--dim)', padding: 4, display: 'flex', alignItems: 'center'
                  }}
                  title={showPass ? 'Hide password' : 'Show password'}
                >
                  {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div style={{
                background: 'rgba(255,68,68,0.08)', border: '1px solid rgba(255,68,68,0.3)',
                borderLeft: '3px solid var(--red)', borderRadius: 6,
                padding: '12px 16px', fontSize: 13, color: '#ff8888',
                marginBottom: 24,
              }}>
                ⚠ {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%', padding: '14px',
                background: loading ? 'rgba(0,212,255,0.05)' : 'var(--cyan)',
                border: 'none',
                borderRadius: 8,
                color: loading ? 'var(--cyan)' : '#000',
                fontFamily: "'Inter', sans-serif",
                fontSize: 14, fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                transition: 'all 0.15s',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                boxShadow: loading ? 'none' : '0 4px 14px rgba(0,212,255,0.3)',
              }}
              onMouseEnter={e => { if (!loading) e.currentTarget.style.transform = 'translateY(-1px)' }}
              onMouseLeave={e => { if (!loading) e.currentTarget.style.transform = 'none' }}
              onActive={e => { if (!loading) e.currentTarget.style.transform = 'translateY(1px)' }}
            >
              {loading
                ? <><span className="spinner" style={{ width: 16, height: 16, borderTopColor: 'var(--cyan)' }} /> AUTHENTICATING...</>
                : 'Sign In'
              }
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
