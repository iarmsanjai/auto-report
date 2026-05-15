import { useState } from 'react'
import ThemeToggle from '../components/ThemeToggle'

export default function HomeHub({ authUser, onLogout, setPage, findingsCount }) {
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false)
  return (
    <div style={{
      minHeight: '100vh',
      width: '100vw',
      background: 'var(--bg)',
      display: 'flex',
      flexDirection: 'column',
      fontFamily: "'Inter', 'PT Sans', sans-serif",
      position: 'relative',
      overflowX: 'hidden',
      overflowY: 'auto',
    }}>
      {/* Background patterns */}
      <div style={{
        position: 'fixed', inset: 0, pointerEvents: 'none',
        backgroundImage: `
          linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px)
        `,
        backgroundSize: '48px 48px',
      }} />
      <div style={{
        position: 'fixed', top: '20%', left: '50%',
        transform: 'translate(-50%,-50%)',
        width: 1000, height: 600,
        background: 'radial-gradient(ellipse, rgba(0,212,255,0.04) 0%, transparent 60%)',
        pointerEvents: 'none',
      }} />

      {/* Top Header */}
      <div style={{
        width: '100%', maxWidth: 1100, margin: '0 auto',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '24px 24px', zIndex: 10
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 24, color: 'var(--cyan)' }}>⬡</span>
          <span style={{
            fontWeight: 700, fontSize: 16, letterSpacing: 2, color: 'var(--cyan)',
          }}>
            <span style={{ color: 'var(--red)' }}>IARM</span> VAPT REPORTS
          </span>
          <span style={{
            background: 'var(--cyan-dim)', color: 'var(--cyan)',
            border: '1px solid var(--cyan)', borderRadius: 4,
            padding: '2px 8px', fontSize: 10, letterSpacing: 1.5, fontWeight: 600
          }}>v1.0</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            paddingRight: 16, borderRight: '1px solid var(--border)'
          }}>
            <span style={{ color: 'var(--cyan)', fontSize: 14 }}>⬡</span>
            <span style={{ color: 'var(--text2)', fontSize: 12, fontWeight: 500 }}>{authUser?.username || 'admin'}</span>
            <span style={{ color: 'var(--dim)', fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              {authUser?.role}
            </span>
          </div>
          <ThemeToggle />
          <button className="btn btn-danger btn-sm" onClick={() => setShowLogoutConfirm(true)}>→ Logout</button>
        </div>
      </div>

      <div style={{ width: '100%', maxWidth: 1100, margin: '0 auto', borderTop: '1px solid var(--border)', marginBottom: 40 }} />

      {/* Main Content */}
      <div style={{ width: '100%', maxWidth: 1100, margin: '0 auto', padding: '0 24px 60px', zIndex: 10 }}>
        
        {/* Hero Section */}
        <div style={{ marginBottom: 48, textAlign: 'center' }}>
          <h1 style={{ fontSize: 32, fontWeight: 700, color: 'var(--text)', marginBottom: 12, letterSpacing: -0.5 }}>
            Welcome to the Reporting Hub
          </h1>
          <p style={{ fontSize: 15, color: 'var(--dim)', maxWidth: 600, margin: '0 auto', lineHeight: 1.6 }}>
            Start a new assessment by importing vulnerability data below, or manage your cloud reports and configurations.
          </p>
        </div>

        {/* Resume Banner */}
        {findingsCount > 0 && authUser?.role !== 'viewer' && (
          <div style={{
            background: 'var(--panel-bg, var(--bg2))',
            border: '1px solid var(--cyan)',
            borderRadius: 12,
            padding: '24px 32px',
            marginBottom: 40,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            boxShadow: '0 8px 32px var(--glow-color)'
          }}>
            <div>
              <div style={{ fontSize: 18, fontWeight: 600, color: 'var(--text)', marginBottom: 4 }}>
                Active Session Detected
              </div>
              <div style={{ fontSize: 13, color: 'var(--dim)' }}>
                You have {findingsCount} finding(s) in your current working session.
              </div>
            </div>
            <button className="btn btn-primary" style={{ padding: '10px 24px', fontSize: 14 }} onClick={() => setPage('dashboard')}>
              Resume Session →
            </button>
          </div>
        )}

        {/* Centered Actions */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          
          <div style={{ width: '100%', maxWidth: 420 }}>
            <div style={{
              fontSize: 12, color: 'var(--dim)', letterSpacing: 1.2,
              textTransform: 'uppercase', marginBottom: 16, fontWeight: 600
            }}>
              Platform Tools
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {authUser?.role !== 'viewer' && (
                <button className="hub-tool-btn" onClick={() => setPage('import')}>
                  <span className="hub-tool-icon" style={{ color: 'var(--cyan)' }}>↑</span>
                  <div style={{ textAlign: 'left' }}>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>Create New Report</div>
                    <div style={{ fontSize: 11, color: 'var(--dim)' }}>Upload vulnerability data</div>
                  </div>
                </button>
              )}

              <button className="hub-tool-btn" onClick={() => setPage('reports')}>
                <span className="hub-tool-icon" style={{ color: 'var(--cyan)' }}>☁</span>
                <div style={{ textAlign: 'left' }}>
                  <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>Cloud Reports</div>
                  <div style={{ fontSize: 11, color: 'var(--dim)' }}>Manage saved assessments</div>
                </div>
              </button>
              
              {authUser?.role === 'admin' && (
                <button className="hub-tool-btn" onClick={() => setPage('admin')}>
                  <span className="hub-tool-icon" style={{ color: 'var(--purple)' }}>⚙</span>
                  <div style={{ textAlign: 'left' }}>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>Admin Panel</div>
                    <div style={{ fontSize: 11, color: 'var(--dim)' }}>User & system settings</div>
                  </div>
                </button>
              )}
            </div>
          </div>
        </div>

      </div>

      {/* Logout Confirmation Modal */}
      {showLogoutConfirm && (
        <div style={{
          position: 'fixed', inset: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 1000
        }}>
          <div style={{
            background: 'var(--panel-bg)',
            border: '1px solid var(--border)',
            borderRadius: 12,
            padding: 32,
            width: 400,
            maxWidth: '90%',
            textAlign: 'center',
            boxShadow: '0 12px 48px rgba(0,0,0,0.5)'
          }}>
            <div style={{ fontSize: 40, color: 'var(--red)', marginBottom: 16 }}>⚠</div>
            <h3 style={{ fontSize: 20, color: 'var(--text)', marginBottom: 12, margin: 0 }}>Confirm Logout</h3>
            <p style={{ color: 'var(--dim)', fontSize: 14, marginBottom: 32 }}>
              Are you sure you want to log out of the reporting platform?
            </p>
            <div style={{ display: 'flex', gap: 16, justifyContent: 'center' }}>
              <button 
                className="btn" 
                style={{ minWidth: 130, padding: '10px 0', textAlign: 'center', justifyContent: 'center' }}
                onClick={() => setShowLogoutConfirm(false)}
              >
                Cancel
              </button>
              <button 
                className="btn btn-danger" 
                style={{ minWidth: 130, padding: '10px 0', textAlign: 'center', justifyContent: 'center' }}
                onClick={onLogout}
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
