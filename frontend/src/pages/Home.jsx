import Dashboard         from '../components/Dashboard'
import DataEditor        from '../components/DataEditor'
import VulnerabilityTable from '../components/VulnerabilityTable'
import ReportPreview     from '../components/ReportPreview'
import AdminPanel        from '../components/AdminPanel'
import ReportsManager    from '../components/ReportsManager'

export default function Home({
  page, setPage,
  findings, setFindings,
  meta, setMeta,
  editTarget, setEditTarget,
  toast,
  onLoadSample,
  authUser,
  onEditReport,
  currentReportId,
  currentReportStatus,
  setCurrentReportStatus,
}) {
  const handleEdit = (finding) => {
    setEditTarget(finding)
    setPage('editor')
  }

  const handleImport = (newFindings, mode, scanType, template) => {
    if (mode === 'replace') setFindings(newFindings)
    else setFindings(prev => [...prev, ...newFindings])
    // scanType & template available for future template auto-selection
  }

  return (
    <>
      {page === 'dashboard' && (
        <Dashboard
          findings={findings}
          meta={meta}
          setPage={setPage}
          onLoadSample={onLoadSample}
        />
      )}

      {page === 'editor' && (
        <DataEditor
          meta={meta}
          setMeta={setMeta}
          findings={findings}
          setFindings={setFindings}
          editTarget={editTarget}
          setEditTarget={setEditTarget}
          toast={toast}
        />
      )}

      {page === 'findings' && (
        <VulnerabilityTable
          findings={findings}
          setFindings={setFindings}
          onEdit={handleEdit}
          toast={toast}
        />
      )}

      {page === 'preview' && (
        <ReportPreview
          findings={findings}
          meta={meta}
          toast={toast}
          authUser={authUser}
          currentReportId={currentReportId}
          currentReportStatus={currentReportStatus}
          setCurrentReportStatus={setCurrentReportStatus}
        />
      )}

      {page === 'reports' && (
        <ReportsManager
          onEditReport={onEditReport}
          toast={toast}
          authUser={authUser}
        />
      )}

      {page === 'admin' && (
        <AdminPanel
          toast={toast}
          authUser={authUser}
        />
      )}
    </>
  )
}
