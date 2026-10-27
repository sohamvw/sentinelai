import React, { useState, useEffect } from 'react';
import { getLatestScanStatus, getReportHtmlUrl, getReportPdfUrl } from '../services/api';

interface ReportViewerPageProps {
  scanResult: any;
}

export const ReportViewerPage: React.FC<ReportViewerPageProps> = ({ scanResult: propScanResult }) => {
  const [activeScan, setActiveScan] = useState<any>(propScanResult);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (propScanResult?.scan_id) {
      setActiveScan(propScanResult);
      return;
    }

    setLoading(true);
    getLatestScanStatus()
      .then((data) => {
        if (data && data.scan_id) {
          setActiveScan(data);
        }
      })
      .catch((err) => console.error('Failed to fetch latest scan for report viewer', err))
      .finally(() => setLoading(false));
  }, [propScanResult]);

  if (loading) {
    return <div className="report-container empty"><p style={{ color: 'var(--text-secondary)' }}>Loading audit report...</p></div>;
  }

  if (!activeScan || !activeScan.scan_id || activeScan.status !== 'COMPLETED') {
    return (
      <div className="report-container empty">
        <div className="empty-card">
          <h3>No Audit Report Generated Yet</h3>
          <p>Please complete a repository audit scan from the Dashboard to view and download the PDF report.</p>
        </div>
      </div>
    );
  }

  const handleDownloadPdf = () => {
    window.open(getReportPdfUrl(activeScan.scan_id), '_blank');
  };

  return (
    <div className="report-container">
      <div className="report-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2>Audit-Ready Security & Compliance Report</h2>
        </div>

        <button className="primary-auth-btn" onClick={handleDownloadPdf} style={{ padding: '12px 24px', fontSize: '15px', fontWeight: 'bold' }}>
          Download Report (PDF)
        </button>
      </div>

      <div className="report-preview-card" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', borderRadius: '12px', padding: '16px', overflow: 'hidden' }}>
        <iframe
          src={getReportHtmlUrl(activeScan.scan_id)}
          title="Security Audit Report Preview"
          style={{ width: '100%', height: '700px', border: 'none', borderRadius: '8px', background: '#ffffff' }}
        />
      </div>
    </div>
  );
};
