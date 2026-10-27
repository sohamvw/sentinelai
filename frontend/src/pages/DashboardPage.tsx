import React, { useState, useEffect } from 'react';
import { getLatestScanStatus, getScan, createScan, createZipScan, cancelScan, getSectors } from '../services/api';


interface DashboardPageProps {
  onScanCompleted: (scanResult: any) => void;
  setActiveTab: (tab: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onScanCompleted, setActiveTab }) => {
  const [repoUrl, setRepoUrl] = useState('');
  const [repositoryZip, setRepositoryZip] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [currentStage, setCurrentStage] = useState('');
  const [scanResult, setLocalScanResult] = useState<any>(null);
  const [error, setError] = useState('');

  // Sectors from API (Indian regulators + generic)
  const [sectors, setSectors] = useState<Array<{ key: string; label: string; regulators?: string[] }>>([]);

  const stages = [
    { key: 'STAGE_1_TREE_MAPPING', label: 'Stage 1: Tree Mapping & LLM File Prioritization', desc: 'Identifies framework and selects high-value target files.' },
    { key: 'STAGE_2_MULTI_HUNTER_SCAN', label: 'Stage 2: Multi-Hunter SAST Team', desc: 'Runs Semgrep, Bandit, Trivy, and AST Traversal in parallel.' },
    { key: 'STAGE_3_LLM_VERIFICATION', label: 'Stage 3: Evidence Verification', desc: 'Reviews scanner evidence; source-backed CVE/CVSS data is preserved without fabrication.' },
    { key: 'STAGE_4_CORRELATION', label: 'Stage 4: Chain-Bounds Correlation', desc: 'Links vulnerabilities into multi-stage attack paths & compliance testing.' },
    { key: 'REPORT_GENERATION', label: 'Stage 5: Report Generation', desc: 'Builds HTML audit template & compiles downloadable PDF.' },
  ];

  const [sector, setSector] = useState('rbi_fintech');
  const [policyFile, setPolicyFile] = useState<File | null>(null);
  const [policyText, setPolicyText] = useState('');

  const handlePolicyFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setPolicyFile(file);
      const reader = new FileReader();
      // Text and Markdown can be read locally. PDF extraction is performed
      // server-side by the policy-intake service after upload.
      if (file.type === 'application/pdf' || file.name.toLowerCase().endsWith('.pdf')) {
        setPolicyText('');
        return;
      }
      reader.onload = (event) => setPolicyText(event.target?.result as string || '');
      reader.readAsText(file);
    }
  };

  const [activeScanId, setActiveScanId] = useState<string | null>(null);

  // Fetch sectors from API on mount
  useEffect(() => {
    getSectors()
      .then((data) => {
        if (data?.sector_packs) {
          setSectors(data.sector_packs.map((pack: any) => ({
            key: pack.key,
            label: pack.label,
            regulators: pack.authority ? [pack.authority] : [],
          })));
        }
      })
      .catch((err) => console.error('Failed to load sectors', err));
  }, []);

  // Fetch latest scan on mount if no active scan is set
  useEffect(() => {
    getLatestScanStatus()
      .then((data) => {
        if (data && data.status !== 'NO_SCANS' && data.status !== 'FAILED' && data.status !== 'CANCELLED' && data.scan_id) {
          setActiveScanId(data.scan_id);
          setLocalScanResult(data);
          if (data.status === 'RUNNING') setIsScanning(true);
          if (data.stage) setCurrentStage(data.stage);
          onScanCompleted(data);
        }
      })
      .catch((err) => console.error('Failed to load latest scan status', err));
  }, []);

  useEffect(() => {
    if (!activeScanId) return;

    const interval = setInterval(async () => {
      try {
        const data = await getScan(activeScanId);

        if (data.stage) setCurrentStage(data.stage);
        setLocalScanResult(data);
        onScanCompleted(data);

        if (data.status === 'COMPLETED') {
          setIsScanning(false);
          setLocalScanResult(data);
          onScanCompleted(data);
          clearInterval(interval);
        } else if (data.status === 'FAILED' || data.status === 'CANCELLED') {
          setIsScanning(false);
          setError(data.error || (data.status === 'CANCELLED' ? 'Scan cancelled.' : 'Background scan failed.'));
          clearInterval(interval);
        }
      } catch (err) {
        console.error('Error polling scan status', err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [activeScanId]);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl && !repositoryZip) return;

    setIsScanning(true);
    setError('');
    setLocalScanResult(null);
    // A new scan must never show the previous scan's findings while it runs.
    onScanCompleted(null);
    setCurrentStage('INTAKE');

    try {
      const data = repositoryZip
        ? await createZipScan(repositoryZip, sector, policyText, policyFile?.name)
        : await createScan({ repository_url: repoUrl, source_type: 'github', sector, policy_document_text: policyText, policy_filename: policyFile?.name || 'uploaded_policy.txt' });

      setActiveScanId(data.scan_id);
    } catch (err: any) {
      setError(err.message || 'Scan execution encountered an error.');
      setIsScanning(false);
    }
  };

  const handleCancelScan = async () => {
    if (!activeScanId) return;
    try {
      await cancelScan(activeScanId);
      setIsScanning(false);
      setLocalScanResult({ status: 'CANCELLED' });
      setCurrentStage('CANCELLED');
    } catch (err) {
      console.error('Failed to cancel scan', err);
    }
  };

  const getStageStatus = (stageKey: string) => {
    if (!scanResult && !isScanning) return { label: 'PENDING', class: 'pending' };
    const stageOrder = [
      'INTAKE',
      'REPOSITORY_CLONING',
      'REPOSITORY_CLONED',
      'STAGE_1_TREE_MAPPING',
      'PRIORITIZING_FILES',
      'STAGE_2_MULTI_HUNTER_SCAN',
      'MULTI_TOOL_SCAN',
      'STAGE_3_LLM_VERIFICATION',
      'LLM_VERIFICATION',
      'STAGE_4_CORRELATION',
      'POLICY_JURISDICTION_CHECK',
      'REPORT_GENERATION',
      'AUDIT_REPORT_READY'
    ];

    const currentIdx = stageOrder.indexOf(currentStage);
    const mappedStageKey = stageKey === 'STAGE_1_TREE_MAPPING' ? 'STAGE_1_TREE_MAPPING'
      : stageKey === 'STAGE_2_MULTI_HUNTER_SCAN' ? 'MULTI_TOOL_SCAN'
      : stageKey === 'STAGE_3_LLM_VERIFICATION' ? 'LLM_VERIFICATION'
      : stageKey === 'STAGE_4_CORRELATION' ? 'STAGE_4_CORRELATION'
      : 'AUDIT_REPORT_READY';

    const stageIdx = stageOrder.indexOf(mappedStageKey);

    if (scanResult?.status === 'FAILED' || scanResult?.status === 'CANCELLED') {
      const failedStage = scanResult.failed_stage || currentStage;
      const failedIdx = stageOrder.indexOf(failedStage);
      if (failedStage === mappedStageKey || failedStage === stageKey) return { label: 'FAILED', class: 'failed' };
      if (failedIdx > stageIdx) return { label: 'COMPLETED', class: 'completed' };
      return { label: 'PENDING', class: 'pending' };
    }
    if (scanResult?.status === 'COMPLETED') return { label: 'COMPLETED', class: 'completed' };

    if (currentStage === mappedStageKey || currentStage === stageKey) return { label: 'RUNNING', class: 'running' };
    if (currentIdx > stageIdx) return { label: 'COMPLETED', class: 'completed' };
    return { label: 'PENDING', class: 'pending' };
  };

  // Determine live compliance indicator color
  const getComplianceIndicatorColor = () => {
    if (!scanResult) return 'gray';
    if (scanResult.status === 'FAILED') return 'red';
    if (scanResult.status === 'CANCELLED') return 'gray';
    if (scanResult.status !== 'COMPLETED') return 'blue';
    const critical = scanResult.critical_count || 0;
    const high = scanResult.high_count || 0;
    if (critical > 0) return 'red';
    if (high > 0) return 'amber';
    return 'green';
  };

  const getComplianceIndicatorLabel = () => {
    if (!scanResult) return 'Ready';
    if (scanResult.status === 'FAILED') return 'Scan failed';
    if (scanResult.status === 'CANCELLED') return 'Scan cancelled';
    if (scanResult.status !== 'COMPLETED') return 'Scanning...';

    const critical = scanResult.critical_count || 0;
    const high = scanResult.high_count || 0;
    if (critical > 0) return 'Non-compliant';
    if (high > 0) return 'Review needed';
    return 'Compliant';
  };

  const indicatorColor = getComplianceIndicatorColor();
  const indicatorColors = {
    green: '#10b981',
    amber: '#f59e0b',
    red: '#ef4444',
    blue: '#3b82f6',
    gray: '#6b7280',
  };

  return (
    <div className="dashboard-container">

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>

      <div className="intake-card">
        <h3>Repository & Policy Intake</h3>
        <form onSubmit={handleStartScan} className="intake-form">
          <div className="input-group" style={{ marginBottom: '14px' }}>
            <input
              type="text"
              placeholder="Enter Repository URL"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              disabled={isScanning}
            />
          </div>

          <div className="input-group" style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>Upload repository ZIP</label>
            <input style={{ width: '100%', padding: '9px', boxSizing: 'border-box' }} type="file" accept=".zip,application/zip" onChange={(e) => { setRepositoryZip(e.target.files?.[0] || null); if (e.target.files?.[0]) setRepoUrl(''); }} disabled={isScanning} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', margin: '16px 0' }}>
            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Industry Sector Policy Jurisdiction
              </label>
              <select
                value={sector}
                onChange={(e) => setSector(e.target.value)}
                disabled={isScanning}
                style={{ width: '100%', padding: '10px 14px', borderRadius: '6px', border: '1px solid var(--border-glass)', backgroundColor: 'var(--bg-glass-hover)', color: 'var(--text-main)', fontWeight: 500, cursor: isScanning ? 'not-allowed' : 'pointer' }}
              >
                {sectors.length > 0 ? (
                  sectors.map((s) => (
                    <option key={s.key} value={s.key}>
                      {s.label}{s.regulators ? ` (${s.regulators.join(', ')})` : ''}
                    </option>
                  ))
                ) : (
                  <>
                    <option value="rbi_fintech">RBI FinTech & Digital Payments</option>
                    <option value="sebi_stock_market">SEBI Stock Market & Securities</option>
                    <option value="ecommerce_india">India E-Commerce & Consumer Protection</option>
                    <option value="saas_india">India SaaS (CERT-In + DPDP)</option>
                  </>
                )}
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Upload company policy (.pdf / .txt / .md)
              </label>
              <input
                type="file"
                accept=".pdf,.txt,.md"
                onChange={handlePolicyFileChange}
                disabled={isScanning}
                style={{ width: '100%', padding: '8px', fontSize: '13px', border: '1px solid var(--border-glass)', borderRadius: '6px', background: 'var(--bg-glass-hover)', color: 'var(--text-main)' }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '12px' }}>
            <button type="submit" className="start-scan-btn" disabled={isScanning} style={{ flex: 1, marginTop: '8px' }}>
              {isScanning ? 'Scanning & Checking Compliance...' : 'Launch Audit Scan & Policy Check'}
            </button>
            {(isScanning || scanResult?.status === 'RUNNING') && (
              <button type="button" onClick={handleCancelScan} className="primary-auth-btn" style={{ background: '#ef4444', color: '#fff', marginTop: '8px' }}>
                Cancel / Reset Scan
              </button>
            )}
          </div>
        </form>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="pipeline-tracker-card">
        <div className="tracker-header">
          <h3>Security & Compliance Scan Pipeline</h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {scanResult && scanResult.status === 'COMPLETED' ? (
              <span className="status-badge completed">Scan Completed ({scanResult.total_findings || scanResult.metrics?.raw_findings || 0} findings analyzed)</span>
            ) : scanResult?.status === 'FAILED' ? (
              <span className="status-badge failed" style={{ color: '#ef4444' }}>Scan Failed ({scanResult.failed_stage || 'repository setup'})</span>
            ) : scanResult?.status === 'CANCELLED' ? (
              <span className="status-badge pending">Scan Cancelled</span>
            ) : isScanning ? (
              <span className="status-badge running" style={{ color: 'var(--primary-color)' }}>Scan Running ({currentStage})</span>
            ) : (
              <span className="status-badge pending" style={{ color: 'var(--text-muted)' }}>Ready for Scan</span>
            )}
            {/* Live compliance indicator dot in tracker header */}
            <span style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              padding: '4px 10px', borderRadius: '20px',
              background: `rgba(${indicatorColor === 'green' ? '16,185,129' : indicatorColor === 'amber' ? '245,158,11' : indicatorColor === 'red' ? '239,68,68' : indicatorColor === 'blue' ? '59,130,246' : '107,114,128'}, 0.12)`,
              border: `1px solid rgba(${indicatorColor === 'green' ? '16,185,129' : indicatorColor === 'amber' ? '245,158,11' : indicatorColor === 'red' ? '239,68,68' : indicatorColor === 'blue' ? '59,130,246' : '107,114,128'}, 0.3)`,
            }}>
              <span style={{
                width: '8px', height: '8px', borderRadius: '50%',
                background: indicatorColors[indicatorColor],
                boxShadow: `0 0 6px ${indicatorColors[indicatorColor]}`,
                animation: indicatorColor !== 'gray' ? 'pulse 2s infinite' : 'none',
              }} />
              <span style={{ fontSize: '11px', fontWeight: 600, color: indicatorColors[indicatorColor], textTransform: 'capitalize' }}>
                {getComplianceIndicatorLabel()}
              </span>
            </span>
          </div>
        </div>

        <div className="pipeline-steps-grid">
          {stages.map((stg, idx) => {
            const stgStatus = getStageStatus(stg.key);
            return (
              <div
                key={stg.key}
                className={`pipeline-step-box ${stgStatus.class}`}
              >
                <div className="step-number">{idx + 1}</div>
                <div className="step-content" style={{ flex: 1 }}>
                  <h4>{stg.label}</h4>
                  <p>{stg.desc}</p>
                </div>
                <span className={`stage-status-indicator ${stgStatus.class}`}>
                  {stgStatus.label === 'COMPLETED' ? '✓ Complete' : stgStatus.label === 'RUNNING' ? 'Running' : stgStatus.label === 'FAILED' ? 'Failed' : 'Pending'}
                </span>
              </div>
            );
          })}
        </div>

        {scanResult && scanResult.status === 'COMPLETED' && (
          <div className="scan-summary-footer" style={{ marginTop: '24px' }}>
            <div className="metrics-row" style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
              <div className="metric-pill critical" style={{ padding: '6px 12px', borderRadius: '6px', background: 'rgba(239,68,68,0.1)', color: '#ef4444', fontWeight: 'bold' }}>Critical: {scanResult.critical_count || 0}</div>
              <div className="metric-pill high" style={{ padding: '6px 12px', borderRadius: '6px', background: 'rgba(249,115,22,0.1)', color: '#f97316', fontWeight: 'bold' }}>High: {scanResult.high_count || 0}</div>
              <div className="metric-pill medium" style={{ padding: '6px 12px', borderRadius: '6px', background: 'rgba(234,179,8,0.1)', color: '#eab308', fontWeight: 'bold' }}>Medium: {scanResult.medium_count || 0}</div>
              <div className="metric-pill verified" style={{ padding: '6px 12px', borderRadius: '6px', background: 'rgba(16,185,129,0.1)', color: '#10b981', fontWeight: 'bold' }}>Total Findings: {scanResult.total_findings || 0}</div>
            </div>

            <div className="action-buttons-row" style={{ display: 'flex', gap: '12px' }}>
              <button className="primary-auth-btn" onClick={() => setActiveTab('findings')}>
                View Detailed Findings
              </button>
              <button className="primary-auth-btn" style={{ background: 'var(--bg-glass-hover)', border: '1px solid var(--border-glass)', color: 'var(--text-main)' }} onClick={() => setActiveTab('audit-logs')}>
                Inspect Audit Logs
              </button>
              <button className="primary-auth-btn" style={{ background: 'var(--bg-glass-hover)', border: '1px solid var(--border-glass)', color: 'var(--text-main)' }} onClick={() => setActiveTab('reports')}>
                Download PDF Audit Report
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
