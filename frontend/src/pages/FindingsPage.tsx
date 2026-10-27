import React, { useState, useEffect } from 'react';
import { getLatestScanStatus } from '../services/api';

interface FindingsPageProps {
  scanResult: any;
}

export const FindingsPage: React.FC<FindingsPageProps> = ({ scanResult: propScanResult }) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [activeView, setActiveView] = useState<'confirmed' | 'raw' | 'rejected' | 'unresolved' | 'matrix'>('confirmed');
  const [matrixTool, setMatrixTool] = useState('ALL');
  const [matrixMode, setMatrixMode] = useState<'count' | 'percentage'>('count');
  const [activeResult, setActiveResult] = useState<any>(propScanResult);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (propScanResult?.final_output || propScanResult?.status === 'COMPLETED') {
      setActiveResult(propScanResult);
      return;
    }

    setLoading(true);
    getLatestScanStatus()
      .then((data) => {
        if (data && (data.final_output || data.status === 'COMPLETED')) {
          setActiveResult(data);
        }
      })
      .catch((err) => console.error('Failed to load findings data from latest scan', err))
      .finally(() => setLoading(false));
  }, [propScanResult]);

  if (loading) {
    return <div className="findings-container empty"><p style={{ color: 'var(--text-secondary)' }}>Loading security findings...</p></div>;
  }

  const finalOutput = activeResult?.final_output ?? (activeResult?.status === 'COMPLETED' ? activeResult : null);

  if (!activeResult || !finalOutput) {
    return (
      <div className="findings-container empty">
        <div className="empty-card">
          <h3>No Security Findings Loaded</h3>
          <p>Please launch an audit scan from the Dashboard to analyze repository findings.</p>
        </div>
      </div>
    );
  }

  const findings = finalOutput.findings || [];
  const rawFindings = finalOutput.raw_findings || [];
  const rejectedFindings = finalOutput.rejected_findings || [];
  const unresolvedFindings = finalOutput.unresolved_findings || [];
  const verificationMatrix = finalOutput.verification_matrix || {
    raw_total: finalOutput.raw_findings_count || rawFindings.length,
    reviewed_total: findings.length + rejectedFindings.length + unresolvedFindings.length,
    confirmed_total: findings.length,
    false_positive_total: rejectedFindings.length,
    unresolved_total: unresolvedFindings.length,
  };
  const chains = finalOutput.chains || [];
  const perToolMatrix = verificationMatrix.per_tool || [];
  const visibleToolMatrix = matrixTool === 'ALL' ? perToolMatrix : perToolMatrix.filter((row: any) => row.tool === matrixTool);
  const matrixValue = (value: number, total: number) => matrixMode === 'percentage'
    ? `${total ? ((value / total) * 100).toFixed(1) : '0.0'}%`
    : String(value);
  const findingsForView = activeView === 'confirmed' ? findings
    : activeView === 'raw' ? rawFindings
    : activeView === 'rejected' ? rejectedFindings
    : activeView === 'unresolved' ? unresolvedFindings : [];
  const filteredFindings = selectedSeverity === 'ALL'
    ? findingsForView
    : findingsForView.filter((f: any) => f.severity === selectedSeverity);

  return (
    <div className="findings-container">
      <div className="findings-header">
        <div>
          <h2>Security Findings & Verification</h2>
        </div>

        <div className="severity-filter-bar">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              className={`filter-btn ${selectedSeverity === sev ? 'active' : ''}`}
              onClick={() => setSelectedSeverity(sev)}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      <div className="severity-filter-bar" style={{ marginBottom: '16px', flexWrap: 'wrap' }}>
        {[
          ['confirmed', `Confirmed (${findings.length})`],
          ['raw', `Raw Scanner Findings (${rawFindings.length})`],
          ['rejected', `False Positives (${rejectedFindings.length})`],
          ['unresolved', `Human Review (${unresolvedFindings.length})`],
          ['matrix', 'Verification Matrix'],
        ].map(([view, label]) => (
          <button key={view} className={`filter-btn ${activeView === view ? 'active' : ''}`} onClick={() => setActiveView(view as typeof activeView)}>{label}</button>
        ))}
      </div>

      {activeView === 'matrix' ? (
        <div className="chains-section" style={{ padding: '22px' }}>
          <h3>📊 Scanner Verification Matrix</h3>
          <div className="metrics-row" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '12px', margin: '20px 0' }}>
            {[
              ['Total Scanner Findings', verificationMatrix.raw_total, '#2563eb'],
              ['Confirmed Findings', verificationMatrix.confirmed_total, '#16a34a'],
              ['False Positives', verificationMatrix.false_positive_total, '#dc2626'],
              ['Human Review Required', verificationMatrix.unresolved_total, '#d97706'],
              ['Decision Coverage', `${verificationMatrix.reviewed_total || 0}/${verificationMatrix.raw_total || 0}`, '#7c3aed'],
            ].map(([label, count, color]) => <div key={String(label)} style={{ padding: '16px', borderRadius: '10px', border: `1px solid ${color}55`, background: `${color}12` }}><div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)' }}>{label}</div><div style={{ fontSize: '27px', fontWeight: 800, color: String(color), marginTop: '5px' }}>{count as any}</div></div>)}
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', flexWrap: 'wrap', marginBottom: '14px' }}>
            <select value={matrixTool} onChange={(event) => setMatrixTool(event.target.value)} style={{ padding: '8px 10px', borderRadius: '7px' }}>
              <option value="ALL">All scanners</option>
              {perToolMatrix.map((row: any) => <option key={row.tool} value={row.tool}>{row.tool}</option>)}
            </select>
            <button className={`filter-btn ${matrixMode === 'count' ? 'active' : ''}`} onClick={() => setMatrixMode('count')}>Count</button>
            <button className={`filter-btn ${matrixMode === 'percentage' ? 'active' : ''}`} onClick={() => setMatrixMode('percentage')}>Percentage</button>
          </div>
          {visibleToolMatrix.length > 0 ? <div style={{ overflowX: 'auto' }}><table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '800px', fontSize: '13px' }}><thead><tr style={{ background: 'var(--bg-glass-hover)' }}>{['Scanner / Tool', 'Total', 'Confirmed', 'False Positives', 'Human Review', 'Confirmed rate', 'Decision coverage'].map((heading) => <th key={heading} style={{ padding: '12px', textAlign: heading === 'Scanner / Tool' ? 'left' : 'center', borderBottom: '1px solid var(--border-glass)' }}>{heading}</th>)}</tr></thead><tbody>{visibleToolMatrix.map((row: any) => <tr key={row.tool}><td style={{ padding: '13px', borderBottom: '1px solid var(--border-glass)', fontWeight: 700 }}>{row.tool}</td><td style={{ padding: '13px', textAlign: 'center' }}>{matrixValue(row.total, row.total)}</td><td style={{ padding: '13px', textAlign: 'center', color: '#16a34a', fontWeight: 700 }}>{matrixValue(row.confirmed, row.total)}</td><td style={{ padding: '13px', textAlign: 'center', color: '#dc2626', fontWeight: 700 }}>{matrixValue(row.false_positives, row.total)}</td><td style={{ padding: '13px', textAlign: 'center', color: '#d97706', fontWeight: 700 }}>{matrixValue(row.unresolved, row.total)}</td><td style={{ padding: '13px', textAlign: 'center' }}>{row.confirmed_rate}%</td><td style={{ padding: '13px', textAlign: 'center' }}>{row.reviewed_rate}%</td></tr>)}</tbody></table></div> : <div className="empty-card"><h3>No per-tool outcomes yet</h3><p>Run a scan to populate scanner verification outcomes.</p></div>}
        </div>
      ) : (
        <>

      {activeView === 'confirmed' && chains.length > 0 && (
        <div className="chains-section">
          <h3>🔗 Attack Chain Pathways</h3>
          <div className="chains-grid">
            {chains.map((chain: any) => (
              <div key={chain.chain_id} className="chain-card">
                <div className="chain-card-header">
                  <span className="chain-id">{chain.chain_id}</span>
                  <span className={`badge badge-${chain.severity?.toLowerCase()}`}>{chain.severity}</span>
                </div>
                <h4>{chain.title}</h4>
                <p>{chain.impact}</p>
                <div className="chain-links">
                  <strong>Linked Findings:</strong> {chain.linked_finding_ids?.join(', ')}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeView === 'confirmed' && findings.length === 0 && rawFindings.length > 0 && (
        <div className="empty-card"><h3>No confirmed vulnerabilities</h3><p>{rawFindings.length} scanner result(s) were still reviewed. Open the False Positives or Human Review tabs to see the retained evidence and decision rationale.</p></div>
      )}
      <div className="findings-list">
        {filteredFindings.map((finding: any) => (
          <div key={finding.finding_id} className={`finding-item-card severity-${finding.severity?.toLowerCase()}`}>
            <div className="finding-header-row">
              <div className="left">
                <span className={`badge badge-${finding.severity?.toLowerCase()}`}>{finding.severity}</span>
                <span className="finding-id">{finding.finding_id}</span>
                <h4>{finding.title}</h4>
              </div>
              <span className="source-tag">Source: {finding.source}</span>
            </div>

            <div className="finding-meta-row">
              <span><strong>File:</strong> <code>{finding.file_path}</code> : L{finding.line_number}</span>
              <span><strong>CVSS Vector:</strong> <code>{finding.cvss_vector}</code></span>
              <span><strong>Status:</strong> <span className="status-confirmed">{finding.status || (activeView === 'confirmed' ? 'CONFIRMED' : activeView === 'rejected' ? 'FALSE_POSITIVE' : activeView === 'unresolved' ? 'UNRESOLVED' : 'RAW')}</span></span>
            </div>

            <p className="finding-summary">{finding.severity_summary || finding.reasoning}</p>
            {finding.reasoning && finding.severity_summary && <p><strong>Review rationale:</strong> {finding.reasoning}</p>}

            {finding.evidence && (
              <div className="code-evidence-box">
                <div className="box-title">Evidence & Context:</div>
                <pre><code>{finding.evidence.join('\n')}</code></pre>
              </div>
            )}

            {finding.remediation && (
              <div className="remediation-box">
                <div className="box-title">💡 LLM Remediation Fix:</div>
                <div className="remediation-text">{finding.remediation}</div>
              </div>
            )}
          </div>
        ))}
      </div>
      {filteredFindings.length === 0 && !(activeView === 'confirmed' && rawFindings.length > 0) && <div className="empty-card"><h3>No entries in this view</h3><p>No matching scanner results were recorded for the selected severity.</p></div>}
        </>
      )}
    </div>
  );
};
