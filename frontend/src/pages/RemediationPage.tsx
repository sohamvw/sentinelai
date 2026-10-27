import React, { useEffect, useRef, useState } from 'react';
import { generateRemediation, getLatestScanStatus, getRemediationStatus, getRemediationDownloadUrl } from '../services/api';

export const RemediationPage: React.FC = () => {
  const [scan, setScan] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState('');
  const currentScanId = useRef<string | null>(null);
  const generating = useRef(false);

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const latest = await getLatestScanStatus();
        if (!active) return;
        const scanId = latest?.scan_id || null;
        if (scanId !== currentScanId.current) {
          currentScanId.current = scanId;
          setResult(null);
          setError('');
        }
        setScan(latest);
        if (scanId && latest?.status === 'COMPLETED' && !generating.current) {
          const saved = await getRemediationStatus(scanId);
          if (active && currentScanId.current === scanId) {
            setResult(saved?.status === 'GENERATED' && saved?.has_bundle ? saved : null);
          }
        } else if (latest?.status !== 'COMPLETED') {
          setResult(null);
        }
      } catch {
        if (active) setError('Unable to load the latest scan.');
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  const createBundle = async () => {
    if (!scan?.scan_id) return;
    // Do not keep showing a previous bundle while a new LLM request is in
    // progress; its counts belong to the prior generation attempt.
    setResult(null);
    generating.current = true;
    setLoading(true);
    setStartedAt(Date.now());
    setError('');
    try {
      setResult(await generateRemediation(scan.scan_id));
    } catch (err: any) {
      setError(err?.message || 'Could not generate the remediation bundle.');
    } finally {
      generating.current = false;
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!loading || !startedAt) return;
    const timer = window.setInterval(() => setElapsed(Math.floor((Date.now() - startedAt) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [loading, startedAt]);

  const completed = scan?.status === 'COMPLETED';
  return (
    <div className="remediation-container">
      <div className="remediation-hero">
        <div>
          <h2>LLM Remediation</h2>
        </div>
        <span className={`remediation-status ${completed ? 'ready' : 'pending'}`}>
          {completed ? 'Completed scan available' : 'Run a completed scan first'}
        </span>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="remediation-card">
        <h3>Review-first workflow</h3>
        <div className="remediation-stats">
          <div><span>Scan</span><strong>{scan?.scan_id || 'None'}</strong></div>
          <div><span>Confirmed findings</span><strong>{scan?.total_findings ?? '—'}</strong></div>
          <div><span>Compliance controls</span><strong>{scan?.policy_compliance?.checks?.length ?? '—'}</strong></div>
        </div>
        <button className="primary-auth-btn remediation-generate" disabled={!completed || loading} onClick={createBundle}>
          {loading ? `LLM is analyzing findings and policy context… ${elapsed}s` : 'Generate LLM Remediation Bundle'}
        </button>
      </div>

      {result?.status === 'GENERATED' && result?.has_bundle && (
        <div className="remediation-card result-card">
          <h3>{result.llm_error ? 'Evidence bundle ready' : 'LLM remediation results'}</h3>
          <p>
            {result.findings_before ?? 0} findings and {result.failed_controls_before ?? 0} failed controls were included.
          </p>
          <div className="remediation-result-stats">
            <div><span>LLM recommendations</span><strong>{result.recommendations_count ?? 0}</strong></div>
            <div><span>Patch proposals</span><strong>{result.patches_proposed ?? 0}</strong></div>
            <div><span>Changes applied</span><strong>{result.changes_applied ?? 0}</strong></div>
          </div>
          {result.llm_error && <div className="remediation-note"><strong>LLM analysis did not complete.</strong><p>{result.llm_error}</p></div>}
          {!result.llm_error && result.patches_proposed > result.changes_applied && (
            <p className="remediation-note">Some proposed patches did not pass validation. Review patch rejection details in the remediation plan inside the ZIP.</p>
          )}
          <div className="remediation-actions">
            <a className="primary-auth-btn" href={getRemediationDownloadUrl(result.scan_id)}>Download ZIP bundle</a>
          </div>
        </div>
      )}

    </div>
  );
};
