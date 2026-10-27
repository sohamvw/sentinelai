import React, { useState, useEffect } from 'react';
import { getAuditLogs } from '../services/api';

interface AuditLogsPageProps {
  scanId?: string;
}

export const AuditLogsPage: React.FC<AuditLogsPageProps> = ({ scanId }) => {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    try {
      const data = await getAuditLogs(scanId);
      setLogs(data.logs || []);
    } catch (err) {
      console.error('Failed to fetch audit logs', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 3000);
    return () => clearInterval(interval);
  }, [scanId]);

  return (
    <div className="audit-logs-container">
      <div className="logs-header">
        <div>
          <h2>Audit Logs & Execution History</h2>
          <p>Real-time audit stream of tool runs, stage transitions, and LLM reasoning events.</p>
        </div>
        <button className="theme-style-refresh" onClick={fetchLogs} title="Refresh audit logs">↻ <span>Refresh Logs</span></button>
      </div>

      {loading ? (
        <div className="loading-spinner">Loading audit logs stream...</div>
      ) : logs.length === 0 ? (
        <div className="empty-card">
          <p>No audit events recorded yet. Run a repository scan to capture execution history.</p>
        </div>
      ) : (
        <div className="logs-table-container">
          <table className="logs-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Scan ID</th>
                <th>Stage</th>
                <th>Tool Name</th>
                <th>Model Used</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {logs.slice().reverse().map((log) => (
                <tr key={log.id}>
                  <td className="log-time">{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td className="log-scan-id"><code>{log.scan_id}</code></td>
                  <td><span className="stage-pill">{log.stage}</span></td>
                  <td><strong>{log.tool_name}</strong></td>
                  <td><code>{log.model_used}</code></td>
                  <td className="log-msg">{log.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
