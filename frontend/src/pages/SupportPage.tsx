import React, { useState } from 'react';
import { submitSupportTicket } from '../services/api';

interface SupportPageProps {
  user: any;
}

export const SupportPage: React.FC<SupportPageProps> = ({ user }) => {
  const [subject, setSubject] = useState('');
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [confirmation, setConfirmation] = useState('');

  const fullName = `${user?.first_name || ''} ${user?.last_name || ''}`.trim() || 'User';
  const email = user?.email || '';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setConfirmation('');

    if (!subject.trim() || !description.trim()) {
      setError('Subject and Description are required.');
      return;
    }

    setLoading(true);

    try {
      await submitSupportTicket({
        user_id: user?.user_id || '',
        user_name: fullName,
        user_email: email,
        subject: subject.trim(),
        description: description.trim(),
      });

      setConfirmation("Your ticket has been submitted, we'll get back to you soon.");
      setSubject('');
      setDescription('');
    } catch (err: any) {
      setError(err.message || 'An error occurred while submitting ticket.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="support-page-container" style={{ padding: '32px', maxWidth: '680px', margin: '0 auto' }}>
      <div className="glass-card" style={{ padding: '32px', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.08)' }}>
        <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '8px', color: 'var(--text-primary)' }}>
          Help & Support / Ticketing
        </h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '24px', fontSize: '14px' }}>
          Have an issue or technical question? Submit a ticket to reach our engineering team.
        </p>

        {error && <div className="auth-error-banner" style={{ marginBottom: '16px' }}>⚠️ {error}</div>}
        {confirmation && (
          <div className="auth-info-banner" style={{ marginBottom: '16px', background: 'rgba(16, 185, 129, 0.1)', borderColor: 'rgba(16, 185, 129, 0.3)', color: '#10b981' }}>
            ✅ {confirmation}
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-row">
            <div className="form-group">
              <label>Reporting User Name</label>
              <input
                type="text"
                value={fullName}
                readOnly
                disabled
                style={{ opacity: 0.7, cursor: 'not-allowed' }}
              />
            </div>
            <div className="form-group">
              <label>Reporting Work Email</label>
              <input
                type="email"
                value={email}
                readOnly
                disabled
                style={{ opacity: 0.7, cursor: 'not-allowed' }}
              />
            </div>
          </div>

          <div className="form-group">
            <label>Subject *</label>
            <input
              type="text"
              placeholder="e.g. Scan pipeline hanging on large repo"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label>Issue Description *</label>
            <textarea
              rows={5}
              placeholder="Please describe what happened, expected behavior, and any error message..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              style={{
                width: '100%',
                padding: '12px',
                borderRadius: '8px',
                background: 'var(--bg-glass-hover)',
                border: '1px solid var(--border-glass)',
                color: 'var(--text-main)',
                fontFamily: 'inherit',
                fontSize: '14px',
                resize: 'vertical'
              }}
              required
            />
          </div>

          <button type="submit" className="primary-auth-btn" disabled={loading} style={{ marginTop: '16px' }}>
            {loading ? 'Submitting Ticket...' : 'Submit Ticket'}
          </button>
        </form>
      </div>
    </div>
  );
};
