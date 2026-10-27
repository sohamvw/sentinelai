import React, { useState } from 'react';
import { updateProfile } from '../services/api';

interface ProfilePageProps {
  user: any;
  onUpdateUser: (updatedUser: any) => void;
}

export const ProfilePage: React.FC<ProfilePageProps> = ({ user, onUpdateUser }) => {
  const [firstName, setFirstName] = useState(user?.first_name || '');
  const [lastName, setLastName] = useState(user?.last_name || '');
  const [username, setUsername] = useState(user?.username || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (newPassword && newPassword !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }

    if (newPassword && !currentPassword) {
      setError('Current password is required to update password.');
      return;
    }

    setLoading(true);

    try {
      const data = await updateProfile({
        email: user.email,
        first_name: firstName,
        last_name: lastName,
        username: username,
        current_password: currentPassword || undefined,
        new_password: newPassword || undefined,
      });

      onUpdateUser(data);
      setSuccess('Profile updated successfully!');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setError(err.message || 'An error occurred while updating profile.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="profile-page-container" style={{ padding: '32px', maxWidth: '680px', margin: '0 auto' }}>
      <div className="glass-card" style={{ padding: '32px', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.08)' }}>
        <h2 style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '8px', color: 'var(--text-primary)' }}>
          Account Settings & Profile
        </h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '24px', fontSize: '14px' }}>
          Update your account details and security credentials.
        </p>

        {error && <div className="auth-error-banner" style={{ marginBottom: '16px' }}>⚠️ {error}</div>}
        {success && <div className="auth-info-banner" style={{ marginBottom: '16px', background: 'rgba(16, 185, 129, 0.1)', borderColor: 'rgba(16, 185, 129, 0.3)', color: '#10b981' }}>✅ {success}</div>}

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-row">
            <div className="form-group">
              <label>First Name</label>
              <input
                type="text"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                required
              />
            </div>
            <div className="form-group">
              <label>Last Name</label>
              <input
                type="text"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
              />
            </div>
          </div>

          <div className="form-group">
            <label>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label>Work Email (Primary)</label>
            <input
              type="email"
              value={user?.email || ''}
              disabled
              style={{ opacity: 0.6, cursor: 'not-allowed' }}
            />
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Email address cannot be changed directly for security integrity.
            </span>
          </div>

          <hr style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.08)', margin: '24px 0' }} />

          <h3 style={{ fontSize: '16px', fontWeight: 'bold', marginBottom: '16px', color: 'var(--text-primary)' }}>
            Change Password
          </h3>

          <div className="form-group">
            <label>Current Password</label>
            <input
              type="password"
              placeholder="Required to confirm password change"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>New Password</label>
              <input
                type="password"
                placeholder="New strong password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label>Confirm New Password</label>
              <input
                type="password"
                placeholder="Re-enter new password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>
          </div>

          <button type="submit" className="primary-auth-btn" disabled={loading} style={{ marginTop: '16px' }}>
            {loading ? 'Saving Changes...' : 'Save Profile Changes'}
          </button>
        </form>
      </div>
    </div>
  );
};
