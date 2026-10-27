import React, { useState, useEffect } from 'react';
import { checkUsername, authPost, verifyOtp, forgotPasswordOtp, resetPassword, checkResetOtp, startOAuth, completeOAuth } from '../services/api';

interface AuthPageProps {
  onSuccess: (user: any, token: string) => void;
  initialMode?: 'signin' | 'signup' | 'verify-otp' | 'forgot-password';
  setAuthMode?: (mode: 'signin' | 'signup' | 'verify-otp' | 'forgot-password') => void;
}

export const AuthPage: React.FC<AuthPageProps> = ({ onSuccess, initialMode = 'signin', setAuthMode }) => {
  const [currentMode, setCurrentMode] = useState<'signin' | 'signup' | 'verify-otp' | 'forgot-password'>(initialMode);

  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [username, setUsername] = useState('');
  const [usernameStatus, setUsernameStatus] = useState<{ available?: boolean; reason?: string }>({});
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [signupConfirmPassword, setSignupConfirmPassword] = useState('');
  const [signupConfirmError, setSignupConfirmError] = useState('');
  const [showPassword, setShowPassword] = useState(false);


  // Forgot password state
  const [resetOtpDigits, setResetOtpDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [resetCodeVerified, setResetCodeVerified] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [confirmPasswordError, setConfirmPasswordError] = useState('');
  const [forgotStep, setForgotStep] = useState<'SEND_OTP' | 'RESET_PASS'>('SEND_OTP');


  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [showSignInLink, setShowSignInLink] = useState(false);
  const [loading, setLoading] = useState(false);

  const [passwordError, setPasswordError] = useState('');
  const [newPasswordError, setNewPasswordError] = useState('');
  const [emailError, setEmailError] = useState('');
  const [usernameError, setUsernameError] = useState('');

  // Sync mode changes when initialMode prop updates & validate verification session on mount/refresh
  useEffect(() => {
    if (initialMode === 'verify-otp') {
      const storedSession = sessionStorage.getItem('sentinel_pending_verify');
      if (storedSession) {
        try {
          const parsed = JSON.parse(storedSession);
          if (parsed.expiresAt && Date.now() < parsed.expiresAt) {
            setEmail(parsed.email || '');
            setFirstName(parsed.firstName || '');
            setCurrentMode('verify-otp');
            return;
          }
        } catch (e) {
          sessionStorage.removeItem('sentinel_pending_verify');
        }
      }
      // Invalid or expired session -> Redirect to sign in with message
      sessionStorage.removeItem('sentinel_pending_verify');
      setCurrentMode('signin');
      setError('Your verification session expired — please sign in or sign up again.');
      if (setAuthMode) setAuthMode('signin');
      window.history.pushState({}, '', '/login');
      return;
    }

    setCurrentMode(initialMode);
  }, [initialMode]);

  const switchMode = (mode: 'signin' | 'signup' | 'verify-otp' | 'forgot-password') => {
    if (mode !== 'verify-otp') {
      sessionStorage.removeItem('sentinel_pending_verify');
    }
    if (mode !== 'forgot-password') {
      // Reset the reset-password flow state so it doesn't leak across screens.
      setResetOtpDigits(['', '', '', '', '', '']);
      setResetCodeVerified(false);
      setNewPassword('');
      setConfirmPassword('');
      setNewPasswordError('');
      setConfirmPasswordError('');
      setForgotStep('SEND_OTP');
    }
    setCurrentMode(mode);
    setError('');
    setInfo('');
    setShowSignInLink(false);
    if (setAuthMode) {
      setAuthMode(mode);
    }
    const path = mode === 'signin' ? '/login' : mode === 'signup' ? '/signup' : mode === 'verify-otp' ? '/verify-otp' : '/forgot-password';
    window.history.pushState({}, '', path);
  };



  // Live debounced username validation & availability check
  useEffect(() => {
    if (currentMode !== 'signup' || !username.trim()) {
      setUsernameStatus({});
      setUsernameError('');
      return;
    }

    if (username.length < 3) {
      setUsernameError('Username must be at least 3 characters long.');
      setUsernameStatus({});
      return;
    }

    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      setUsernameError('Alphanumeric characters and underscores only.');
      setUsernameStatus({});
      return;
    }

    setUsernameError('');

    const timer = setTimeout(async () => {
      try {
        const data = await checkUsername(username);
        setUsernameStatus(data);
      } catch (err) {
        setUsernameStatus({});
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [username, currentMode]);

  const validateEmail = (val: string) => {
    setEmail(val);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (val && !emailRegex.test(val)) {
      setEmailError('Please enter a valid email address (e.g. name@domain.com).');
    } else {
      setEmailError('');
    }
  };

  const validatePassword = (val: string, setter: (msg: string) => void) => {
    if (!val) {
      setter('');
      return;
    }
    const hasMinLen = val.length >= 8;
    const hasUpper = /[A-Z]/.test(val);
    const hasLower = /[a-z]/.test(val);
    const hasNumber = /[0-9]/.test(val);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(val);

    if (!hasMinLen || !hasUpper || !hasLower || !hasNumber || !hasSpecial) {
      setter('Password must be at least 8 characters long and contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character (!@#$%^&*).');
    } else {
      setter('');
    }
  };


  const [otpDigits, setOtpDigits] = useState<string[]>(['', '', '', '', '', '']);

  const handleOtpBoxChange = (index: number, val: string) => {
    if (!/^\d*$/.test(val)) return;
    const newDigits = [...otpDigits];
    newDigits[index] = val.slice(-1);
    setOtpDigits(newDigits);

    if (val && index < 5) {
      const nextInput = document.getElementById(`otp-input-${index + 1}`);
      if (nextInput) nextInput.focus();
    }
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !otpDigits[index] && index > 0) {
      const prevInput = document.getElementById(`otp-input-${index - 1}`);
      if (prevInput) prevInput.focus();
    }
  };

  const handleOtpPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (!pasted) return;
    const newDigits = pasted.split('').concat(Array(6).fill('')).slice(0, 6);
    setOtpDigits(newDigits);
    const lastFilledIndex = Math.min(pasted.length, 5);
    const targetInput = document.getElementById(`otp-input-${lastFilledIndex}`);
    if (targetInput) targetInput.focus();
  };

  // Reset-flow OTP box handlers (separate state from the verify-otp flow).
  const handleResetOtpBoxChange = (index: number, val: string) => {
    if (!/^\d*$/.test(val)) return;
    const next = [...resetOtpDigits];
    next[index] = val.slice(-1);
    setResetOtpDigits(next);
    if (val && index < 5) {
      const nextInput = document.getElementById(`reset-otp-input-${index + 1}`);
      if (nextInput) nextInput.focus();
    }
  };
  const handleResetOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !resetOtpDigits[index] && index > 0) {
      const prevInput = document.getElementById(`reset-otp-input-${index - 1}`);
      if (prevInput) prevInput.focus();
    }
  };
  const handleResetOtpPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (!pasted) return;
    setResetOtpDigits(pasted.split('').concat(Array(6).fill('')).slice(0, 6));
    const lastFilledIndex = Math.min(pasted.length, 5);
    const targetInput = document.getElementById(`reset-otp-input-${lastFilledIndex}`);
    if (targetInput) targetInput.focus();
  };


  const handleSubmitAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setInfo('');
    setShowSignInLink(false);

    if (emailError || !email) {
      setError('Please provide a valid email address.');
      return;
    }

    if (currentMode === 'signup') {
      if (!firstName.trim() || !username.trim()) {
        setError('First name, Username, Email, and Password are required.');
        return;
      }
      if (usernameError || usernameStatus.available === false) {
        setError('Please select a valid, available username.');
        return;
      }
      if (passwordError || !password) {
        setError('Please fulfill all password complexity requirements.');
        return;
      }
      if (password !== signupConfirmPassword) {
        setError('Passwords do not match.');
        return;
      }
    }

    setLoading(true);
    const endpoint = currentMode === 'signup' ? '/register' : '/login';
    const body = currentMode === 'signup'
      ? { first_name: firstName, last_name: lastName, username: username.trim(), email, password }
      : { email, password };

    try {
      const data = await authPost(endpoint, body);

      if (data.user && data.user.first_name) {
        setFirstName(data.user.first_name);
      }

      if (data.requires_verification) {

        const verifySessionData = {
          email: email,
          firstName: data.user?.first_name || firstName,
          expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
        };
        sessionStorage.setItem('sentinel_pending_verify', JSON.stringify(verifySessionData));
        switchMode('verify-otp');

        setInfo(`Check ${email} — the code expires in 10 minutes`);
      } else {
        sessionStorage.removeItem('sentinel_pending_verify');
        onSuccess(data.user, data.access_token);
      }
    } catch (err: any) {
      if (err.status === 409) {
        setShowSignInLink(true);
        setError(err.message || 'An account with this email already exists.');
        setTimeout(() => { switchMode('signin'); }, 3000);
        return;
      }
      setError(err.message || 'Authentication error encountered.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const submittedCode = otpDigits.join('');
    if (submittedCode.length !== 6) {
      setError('Please enter the full 6-digit verification code.');
      return;
    }

    setLoading(true);
    try {
      const data = await verifyOtp({ email, code: submittedCode });

      sessionStorage.removeItem('sentinel_pending_verify');
      onSuccess(data.user, data.access_token);
    } catch (err: any) {
      setError(err.message || 'Verification code failed');
    } finally {
      setLoading(false);
    }
  };



  const handleForgotPasswordOtpSend = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setInfo('');

    if (!email || emailError) {
      setError('Please enter a valid email address.');
      return;
    }

    setLoading(true);
    try {
      await forgotPasswordOtp({ email });

      setForgotStep('RESET_PASS');
      setResetOtpDigits(['', '', '', '', '', '']);
      setResetCodeVerified(false);
      setNewPassword('');
      setConfirmPassword('');
      setNewPasswordError('');
      setConfirmPasswordError('');
      setInfo(`Password reset code dispatched to ${email}.`);

    } catch (err: any) {
      setError(err.message || 'Error requesting password reset.');
    } finally {
      setLoading(false);
    }
  };

  const handleResetCodeCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const submittedCode = resetOtpDigits.join('');
    if (submittedCode.length !== 6) {
      setError('Please enter the full 6-digit code.');
      return;
    }

    setLoading(true);
    try {
      await checkResetOtp({ email, code: submittedCode });
      setResetCodeVerified(true);
      setError('');
      setInfo('Code verified — set your new password below.');
    } catch (err: any) {
      setError(err.message || 'Invalid or expired code.');
      // Clear the boxes so the user can retype cleanly
      setResetOtpDigits(['', '', '', '', '', '']);
      const firstBox = document.getElementById('reset-otp-input-0');
      if (firstBox) firstBox.focus();
    } finally {
      setLoading(false);
    }
  };

  const handleResetPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!resetCodeVerified) {
      setError('Please verify the 6-digit code first.');
      return;
    }
    if (newPasswordError || !newPassword) {
      setError('Please fulfill password complexity rules.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    const submittedCode = resetOtpDigits.join('');

    setLoading(true);
    try {
      const data = await resetPassword({ email, code: submittedCode, new_password: newPassword });
      onSuccess(data.user, data.access_token);
    } catch (err: any) {
      setError(err.message || 'Password reset error');
    } finally {
      setLoading(false);
    }
  };

  const handleOAuth = async (provider: 'github') => {
    setLoading(true);
    setError('');
    try {
      const data = await startOAuth(provider);
      if (data.url && (data.url.startsWith('http://') || data.url.startsWith('https://'))) {
        window.location.href = data.url;
      } else {
        const cbData = await completeOAuth(provider, 'dev_test_code');
        onSuccess(cbData.user, cbData.access_token);
      }
    } catch (err) {
      setError(`OAuth sign-in with ${provider} failed.`);
    } finally {
      setLoading(false);
    }
  };

  // Real-time password requirement checklist
  const passwordRules = {
    hasMinLen: password.length >= 8,
    hasUpper: /[A-Z]/.test(password),
    hasLower: /[a-z]/.test(password),
    hasNumber: /[0-9]/.test(password),
    hasSpecial: /[!@#$%^&*(),.?":{}|<>]/.test(password),
  };

  const isPasswordValid = Object.values(passwordRules).every(Boolean);

  return (
    <div className="auth-page-container">
      <div className="auth-card">
        {currentMode === 'signin' || currentMode === 'signup' ? (
          <>
            <div className="auth-header">
              <h2>{currentMode === 'signup' ? 'Create Account' : 'Sign In'}</h2>
            </div>




            {error && (
              <div className="auth-error-banner">
                <div>⚠️ {error}</div>
                {showSignInLink && (
                  <button
                    type="button"
                    onClick={() => switchMode('signin')}
                    style={{
                      alignSelf: 'flex-start',
                      background: '#FF6B1A',
                      color: 'white',
                      border: 'none',
                      padding: '4px 10px',
                      borderRadius: '4px',
                      fontSize: '12px',
                      fontWeight: 'bold',
                      cursor: 'pointer'
                    }}
                  >
                    👉 Go to Sign In Now
                  </button>
                )}
              </div>
            )}
            {info && <div className="auth-info-banner">ℹ️ {info}</div>}

            <form onSubmit={handleSubmitAuth} className="auth-form" method="post" action="#">
              {currentMode === 'signup' && (
                <>
                  <div className="form-row">
                    <div className="form-group">
                      <label>First Name *</label>
                      <input
                        type="text"
                        name="given-name"
                        autoComplete="given-name"
                        placeholder="Soham"
                        value={firstName}
                        onChange={(e) => setFirstName(e.target.value)}
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label>Last Name (Optional)</label>
                      <input
                        type="text"
                        name="family-name"
                        autoComplete="family-name"
                        placeholder="Engineer"
                        value={lastName}
                        onChange={(e) => setLastName(e.target.value)}
                      />
                    </div>
                  </div>

                  <div className="form-group">
                    <label>Username *</label>
                    <input
                      type="text"
                      name="username"
                      autoComplete="username"
                      placeholder="soham_sec"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      required
                    />
                    {usernameError && <span style={{ color: '#ef4444', fontSize: '11px', marginTop: '4px' }}>⚠️ {usernameError}</span>}
                    {!usernameError && usernameStatus.available === true && (
                      <span style={{ color: '#10b981', fontSize: '11px', marginTop: '4px' }}>✅ Username is available!</span>
                    )}
                    {!usernameError && usernameStatus.available === false && (
                      <span style={{ color: '#ef4444', fontSize: '11px', marginTop: '4px' }}>❌ {usernameStatus.reason || 'Username is already taken.'}</span>
                    )}
                  </div>
                </>
              )}

              <div className="form-group">
                <label>Email *</label>

                <input
                  type="email"
                  name="email"
                  autoComplete="username"
                  placeholder="developer@company.com"
                  value={email}
                  onChange={(e) => validateEmail(e.target.value)}
                  required
                />
                {emailError && <span style={{ color: '#ef4444', fontSize: '11px', marginTop: '4px' }}>{emailError}</span>}
              </div>

              <div className="form-group">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <label>Password *</label>
                  {currentMode === 'signin' && (
                    <a
                      href="#forgot-password"
                      onClick={(e) => { e.preventDefault(); switchMode('forgot-password'); }}
                      style={{ fontSize: '12px', color: '#FF6B1A', textDecoration: 'none' }}
                    >
                      Forgot password?
                    </a>
                  )}
                </div>
                <div style={{ position: 'relative' }}>
                  <input
                    type={showPassword ? 'text' : 'password'}
                    name="password"
                    autoComplete={currentMode === 'signup' ? 'new-password' : 'current-password'}
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (currentMode === 'signup') validatePassword(e.target.value, setPasswordError);
                    }}
                    style={{ width: '100%', paddingRight: '40px' }}
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{
                      position: 'absolute',
                      right: '10px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-secondary)',
                      cursor: 'pointer',
                      fontSize: '16px',
                      display: 'flex',
                      alignItems: 'center',
                      padding: '4px'
                    }}
                    title={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? (
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                        <line x1="1" y1="1" x2="23" y2="23"></line>
                      </svg>
                    ) : (
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                        <circle cx="12" cy="12" r="3"></circle>
                      </svg>
                    )}
                  </button>
                </div>

                {currentMode === 'signup' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '8px', fontSize: '11px', background: 'rgba(255,255,255,0.02)', padding: '8px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ color: passwordRules.hasMinLen ? '#10b981' : '#a1a1aa' }}>
                      {passwordRules.hasMinLen ? '✓' : '○'} At least 8 characters
                    </div>
                    <div style={{ color: passwordRules.hasUpper ? '#10b981' : '#a1a1aa' }}>
                      {passwordRules.hasUpper ? '✓' : '○'} At least 1 uppercase letter (A-Z)
                    </div>
                    <div style={{ color: passwordRules.hasLower ? '#10b981' : '#a1a1aa' }}>
                      {passwordRules.hasLower ? '✓' : '○'} At least 1 lowercase letter (a-z)
                    </div>
                    <div style={{ color: passwordRules.hasNumber ? '#10b981' : '#a1a1aa' }}>
                      {passwordRules.hasNumber ? '✓' : '○'} At least 1 number (0-9)
                    </div>
                    <div style={{ color: passwordRules.hasSpecial ? '#10b981' : '#a1a1aa' }}>
                      {passwordRules.hasSpecial ? '✓' : '○'} At least 1 special character (!@#$%^&*)
                    </div>
                  </div>
                )}
              </div>

              {currentMode === 'signup' && (
                <div className="form-group">
                  <label>Confirm Password *</label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      name="confirm-password"
                      autoComplete="new-password"
                      placeholder="Re-enter your password"
                      value={signupConfirmPassword}
                      onChange={(e) => {
                        const val = e.target.value;
                        setSignupConfirmPassword(val);
                        if (val && val !== password) {
                          setSignupConfirmError('Passwords do not match.');
                        } else {
                          setSignupConfirmError('');
                        }
                      }}
                      style={{ width: '100%', paddingRight: '40px' }}
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      style={{
                        position: 'absolute',
                        right: '10px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-secondary)',
                        cursor: 'pointer',
                        fontSize: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        padding: '4px'
                      }}
                      title={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? (
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                          <line x1="1" y1="1" x2="23" y2="23"></line>
                        </svg>
                      ) : (
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                          <circle cx="12" cy="12" r="3"></circle>
                        </svg>
                      )}
                    </button>
                  </div>
                  {signupConfirmError && (
                    <span style={{ color: '#ef4444', fontSize: '11px', marginTop: '4px' }}>
                      ⚠️ {signupConfirmError}
                    </span>
                  )}
                  {!signupConfirmError && signupConfirmPassword && password === signupConfirmPassword && (
                    <span style={{ color: '#10b981', fontSize: '11px', marginTop: '4px' }}>
                      ✅ Passwords match
                    </span>
                  )}
                </div>
              )}

              <button
                type="submit"
                className="primary-auth-btn"
                disabled={loading || (currentMode === 'signup' && (!isPasswordValid || usernameStatus.available === false))}
              >
                {loading ? 'Processing...' : currentMode === 'signup' ? 'Create Account' : 'Sign In'}
              </button>
            </form>



            {currentMode === 'signin' && (
              <>
                <div className="auth-divider">
                  <span>OR CONTINUE WITH</span>
                </div>

                <div className="oauth-buttons-row">
                  <button className="oauth-btn github" onClick={() => handleOAuth('github')} disabled={loading} style={{ width: '100%' }}>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style={{ marginRight: '8px' }}>
                      <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                    </svg>
                    GitHub
                  </button>
                </div>
              </>
            )}



            <div className="auth-footer-toggle">
              {currentMode === 'signup' ? (
                <p>Already have an account? <a href="/login" onClick={(e) => { e.preventDefault(); switchMode('signin'); }}>Sign In</a></p>
              ) : (
                <p>Don't have an account? <a href="/signup" onClick={(e) => { e.preventDefault(); switchMode('signup'); }}>Sign Up</a></p>
              )}
            </div>

          </>
        ) : currentMode === 'verify-otp' ? (
          <>
            <div className="auth-header">
              <h2>Enter 6-Digit Verification Code</h2>
              <p>Hey <strong>{firstName || 'there'}</strong>, we sent a code to <strong>{email}</strong></p>
            </div>

            {error && <div className="auth-error-banner">⚠️ {error}</div>}
            {info && <div className="auth-info-banner">ℹ️ {info}</div>}


            <form onSubmit={handleVerifyOtp} className="auth-form">
              <div className="form-group">
                <label>6-Digit Verification Code</label>
                <div className="otp-inputs-grid">
                  {otpDigits.map((digit, idx) => (
                    <input
                      key={idx}
                      id={`otp-input-${idx}`}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      className={`otp-box ${digit ? 'filled' : ''}`}
                      value={digit}
                      onChange={(e) => handleOtpBoxChange(idx, e.target.value)}
                      onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                      onPaste={handleOtpPaste}
                      autoFocus={idx === 0}
                      required
                    />
                  ))}
                </div>
              </div>

              <button type="submit" className="primary-auth-btn" disabled={loading || otpDigits.join('').length !== 6}>
                {loading ? 'Verifying...' : '✅ Verify Code & Access Dashboard'}
              </button>
            </form>


            <div className="otp-actions-row">
              <button type="button" className="text-btn" onClick={() => switchMode('signin')}>
                ← Back to Sign In
              </button>
            </div>
          </>
        ) : (
          /* Forgot Password Flow */
          <>
            <div className="auth-header">
              <h2>Reset Password</h2>
              <p>{forgotStep === 'SEND_OTP' ? 'Enter your registered email to receive a 6-digit verification code.' : `Enter the 6-digit code sent to ${email} and choose a new password.`}</p>
            </div>

            {error && <div className="auth-error-banner">⚠️ {error}</div>}
            {info && <div className="auth-info-banner">ℹ️ {info}</div>}


            {forgotStep === 'SEND_OTP' ? (
              <form onSubmit={handleForgotPasswordOtpSend} className="auth-form">
                <div className="form-group">
                  <label>Email *</label>

                  <input
                    type="email"
                    placeholder="developer@company.com"
                    value={email}
                    onChange={(e) => validateEmail(e.target.value)}
                    required
                  />
                  {emailError && <span style={{ color: '#ef4444', fontSize: '11px', marginTop: '4px' }}>{emailError}</span>}
                </div>

                <button type="submit" className="primary-auth-btn" disabled={loading}>
                  {loading ? 'Sending Code...' : 'Send Reset Code'}
                </button>
              </form>

            ) : (
              !resetCodeVerified ? (
                <form onSubmit={handleResetCodeCheck} className="auth-form">
                  <div className="form-group">
                    <label>6-Digit Reset Code *</label>
                    <div className="otp-inputs-grid">
                      {resetOtpDigits.map((digit, idx) => (
                        <input
                          key={idx}
                          id={`reset-otp-input-${idx}`}
                          type="text"
                          inputMode="numeric"
                          maxLength={1}
                          className={`otp-box ${digit ? 'filled' : ''}`}
                          value={digit}
                          onChange={(e) => handleResetOtpBoxChange(idx, e.target.value)}
                          onKeyDown={(e) => handleResetOtpKeyDown(idx, e)}
                          onPaste={handleResetOtpPaste}
                          autoFocus={idx === 0}
                          required
                        />
                      ))}
                    </div>
                    <span style={{ color: '#a1a1aa', fontSize: '11px', marginTop: '8px', textAlign: 'center', display: 'block' }}>
                      Enter the 6 digits we sent to <strong>{email}</strong>
                    </span>
                  </div>

                  <button
                    type="submit"
                    className="primary-auth-btn"
                    disabled={loading || resetOtpDigits.join('').length !== 6}
                  >
                    {loading ? 'Verifying...' : 'Verify Code'}
                  </button>
                </form>
              ) : (
                <form onSubmit={handleResetPasswordSubmit} className="auth-form">
                  <div style={{ background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#10b981', padding: '8px 12px', borderRadius: '8px', fontSize: '12px', marginBottom: '4px', textAlign: 'center' }}>
                    ✅ Code verified — choose a new password
                  </div>

                  <div className="form-group">
                    <label>New Password *</label>
                    <div style={{ position: 'relative' }}>
                      <input
                        type={showPassword ? 'text' : 'password'}
                        placeholder="••••••••••••"
                        value={newPassword}
                        onChange={(e) => {
                          setNewPassword(e.target.value);
                          validatePassword(e.target.value, setNewPasswordError);
                        }}
                        style={{ width: '100%', paddingRight: '40px' }}
                        autoFocus
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        style={{
                          position: 'absolute',
                          right: '10px',
                          top: '50%',
                          transform: 'translateY(-50%)',
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-secondary)',
                          cursor: 'pointer',
                          fontSize: '16px',
                          display: 'flex',
                          alignItems: 'center',
                          padding: '4px'
                        }}
                        title={showPassword ? "Hide password" : "Show password"}
                      >
                        {showPassword ? (
                          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                            <line x1="1" y1="1" x2="23" y2="23"></line>
                          </svg>
                        ) : (
                          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                            <circle cx="12" cy="12" r="3"></circle>
                          </svg>
                        )}
                      </button>
                    </div>
                    <span style={{ color: '#a1a1aa', fontSize: '11px', marginTop: '4px' }}>
                      Min 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character.
                    </span>
                    {newPasswordError && (
                      <span style={{ color: '#ef4444', fontSize: '11px', marginTop: '4px', display: 'block' }}>
                        ⚠️ {newPasswordError}
                      </span>
                    )}
                  </div>

                  <div className="form-group">
                    <label>Confirm New Password *</label>
                    <div style={{ position: 'relative' }}>
                      <input
                        type={showPassword ? 'text' : 'password'}
                        placeholder="••••••••••••"
                        value={confirmPassword}
                        onChange={(e) => {
                          const val = e.target.value;
                          setConfirmPassword(val);
                          if (val && val !== newPassword) {
                            setConfirmPasswordError('Passwords do not match.');
                          } else {
                            setConfirmPasswordError('');
                          }
                        }}
                        style={{ width: '100%', paddingRight: '40px' }}
                        required
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        style={{
                          position: 'absolute',
                          right: '10px',
                          top: '50%',
                          transform: 'translateY(-50%)',
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-secondary)',
                          cursor: 'pointer',
                          fontSize: '16px',
                          display: 'flex',
                          alignItems: 'center',
                          padding: '4px'
                        }}
                        title={showPassword ? "Hide password" : "Show password"}
                      >
                        {showPassword ? (
                          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                            <line x1="1" y1="1" x2="23" y2="23"></line>
                          </svg>
                        ) : (
                          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                            <circle cx="12" cy="12" r="3"></circle>
                          </svg>
                        )}
                      </button>
                    </div>
                    {confirmPasswordError && (
                      <span style={{ color: '#ef4444', fontSize: '11px', marginTop: '4px' }}>
                        ⚠️ {confirmPasswordError}
                      </span>
                    )}
                    {!confirmPasswordError && confirmPassword && confirmPassword === newPassword && (
                      <span style={{ color: '#10b981', fontSize: '11px', marginTop: '4px' }}>
                        ✅ Passwords match
                      </span>
                    )}
                  </div>

                  <button type="submit" className="primary-auth-btn" disabled={loading}>
                    {loading ? 'Resetting Password...' : '🔑 Update Password & Access Dashboard'}
                  </button>
                </form>
              )
            )}

            <div className="otp-actions-row">
              <button type="button" className="text-btn" onClick={() => switchMode('signin')}>
                ← Back to Sign In
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
