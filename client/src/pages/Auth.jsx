import { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { Brand } from '../layouts/AppLayout.jsx';
import { DEMO_MODE, errorMessage } from '../services/api.js';

function AuthForm({ mode }) {
  const { user, login, register } = useAuth();
  const nav = useNavigate();
  const [f, setF] = useState({ name: '', email: DEMO_MODE ? 'demo@sentinel.local' : '', password: DEMO_MODE ? 'demo-password-1' : '' });
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  if (user) return <Navigate to="/dashboard" replace />;
  const submit = async (e) => {
    e.preventDefault(); setErr(null); setBusy(true);
    try {
      if (mode === 'login') await login(f.email, f.password); else await register(f.name, f.email, f.password);
      nav('/dashboard');
    } catch (e2) { setErr(errorMessage(e2)); } finally { setBusy(false); }
  };
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  return (
    <div className="auth">
      <div className="auth-card panel">
        <Brand />
        <h1 style={{ fontSize: 22, marginBottom: 6 }}>{mode === 'login' ? 'Sign in' : 'Create an account'}</h1>
        <p className="muted small" style={{ marginBottom: 18 }}>{mode === 'login' ? 'Monitor the health and security of your BOSS 10 machines.' : 'The first account becomes the administrator. Later accounts start as viewers.'}</p>
        <form onSubmit={submit}>
          {mode === 'register' && <label className="field">Name<input required value={f.name} onChange={set('name')} autoComplete="name" /></label>}
          <label className="field">Email<input required type="email" value={f.email} onChange={set('email')} autoComplete="email" /></label>
          <label className="field">Password<input required type="password" minLength={mode === 'register' ? 10 : 1} value={f.password} onChange={set('password')} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} /></label>
          {mode === 'register' && <span className="small muted">At least 10 characters with a letter and a digit.</span>}
          {err && <p className="st-ERROR small" role="alert">{err}</p>}
          <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}</button>
        </form>
        <p className="small" style={{ marginTop: 16 }}>{mode === 'login' ? <>No account? <Link to="/register">Create one</Link></> : <>Have an account? <Link to="/login">Sign in</Link></>}</p>
      </div>
    </div>
  );
}

export const Login = () => <AuthForm mode="login" />;
export const Register = () => <AuthForm mode="register" />;
