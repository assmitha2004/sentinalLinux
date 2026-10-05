import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import RiskGauge from '../components/RiskGauge.jsx';
import { Command, ErrorState, Severity, SeverityBar } from '../components/ui.jsx';
import { Login } from '../pages/Auth.jsx';
import { AuthProvider } from '../context/AuthContext.jsx';
import { bytes, healthWord } from '../utils/format.js';

describe('UI building blocks', () => {
  it('risk gauge shows score, band and empty state', () => {
    const { rerender } = render(<RiskGauge score={72} level="HIGH_RISK" />);
    expect(screen.getAllByText('72').length).toBeGreaterThan(0);
    expect(screen.getByLabelText(/Risk score 72 of 100, High risk/)).toBeInTheDocument();
    rerender(<RiskGauge score={null} />);
    expect(screen.getByText('No scan yet')).toBeInTheDocument();
  });
  it('commands are labelled read-only or modifying', () => {
    render(<><Command command="sshd -T" /><Command command="systemctl restart ssh" modifying /></>);
    expect(screen.getByText('Read-only check')).toBeInTheDocument();
    expect(screen.getByText(/Modifying/)).toBeInTheDocument();
  });
  it('error state explains and offers retry', () => {
    render(<ErrorState error="Cannot reach the SentinelAI server." onRetry={() => {}} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Cannot reach the SentinelAI server.');
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });
  it('severity badge and bar', () => {
    render(<><Severity value="CRITICAL" /><SeverityBar counts={{ CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 3 }} /></>);
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByRole('img')).toHaveAttribute('aria-label', '1 critical, 2 high, 0 medium, 3 low');
  });
  it('login page renders', async () => {
    render(<MemoryRouter><AuthProvider><Login /></AuthProvider></MemoryRouter>);
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
  });
  it('formatters', () => {
    expect(bytes(1536)).toBe('1.5 KB');
    expect(healthWord(90)).toBe('Healthy');
    expect(healthWord(null)).toBe('No data');
  });
});
