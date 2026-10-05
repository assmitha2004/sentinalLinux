import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

const axis = { stroke: '#8f99b5', fontSize: 12, tickLine: false, axisLine: false };
const time = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const tip = { contentStyle: { background: '#1e2945', border: '1px solid #2a3657', borderRadius: 6, color: '#e7eaf3' }, labelFormatter: (t) => new Date(t).toLocaleString() };

/** series: [{ key, name, color, get(row) }] */
export function TimeChart({ data, series, unit = '%', max = 100, height = 200, format }) {
  const rows = (data || []).map((r) => Object.fromEntries([['t', r.timestamp || r.at], ...series.map((s) => [s.key, s.get(r)])]));
  const fmt = format || ((v) => `${Math.round(v)}${unit}`);
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={rows} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
        <CartesianGrid stroke="#2a3657" vertical={false} />
        <XAxis dataKey="t" tickFormatter={time} {...axis} minTickGap={40} />
        <YAxis domain={[0, max ?? 'auto']} tickFormatter={fmt} {...axis} width={max == null ? 80 : 50} />
        <Tooltip {...tip} formatter={(v) => fmt(v)} />
        {series.map((s) => <Area key={s.key} type="monotone" dataKey={s.key} name={s.name} stroke={s.color} fill={s.color} fillOpacity={0.12} strokeWidth={1.6} dot={false} isAnimationActive={false} connectNulls />)}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function ScoreHistory({ data, height = 180 }) {
  const spanDays = data.length > 1 ? (new Date(data[data.length - 1].at) - new Date(data[0].at)) / 864e5 : 0;
  const tick = (t) => (spanDays < 2 ? time(t) : new Date(t).toLocaleDateString([], { month: 'short', day: 'numeric' }));
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 6, right: 6, bottom: 0, left: -18 }}>
        <CartesianGrid stroke="#2a3657" vertical={false} />
        <XAxis dataKey="at" tickFormatter={tick} {...axis} minTickGap={40} />
        <YAxis domain={[0, 100]} {...axis} />
        <Tooltip {...tip} />
        <Line type="stepAfter" dataKey="risk" name="Risk score" stroke="#f2803a" strokeWidth={2} dot={false} isAnimationActive={false} />
        <Line type="monotone" dataKey="health" name="Health score" stroke="#45c08a" strokeWidth={1.6} dot={false} isAnimationActive={false} />
      </LineChart>
    </ResponsiveContainer>
  );
}
