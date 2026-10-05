import { useCallback, useEffect, useRef, useState } from 'react';
import { api, errorMessage } from '../services/api.js';

/** GET with loading/error state. `deps` re-fetch; `reload()` for manual/socket refresh. */
export function useApi(url, params, deps = []) {
  const [state, setState] = useState({ data: null, meta: null, loading: true, error: null });
  const key = JSON.stringify(params || {});
  const alive = useRef(true);
  const load = useCallback(async (silent = false) => {
    if (!url) return;
    if (!silent) setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const r = await api('get', url, undefined, params);
      if (alive.current) setState({ data: r.data, meta: r.meta, loading: false, error: null });
    } catch (e) {
      if (alive.current) setState((s) => ({ ...s, loading: false, error: errorMessage(e) }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, key, ...deps]);
  useEffect(() => { alive.current = true; load(); return () => { alive.current = false; }; }, [load]);
  return { ...state, reload: load, setData: (d) => setState((s) => ({ ...s, data: typeof d === 'function' ? d(s.data) : d })) };
}
