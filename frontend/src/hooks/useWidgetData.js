import React from "react";
import axios from "axios";
import { useTimePickerStore } from "@greedybear/gb-ui";

/**
 * Map<cacheKey, { data: any, ts: number }>
 * Entries expire after CACHE_TTL_MS.
 */
const cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export function clearWidgetDataCache() {
  cache.clear();
}

/**
 * Shared data-fetching hook for dashboard widgets.
 *
 * Reads `range` from `useTimePickerStore` automatically, so callers
 * do not need to thread it through props.
 *
 * Caching: if (url, params, range) matches a recent cache entry (< 5 min old),
 * the cached data is returned immediately without firing a network request.
 * This prevents redundant fetches when the user switches widgets or the
 * component remounts while the selected time range has not changed.
 *
 * @param {string} url                API endpoint to fetch.
 * @param {Object} [extraParams={}]   Additional query params merged with { range }.
 * @returns {{ data: any, loading: boolean, error: string|null }}
 */
export default function useWidgetData(url, extraParams = {}) {
  const { range } = useTimePickerStore();

  const cacheKey = `${url}|${JSON.stringify(extraParams)}|${JSON.stringify(range)}`;

  const [data, setData] = React.useState(() => {
    const entry = cache.get(cacheKey);
    if (entry && Date.now() - entry.ts < CACHE_TTL_MS) return entry.data;
    return null;
  });
  const [loading, setLoading] = React.useState(() => {
    const entry = cache.get(cacheKey);
    return !(entry && Date.now() - entry.ts < CACHE_TTL_MS);
  });
  const [error, setError] = React.useState(null);

  React.useEffect(() => {
    const entry = cache.get(cacheKey);
    if (entry && Date.now() - entry.ts < CACHE_TTL_MS) {
      // Cache hit
      setData(entry.data);
      setLoading(false);
      setError(null);
      return;
    }

    const controller = new AbortController();
    let cancelled = false;

    setLoading(true);
    setError(null);

    axios
      .get(url, {
        params: { range, ...extraParams },
        signal: controller.signal,
      })
      .then((resp) => {
        if (cancelled) return;
        const result = resp.data ?? null;
        cache.set(cacheKey, { data: result, ts: Date.now() });
        setData(result);
        setLoading(false);
      })
      .catch((err) => {
        if (cancelled || axios.isCancel(err)) return;
        console.error(`[useWidgetData] fetch failed for ${url}:`, err);
        setError("Failed to load data.");
        setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cacheKey]);

  return { data, loading, error };
}
