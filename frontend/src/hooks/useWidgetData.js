import React from "react";
import axios from "axios";
import { useTimePickerStore } from "@greedybear/gb-ui";

/**
 * Map<cacheKey, { data: any, ts: number }>
 * Entries expire after CACHE_TTL_MS.
 */
const cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

const inflight = new Map();

export function clearWidgetDataCache() {
  cache.clear();
  inflight.clear();
}

/**
 * Normalise raw attacker-countries API data into two structures consumed by
 * the dashboard map and bar-chart widgets.
 *
 * @param {any} rawData - Raw response from the API (may be null / non-array).
 * @returns {{
 *   countryDataMap: Record<string, number>,  // alpha-2 → aggregated count
 *   maxCount: number,                        // highest single-country count
 *   normalizedData: Array<{country:string, count:number, code:string}> // sorted desc
 * }}
 */
export function normalizeAttackerCountries(rawData) {
  const countryDataMap = {};
  const nameMap = {};
  let maxCount = 0;

  const raw = Array.isArray(rawData) ? rawData : [];
  raw.forEach((item) => {
    if (!item || typeof item !== "object") return;
    const code =
      typeof item.code === "string" ? item.code.toUpperCase() : null;
    if (!code) return;
    const count = Math.max(0, Number(item.count) || 0);
    countryDataMap[code] = (countryDataMap[code] || 0) + count;
    if (!nameMap[code]) nameMap[code] = item.country || code;
    if (countryDataMap[code] > maxCount) maxCount = countryDataMap[code];
  });

  const normalizedData = Object.entries(countryDataMap)
    .map(([code, count]) => ({ country: nameMap[code], count, code }))
    .sort((a, b) => b.count - a.count);

  return { countryDataMap, maxCount, normalizedData };
}

/**
 * Shared data-fetching hook for dashboard widgets.
 *
 * Reads `range` from `useTimePickerStore` automatically, so callers
 * do not need to thread it through props.
 *
 * Caching: if (url, params, range) matches a recent cache entry (< 5 min old),
 * the cached data is returned immediately without firing a network request.
 * In-flight deduplication: if the same key is already being fetched by another
 * component, the new caller subscribes to the same Promise instead of issuing
 * a second GET.
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

  React.useLayoutEffect(() => {
    const entry = cache.get(cacheKey);
    if (entry && Date.now() - entry.ts < CACHE_TTL_MS) {
      // Cache hit
      setData(null);
      setData(entry.data);
      setLoading(false);
      setError(null);
      return;
    }

    const controller = new AbortController();
    let cancelled = false;

    setLoading(true);
    setError(null);

    // Reuse an in-flight promise if one already exists for this key,
    // otherwise start a new request and register it.
    let promise = inflight.get(cacheKey);
    if (!promise) {
      promise = axios
        .get(url, {
          params: { range, ...extraParams },
          signal: controller.signal,
        })
        .then((resp) => resp.data ?? null)
        .finally(() => inflight.delete(cacheKey));
      inflight.set(cacheKey, promise);
    }

    promise
      .then((result) => {
        if (cancelled) return;
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
