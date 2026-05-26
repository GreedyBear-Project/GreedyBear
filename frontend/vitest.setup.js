import '@testing-library/jest-dom';
import { vi } from 'vitest';

// react-grid-layout's WidthProvider uses ResizeObserver which is absent in jsdom.
// Stub it so tests that render the Dashboard (which includes DashboardRenderer +
// ResponsiveReactGridLayout) don't throw "ResizeObserver is not defined".
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

if (typeof globalThis.localStorage !== 'undefined' && typeof globalThis.localStorage.getItem !== 'function') {
    const store = {};
    globalThis.localStorage = {
        getItem: (key) => store[key] ?? null,
        setItem: (key, value) => { store[key] = String(value); },
        removeItem: (key) => { delete store[key]; },
        clear: () => { Object.keys(store).forEach(k => delete store[k]); },
        get length() { return Object.keys(store).length; },
        key: (i) => Object.keys(store)[i] ?? null,
    };
}




