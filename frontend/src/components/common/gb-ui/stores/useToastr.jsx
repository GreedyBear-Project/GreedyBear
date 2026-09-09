import { create } from "zustand";
import { nanoid } from "nanoid";

const toastTimeouts = new Map();

// store
const useToastr = create((set, get) => ({
  toasts: [],
  addToast: (header, body, color, showToggle = false, timeout = 4000) => {
    const payload = {
      id: `toast-${color}-${nanoid(4)}`,
      header,
      body,
      color,
      showToggle,
      timeout,
    };
    const timeoutId = setTimeout(() => {
      get().removeToast(payload.id);
      toastTimeouts.delete(payload.id);
    }, timeout);
    toastTimeouts.set(payload.id, timeoutId);
    set(({ toasts }) => ({
      toasts: [...toasts, payload],
    }));
  },
  removeToast: (id) => {
    const timeoutId = toastTimeouts.get(id);
    if (timeoutId) {
      clearTimeout(timeoutId);
      toastTimeouts.delete(id);
    }

    set(({ toasts }) => ({
      toasts: toasts.filter((t) => t.id !== id),
    }));
  },
}));

export default useToastr;
