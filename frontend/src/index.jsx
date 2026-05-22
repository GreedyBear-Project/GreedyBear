import "./styles/App.scss";

import React from "react";
import { createRoot } from "react-dom/client";
import axios from "axios";
import App from "./App";
import useAuthStore from "./stores/useAuthStore";

// axios interceptor to handle session expiration (401) or role sync (403)
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const { status, config } = error.response;
      // if 401, session is expired -> logout
      if (status === 401) {
        useAuthStore.getState().reset();
      }
      // if 403, permission denied -> refresh roles (unless it's already the auth check)
      else if (status === 403 && !config._isRetry) {
        config._isRetry = true;
        useAuthStore.getState().checkAuthentication();
      }
    }
    return Promise.reject(error);
  },
);

function noop() {}

// Vite uses import.meta.env.MODE, but Jest uses process.env.NODE_ENV
const isProduction =
  typeof process !== "undefined" && process.env.NODE_ENV === "test"
    ? false
    : import.meta.env.MODE !== "development";

if (isProduction) {
  console.debug = noop;
}

createRoot(document.getElementById("root")).render(<App />);
