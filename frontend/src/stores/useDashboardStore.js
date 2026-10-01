import axios from "axios";
import { create } from "zustand";
import { persist } from "zustand/middleware";

import { addToast } from "../components/common/gb-ui/index";

import {
  WIDGET_CONFIGS,
  DASHBOARD_LAYOUTS,
} from "../components/dashboard/defaultDashboardConfig";
import { DASHBOARD_CONFIG_URI } from "../constants/api";

/**
 * useDashboardStore
 *
 * Holds the live dashboard layout state that the ConfigEditor mutates.
 * Persisted to localStorage as a cache; the source-of-truth is the server
 * (GET /api/dashboard-config/).  On first load the server is fetched; when no
 * DB record exists the built-in defaults are used.
 *
 * Shape:
 *   layouts          {object}  react-grid-layout layouts object (all breakpoints)
 *   widgetConfigs    {Array}   ordered list of { type, id, noGrid? }
 *   isDirty          {boolean} true when there are unsaved changes
 *   savedVersion     {number}  incremented on every successful save; used as a
 *                              React key on DashboardRenderer to force a clean
 *                              RGL remount so new positions are picked up.
 *   serverSynced     {boolean} true once we have attempted a server fetch this
 *                              session (prevents redundant requests on re-render)
 */
const useDashboardStore = create(
  persist(
    (set, get) => ({
      layouts: DASHBOARD_LAYOUTS,
      widgetConfigs: WIDGET_CONFIGS,
      isDirty: false,
      savedVersion: 0,
      serverSynced: false,

      // ---------------------------------------------------------------- RGL --

      /** Called by RGL onLayoutChange, keeps layouts in sync with drag/resize */
      setLayouts: (layouts) => set({ layouts, isDirty: true }),

      /** Called when admin adds or removes a widget */
      setWidgetConfigs: (widgetConfigs) =>
        set({ widgetConfigs, isDirty: true }),

      // --------------------------------------------------------- local save --

      /**
       * Commit the current layout locally only (increments savedVersion so
       * DashboardRenderer remounts).  Used internally after a successful server
       * save, or can be called standalone for an optimistic local commit.
       */
      commitLocal: () =>
        set((s) => ({ isDirty: false, savedVersion: s.savedVersion + 1 })),
      save: () =>
        set((s) => ({ isDirty: false, savedVersion: s.savedVersion + 1 })),

      /** Reset to the hardcoded defaults (local only, does NOT call the API) */
      resetToDefault: () =>
        set((s) => ({
          layouts: DASHBOARD_LAYOUTS,
          widgetConfigs: WIDGET_CONFIGS,
          isDirty: false,
          savedVersion: s.savedVersion + 1,
          serverSynced: false,
        })),

      // ------------------------------------------------------- server fetch --

      /**
       * loadFromServer()
       *
       * Fetches the global dashboard config from the backend.
       * - If a record exists: apply it to the store.
       * - If the server returns null (no saved record): stay on current
       *   state (defaults or whatever localStorage holds).
       * - On network/auth error: silently stay on current state.
       *
       * Guards against redundant fetches with `serverSynced`.
       */
      loadFromServer: async () => {
        if (get().serverSynced) return;

        try {
          const resp = await axios.get(DASHBOARD_CONFIG_URI, {
            certegoUIenableProgressBar: false,
            headers: { "Content-Type": "application/json" },
          });

          const { layout } = resp.data;

          if (
            layout !== null &&
            layout !== undefined &&
            typeof layout === "object" &&
            Array.isArray(layout.widgetConfigs) &&
            layout.layouts
          ) {
            set((s) => ({
              widgetConfigs: layout.widgetConfigs,
              layouts: layout.layouts,
              isDirty: false,
              // Keep savedVersion so a pending local edit isn't wiped.
              savedVersion: s.savedVersion,
              serverSynced: true,
            }));
          } else {
            // keep defaults, mark as synced so we
            // don't keep hitting the server on every re-render.
            set({ serverSynced: true });
          }
        } catch (err) {
          // Unauthenticated users get a 401; treat silently (fallback to defaults).
          console.warn("DashboardConfig: could not load from server.", err);
          // Don't set serverSynced=true on error so a retry happens next mount.
        }
      },

      // ------------------------------------------------------- server save ---

      /**
       * saveToServer()
       *
       * PUTs the current layout to the backend (superuser only).
       * On success: commits locally (increments savedVersion, clears isDirty).
       * On failure: shows a toast, leaves isDirty=true so the user can retry.
       */
      saveToServer: async () => {
        const { widgetConfigs, layouts } = get();
        const layout = { widgetConfigs, layouts };

        try {
          await axios.put(
            DASHBOARD_CONFIG_URI,
            { layout },
            {
              certegoUIenableProgressBar: true,
              headers: { "Content-Type": "application/json" },
            },
          );

          get().commitLocal();
          addToast("Dashboard layout saved.", null, "success");
        } catch (err) {
          addToast(
            "Failed to save dashboard layout.",
            err?.parsedMsg ?? err?.message,
            "danger",
            true,
          );
        }
      },

      // ----------------------------------------------------- server reset ----

      /**
       * resetToServerDefault()
       *
       * Deletes the server record so all users fall back to built-in defaults,
       * then resets the local store too.  Superuser only.
       */
      resetToServerDefault: async () => {
        try {
          await axios.delete(DASHBOARD_CONFIG_URI, {
            certegoUIenableProgressBar: true,
          });
        } catch (err) {
          // 404 is fine (nothing to delete); other errors are shown.
          if (err?.response?.status !== 404) {
            addToast(
              "Failed to reset server dashboard config.",
              err?.parsedMsg ?? err?.message,
              "danger",
              true,
            );
            return;
          }
        }

        set((s) => ({
          layouts: DASHBOARD_LAYOUTS,
          widgetConfigs: WIDGET_CONFIGS,
          isDirty: false,
          savedVersion: s.savedVersion + 1,
          serverSynced: false,
        }));

        addToast(
          "Dashboard reset to defaults.",
          "The default layout has been restored for all users.",
          "info",
        );
      },
    }),
    {
      name: "greedybear-dashboard-config",
      // always re-check the server on a fresh
      // browser session so stale localStorage doesn't shadow a newer server config.
      partialize: (s) => ({
        layouts: s.layouts,
        widgetConfigs: s.widgetConfigs,
        isDirty: s.isDirty,
        savedVersion: s.savedVersion,
      }),
    },
  ),
);

export default useDashboardStore;
