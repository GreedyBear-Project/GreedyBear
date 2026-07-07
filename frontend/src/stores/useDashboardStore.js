import { create } from "zustand";
import { persist } from "zustand/middleware";

import {
  WIDGET_CONFIGS,
  DASHBOARD_LAYOUTS,
} from "../components/dashboard/defaultDashboardConfig";

/**
 * useDashboardStore
 *
 * Holds the live dashboard layout state that the ConfigEditor mutates.
 * Persisted to localStorage.
 *
 * Shape:
 *   layouts       {object}  react-grid-layout layouts object (all breakpoints)
 *   widgetConfigs {Array}   ordered list of { type, id, noGrid? }
 *   isDirty       {boolean} true when there are unsaved changes
 *   savedVersion  {number}  incremented on every save(); used as a React key on
 *                           DashboardRenderer to force a clean RGL remount so the
 *                           new positions are always picked up from props.
 */
const useDashboardStore = create(
  persist(
    (set) => ({
      layouts: DASHBOARD_LAYOUTS,
      widgetConfigs: WIDGET_CONFIGS,
      isDirty: false,
      savedVersion: 0,

      /** Called by RGL onLayoutChange, keeps layouts in sync with drag/resize */
      setLayouts: (layouts) => set({ layouts, isDirty: true }),

      /** Called when admin adds or removes a widget */
      setWidgetConfigs: (widgetConfigs) =>
        set({ widgetConfigs, isDirty: true }),

      /**
       * Commit the current layout.
       * Incrementing savedVersion causes Dashboard to remount DashboardRenderer
       * (via React key), which forces react-grid-layout to re-initialize its
       * internal layout state from the updated props.
       */
      save: () =>
        set((s) => ({ isDirty: false, savedVersion: s.savedVersion + 1 })),

      /** Reset to the hardcoded defaults */
      resetToDefault: () =>
        set((s) => ({
          layouts: DASHBOARD_LAYOUTS,
          widgetConfigs: WIDGET_CONFIGS,
          isDirty: false,
          savedVersion: s.savedVersion + 1,
        })),
    }),
    {
      name: "greedybear-dashboard-config",
    },
  ),
);

export default useDashboardStore;
