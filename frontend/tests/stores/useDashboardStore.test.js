import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const localStorageStore = {};
const localStorageMock = {
  getItem: vi.fn((key) => localStorageStore[key] ?? null),
  setItem: vi.fn((key, value) => {
    localStorageStore[key] = value;
  }),
  removeItem: vi.fn((key) => {
    delete localStorageStore[key];
  }),
  clear: vi.fn(() => {
    Object.keys(localStorageStore).forEach((k) => delete localStorageStore[k]);
  }),
};
Object.defineProperty(global, "localStorage", { value: localStorageMock });

import useDashboardStore from "../../src/stores/useDashboardStore";
import {
  WIDGET_CONFIGS,
  DASHBOARD_LAYOUTS,
} from "../../src/components/dashboard/defaultDashboardConfig";

// helpter to reset store to defaults
function resetStore() {
  useDashboardStore.setState({
    layouts: DASHBOARD_LAYOUTS,
    widgetConfigs: WIDGET_CONFIGS,
    isDirty: false,
    savedVersion: 0,
  });
}

describe("useDashboardStore", () => {
  beforeEach(() => {
    resetStore();
    vi.clearAllMocks();
  });

  afterEach(() => {
    localStorageMock.clear();
  });

  // Initial state

  describe("initial state", () => {
    test("starts with default widget configs", () => {
      const { widgetConfigs } = useDashboardStore.getState();
      expect(widgetConfigs).toEqual(WIDGET_CONFIGS);
    });

    test("starts with default layouts", () => {
      const { layouts } = useDashboardStore.getState();
      expect(layouts).toEqual(DASHBOARD_LAYOUTS);
    });

    test("isDirty starts false", () => {
      expect(useDashboardStore.getState().isDirty).toBe(false);
    });

    test("savedVersion starts at 0", () => {
      expect(useDashboardStore.getState().savedVersion).toBe(0);
    });
  });

  // setLayouts

  describe("setLayouts", () => {
    test("replaces layouts and marks store dirty", () => {
      const newLayouts = { lg: [{ i: "X", x: 0, y: 0, w: 12, h: 9 }], md: [], sm: [] };
      useDashboardStore.getState().setLayouts(newLayouts);

      const state = useDashboardStore.getState();
      expect(state.layouts).toEqual(newLayouts);
      expect(state.isDirty).toBe(true);
    });

    test("does not change savedVersion", () => {
      useDashboardStore.getState().setLayouts({ lg: [], md: [], sm: [] });
      expect(useDashboardStore.getState().savedVersion).toBe(0);
    });
  });

  // setWidgetConfigs

  describe("setWidgetConfigs", () => {
    test("replaces widgetConfigs and marks store dirty", () => {
      const newConfigs = [{ type: "FeedsTypesChart", id: "FeedsTypesChart" }];
      useDashboardStore.getState().setWidgetConfigs(newConfigs);

      const state = useDashboardStore.getState();
      expect(state.widgetConfigs).toEqual(newConfigs);
      expect(state.isDirty).toBe(true);
    });
  });

  // save

  describe("save", () => {
    test("clears isDirty", () => {
      useDashboardStore.setState({ isDirty: true });
      useDashboardStore.getState().save();
      expect(useDashboardStore.getState().isDirty).toBe(false);
    });

    test("increments savedVersion by 1 each call", () => {
      useDashboardStore.getState().save();
      expect(useDashboardStore.getState().savedVersion).toBe(1);
      useDashboardStore.getState().save();
      expect(useDashboardStore.getState().savedVersion).toBe(2);
    });

    test("preserves current layouts and widgetConfigs", () => {
      const customLayouts = { lg: [{ i: "A", x: 0, y: 0, w: 6, h: 9 }], md: [], sm: [] };
      useDashboardStore.setState({ layouts: customLayouts, isDirty: true });
      useDashboardStore.getState().save();
      expect(useDashboardStore.getState().layouts).toEqual(customLayouts);
    });
  });

  // resetToDefault

  describe("resetToDefault", () => {
    test("restores default widgetConfigs", () => {
      useDashboardStore.setState({ widgetConfigs: [] });
      useDashboardStore.getState().resetToDefault();
      expect(useDashboardStore.getState().widgetConfigs).toEqual(WIDGET_CONFIGS);
    });

    test("restores default layouts", () => {
      useDashboardStore.setState({ layouts: { lg: [], md: [], sm: [] } });
      useDashboardStore.getState().resetToDefault();
      expect(useDashboardStore.getState().layouts).toEqual(DASHBOARD_LAYOUTS);
    });

    test("clears isDirty", () => {
      useDashboardStore.setState({ isDirty: true });
      useDashboardStore.getState().resetToDefault();
      expect(useDashboardStore.getState().isDirty).toBe(false);
    });

    test("increments savedVersion so Dashboard remounts DashboardRenderer", () => {
      const before = useDashboardStore.getState().savedVersion;
      useDashboardStore.getState().resetToDefault();
      expect(useDashboardStore.getState().savedVersion).toBe(before + 1);
    });
  });

  // savedVersion as React key

  describe("savedVersion remount signal", () => {
    test("save() always increments even when isDirty was already false", () => {
      // edge case, calling save twice without any dirty change
      useDashboardStore.getState().save();
      useDashboardStore.getState().save();
      expect(useDashboardStore.getState().savedVersion).toBe(2);
    });

    test("setLayouts does NOT increment savedVersion", () => {
      useDashboardStore.getState().setLayouts({ lg: [], md: [], sm: [] });
      expect(useDashboardStore.getState().savedVersion).toBe(0);
    });
  });

  // dirty / clean cycle

  describe("dirty / clean cycle", () => {
    test("setLayouts -> isDirty=true, save -> isDirty=false", () => {
      const store = useDashboardStore.getState();
      store.setLayouts({ lg: [], md: [], sm: [] });
      expect(useDashboardStore.getState().isDirty).toBe(true);
      useDashboardStore.getState().save();
      expect(useDashboardStore.getState().isDirty).toBe(false);
    });

    test("setWidgetConfigs -> isDirty=true, resetToDefault -> isDirty=false", () => {
      useDashboardStore.getState().setWidgetConfigs([]);
      expect(useDashboardStore.getState().isDirty).toBe(true);
      useDashboardStore.getState().resetToDefault();
      expect(useDashboardStore.getState().isDirty).toBe(false);
    });
  });
});
