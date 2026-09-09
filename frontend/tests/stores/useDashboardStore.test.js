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

vi.mock("axios", () => ({
  default: { get: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));

vi.mock("../../src/components/common/gb-ui/index", async (importOriginal) => ({
  ...(await importOriginal()),
  addToast: vi.fn(),
}));

import axios from "axios";
import useDashboardStore from "../../src/stores/useDashboardStore";
import {
  WIDGET_CONFIGS,
  DASHBOARD_LAYOUTS,
} from "../../src/components/dashboard/defaultDashboardConfig";

const CUSTOM_LAYOUT = {
  widgetConfigs: [{ type: "FeedsTypesChart", id: "FeedsTypesChart" }],
  layouts: {
    lg: [{ i: "FeedsTypesChart", x: 0, y: 0, w: 6, h: 9 }],
    md: [],
    sm: [],
  },
};

function resetStore() {
  useDashboardStore.setState({
    layouts: DASHBOARD_LAYOUTS,
    widgetConfigs: WIDGET_CONFIGS,
    isDirty: false,
    savedVersion: 0,
    serverSynced: false,
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
      expect(useDashboardStore.getState().widgetConfigs).toEqual(
        WIDGET_CONFIGS,
      );
    });

    test("starts with default layouts", () => {
      expect(useDashboardStore.getState().layouts).toEqual(DASHBOARD_LAYOUTS);
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
      const newLayouts = {
        lg: [{ i: "X", x: 0, y: 0, w: 12, h: 9 }],
        md: [],
        sm: [],
      };
      useDashboardStore.getState().setLayouts(newLayouts);
      expect(useDashboardStore.getState().layouts).toEqual(newLayouts);
      expect(useDashboardStore.getState().isDirty).toBe(true);
    });
  });

  // setWidgetConfigs

  describe("setWidgetConfigs", () => {
    test("replaces widgetConfigs and marks store dirty", () => {
      const newConfigs = [{ type: "FeedsTypesChart", id: "FeedsTypesChart" }];
      useDashboardStore.getState().setWidgetConfigs(newConfigs);
      expect(useDashboardStore.getState().widgetConfigs).toEqual(newConfigs);
      expect(useDashboardStore.getState().isDirty).toBe(true);
    });
  });

  // save

  describe("save", () => {
    test("clears isDirty and increments savedVersion", () => {
      useDashboardStore.setState({ isDirty: true });
      useDashboardStore.getState().save();
      expect(useDashboardStore.getState().isDirty).toBe(false);
      expect(useDashboardStore.getState().savedVersion).toBe(1);
    });
  });

  // resetToDefault

  describe("resetToDefault", () => {
    test("restores defaults and clears isDirty", () => {
      useDashboardStore.setState({ widgetConfigs: [], isDirty: true });
      useDashboardStore.getState().resetToDefault();
      expect(useDashboardStore.getState().widgetConfigs).toEqual(
        WIDGET_CONFIGS,
      );
      expect(useDashboardStore.getState().isDirty).toBe(false);
    });

    test("increments savedVersion", () => {
      useDashboardStore.getState().resetToDefault();
      expect(useDashboardStore.getState().savedVersion).toBe(1);
    });
  });

  // dirty / clean cycle

  describe("dirty / clean cycle", () => {
    test("setLayouts -> isDirty=true, save -> isDirty=false", () => {
      useDashboardStore.getState().setLayouts({ lg: [], md: [], sm: [] });
      expect(useDashboardStore.getState().isDirty).toBe(true);
      useDashboardStore.getState().save();
      expect(useDashboardStore.getState().isDirty).toBe(false);
    });
  });

  // loadFromServer

  describe("loadFromServer", () => {
    test("applies layout from server", async () => {
      axios.get.mockResolvedValue({ data: { layout: CUSTOM_LAYOUT } });
      await useDashboardStore.getState().loadFromServer();
      expect(useDashboardStore.getState().widgetConfigs).toEqual(
        CUSTOM_LAYOUT.widgetConfigs,
      );
      expect(useDashboardStore.getState().layouts).toEqual(
        CUSTOM_LAYOUT.layouts,
      );
    });

    test("leaves defaults when server returns null layout", async () => {
      axios.get.mockResolvedValue({ data: { layout: null } });
      await useDashboardStore.getState().loadFromServer();
      expect(useDashboardStore.getState().widgetConfigs).toEqual(
        WIDGET_CONFIGS,
      );
    });

    test("skips fetch when already synced", async () => {
      useDashboardStore.setState({ serverSynced: true });
      await useDashboardStore.getState().loadFromServer();
      expect(axios.get).not.toHaveBeenCalled();
    });

    test("leaves defaults on network error", async () => {
      axios.get.mockRejectedValue(new Error("network error"));
      await useDashboardStore.getState().loadFromServer();
      expect(useDashboardStore.getState().widgetConfigs).toEqual(
        WIDGET_CONFIGS,
      );
    });
  });

  // saveToServer

  describe("saveToServer", () => {
    test("clears isDirty and increments savedVersion on success", async () => {
      axios.put.mockResolvedValue({ data: {} });
      useDashboardStore.setState({ isDirty: true });
      await useDashboardStore.getState().saveToServer();
      expect(useDashboardStore.getState().isDirty).toBe(false);
      expect(useDashboardStore.getState().savedVersion).toBe(1);
    });

    test("leaves isDirty=true when PUT fails", async () => {
      axios.put.mockRejectedValue(new Error("server error"));
      useDashboardStore.setState({ isDirty: true });
      await useDashboardStore.getState().saveToServer();
      expect(useDashboardStore.getState().isDirty).toBe(true);
    });
  });

  // resetToServerDefault

  describe("resetToServerDefault", () => {
    test("restores defaults on success", async () => {
      axios.delete.mockResolvedValue({});
      useDashboardStore.setState({ widgetConfigs: [], isDirty: true });
      await useDashboardStore.getState().resetToServerDefault();
      expect(useDashboardStore.getState().widgetConfigs).toEqual(
        WIDGET_CONFIGS,
      );
      expect(useDashboardStore.getState().isDirty).toBe(false);
    });

    test("treats 404 as success and resets local state", async () => {
      const err = new Error("not found");
      err.response = { status: 404 };
      axios.delete.mockRejectedValue(err);
      await useDashboardStore.getState().resetToServerDefault();
      expect(useDashboardStore.getState().widgetConfigs).toEqual(
        WIDGET_CONFIGS,
      );
    });

    test("does not reset local state on non-404 error", async () => {
      const err = new Error("server error");
      err.response = { status: 500 };
      axios.delete.mockRejectedValue(err);
      useDashboardStore.setState({ widgetConfigs: [], isDirty: true });
      await useDashboardStore.getState().resetToServerDefault();
      expect(useDashboardStore.getState().widgetConfigs).toEqual([]);
      expect(useDashboardStore.getState().isDirty).toBe(true);
    });
  });
});
