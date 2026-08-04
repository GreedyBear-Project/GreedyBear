import React from "react";
import "@testing-library/jest-dom";
import { render, screen, fireEvent, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// Mock react-grid-layout
vi.mock("react-grid-layout", () => ({
  Responsive: ({ children }) => <div data-testid="rgl-grid">{children}</div>,
  useContainerWidth: () => ({ width: 1200, containerRef: { current: null } }),
}));

// Mock all real widget components to divs
vi.mock("../../../src/components/dashboard/utils/charts", () => ({
  FeedsTypesChart: () => <div data-testid="widget-FeedsTypesChart" />,
  FeedsSourcesChart: () => <div data-testid="widget-FeedsSourcesChart" />,
  FeedsDownloadsChart: () => <div data-testid="widget-FeedsDownloadsChart" />,
  EnrichmentSourcesChart: () => (
    <div data-testid="widget-EnrichmentSourcesChart" />
  ),
  EnrichmentRequestsChart: () => (
    <div data-testid="widget-EnrichmentRequestsChart" />
  ),
  AttackOriginCountriesChart: () => (
    <div data-testid="widget-AttackOriginCountriesChart" />
  ),
}));

vi.mock("../../../src/components/dashboard/AttackOriginMap", () => ({
  default: () => <div data-testid="widget-AttackOriginMap" />,
}));

vi.mock("../../../src/components/dashboard/EnrichmentLookup", () => ({
  default: () => <div data-testid="widget-EnrichmentLookup" />,
}));

vi.mock("axios");

// Mock @greedybear/gb-ui
vi.mock("@greedybear/gb-ui", async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    SmallInfoCard: ({ header, body, style, id }) => (
      <div data-testid={`card-${id}`} style={style}>
        <div>{header}</div>
        <div>{body}</div>
      </div>
    ),
    ElasticTimePicker: () => <div />,
  };
});

// Mock useAuthStore
const mockUseAuthStore = vi.fn();
vi.mock("../../../src/stores", () => ({
  useAuthStore: (selector) => mockUseAuthStore(selector),
}));

// Import store and reset helpers
import useDashboardStore from "../../../src/stores/useDashboardStore";
import {
  WIDGET_CONFIGS,
  DASHBOARD_LAYOUTS,
} from "../../../src/components/dashboard/defaultDashboardConfig";

function resetStore() {
  useDashboardStore.setState({
    layouts: DASHBOARD_LAYOUTS,
    widgetConfigs: WIDGET_CONFIGS,
    isDirty: false,
    savedVersion: 0,
  });
}

import ConfigEditor from "../../../src/components/dashboard/ConfigEditor";

// Render helper
function renderEditor() {
  return render(
    <MemoryRouter>
      <ConfigEditor />
    </MemoryRouter>,
  );
}

describe("ConfigEditor", () => {
  beforeEach(() => {
    resetStore();
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isSuperuser: true }),
    );
  });

  describe("structural rendering", () => {
    test("renders the page title", () => {
      renderEditor();
      expect(screen.getByText("Dashboard Config")).toBeInTheDocument();
    });

    test("renders a back-to-dashboard link", () => {
      renderEditor();
      expect(
        screen.getByRole("link", { name: /dashboard/i }),
      ).toBeInTheDocument();
    });

    test("renders Save and Reset buttons", () => {
      renderEditor();
      expect(screen.getByRole("button", { name: /save/i })).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: /reset/i }),
      ).toBeInTheDocument();
    });

    test("renders the Add Widget button", () => {
      renderEditor();
      expect(
        screen.getByRole("button", { name: /add widget/i }),
      ).toBeInTheDocument();
    });

    test("Save button is disabled when there are no unsaved changes", () => {
      renderEditor();
      expect(screen.getByRole("button", { name: /save/i })).toBeDisabled();
    });

    test("does NOT show 'Unsaved changes' badge initially", () => {
      renderEditor();
      expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument();
    });
  });

  // Grid widget rendering

  describe("grid widgets", () => {
    test("renders all default grid widgets inside the RGL grid", () => {
      renderEditor();
      const grid = screen.getByTestId("rgl-grid");
      // Default config has 7 widgets: 1 noGrid + 6 in grid
      // The grid should contain 6 widget card headers (displayNames)
      expect(within(grid).getByText("Feeds: Types")).toBeInTheDocument();
      expect(within(grid).getByText("Feeds: Sources")).toBeInTheDocument();
      expect(within(grid).getByText("Feeds: Downloads")).toBeInTheDocument();
      expect(
        within(grid).getByText("Enrichment Service: Sources"),
      ).toBeInTheDocument();
      expect(
        within(grid).getByText("Enrichment Service: Requests"),
      ).toBeInTheDocument();
      expect(
        within(grid).getByText("Attack Origins: World Map"),
      ).toBeInTheDocument();
      expect(
        within(grid).getByText("Attack Origins: Top Countries"),
      ).toBeInTheDocument();
    });

    test("renders a remove (✕) button for each grid widget", () => {
      renderEditor();
      const grid = screen.getByTestId("rgl-grid");
      const removeButtons = within(grid).getAllByTitle("Remove widget");
      // 7 grid widgets in default config
      expect(removeButtons).toHaveLength(7);
    });
  });

  // noGrid widget rendering

  describe("noGrid widgets", () => {
    test("renders the noGrid widget (EnrichmentLookup) above the grid", () => {
      renderEditor();
      const grid = screen.getByTestId("rgl-grid");
      // The noGrid widget's card header should exist on the page...
      expect(screen.getByText("Enrichment Lookup")).toBeInTheDocument();
      // ...but NOT inside the RGL grid
      expect(
        within(grid).queryByText("Enrichment Lookup"),
      ).not.toBeInTheDocument();
    });
  });

  // Remove widget

  describe("remove widget", () => {
    test("clicking ✕ removes the widget from the grid", () => {
      renderEditor();
      const grid = screen.getByTestId("rgl-grid");
      expect(within(grid).getByText("Feeds: Types")).toBeInTheDocument();

      // Remove buttons are siblings of the card div (position:relative wrapper),
      // so we query them directly from the grid and click the first one.
      const [firstRemoveBtn] = within(grid).getAllByTitle("Remove widget");
      fireEvent.click(firstRemoveBtn);

      // After removal the grid should have one less widget header
      expect(within(grid).queryByText("Feeds: Types")).not.toBeInTheDocument();
    });

    test("removing a widget marks the store as dirty", () => {
      renderEditor();
      const grid = screen.getByTestId("rgl-grid");
      const [firstRemoveBtn] = within(grid).getAllByTitle("Remove widget");
      fireEvent.click(firstRemoveBtn);

      expect(useDashboardStore.getState().isDirty).toBe(true);
    });

    test("'Unsaved changes' badge appears after a widget is removed", () => {
      renderEditor();
      const grid = screen.getByTestId("rgl-grid");
      const [firstRemoveBtn] = within(grid).getAllByTitle("Remove widget");
      fireEvent.click(firstRemoveBtn);

      expect(screen.getByText("Unsaved changes")).toBeInTheDocument();
    });

    test("Save button becomes enabled after a widget is removed", () => {
      renderEditor();
      const grid = screen.getByTestId("rgl-grid");
      const [firstRemoveBtn] = within(grid).getAllByTitle("Remove widget");
      fireEvent.click(firstRemoveBtn);

      expect(screen.getByRole("button", { name: /save/i })).not.toBeDisabled();
    });
  });

  // Save action

  describe("save", () => {
    test("clicking Save clears the dirty flag and hides the badge", () => {
      useDashboardStore.setState({ isDirty: true });
      renderEditor();

      fireEvent.click(screen.getByRole("button", { name: /save/i }));

      expect(useDashboardStore.getState().isDirty).toBe(false);
      expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument();
    });

    test("clicking Save increments savedVersion", () => {
      useDashboardStore.setState({ isDirty: true });
      renderEditor();

      const before = useDashboardStore.getState().savedVersion;
      fireEvent.click(screen.getByRole("button", { name: /save/i }));
      expect(useDashboardStore.getState().savedVersion).toBe(before + 1);
    });
  });

  // Reset action

  describe("reset", () => {
    test("clicking Reset and confirming restores default widget configs", () => {
      // Stub window.confirm to auto-approve
      vi.spyOn(window, "confirm").mockReturnValue(true);

      // Remove a widget so state differs from defaults
      useDashboardStore.setState({
        widgetConfigs: WIDGET_CONFIGS.filter(
          (c) => c.type !== "FeedsTypesChart",
        ),
        isDirty: true,
      });

      renderEditor();
      fireEvent.click(screen.getByRole("button", { name: /reset/i }));

      expect(useDashboardStore.getState().widgetConfigs).toEqual(
        WIDGET_CONFIGS,
      );
      expect(useDashboardStore.getState().isDirty).toBe(false);

      vi.restoreAllMocks();
    });

    test("clicking Reset and cancelling does NOT restore defaults", () => {
      vi.spyOn(window, "confirm").mockReturnValue(false);

      const trimmedConfigs = WIDGET_CONFIGS.filter(
        (c) => c.type !== "FeedsTypesChart",
      );
      useDashboardStore.setState({
        widgetConfigs: trimmedConfigs,
        isDirty: true,
      });

      renderEditor();
      fireEvent.click(screen.getByRole("button", { name: /reset/i }));

      expect(useDashboardStore.getState().widgetConfigs).toEqual(
        trimmedConfigs,
      );

      vi.restoreAllMocks();
    });
  });

  //  Add Widget dropdown

  describe("Add Widget dropdown", () => {
    test("Add Widget button is disabled when all widgets are already on the grid", () => {
      // Default config already has all widgets = dropdown should be disabled
      renderEditor();
      expect(
        screen.getByRole("button", { name: /add widget/i }),
      ).toBeDisabled();
    });

    test("Add Widget button is enabled when a widget has been removed", () => {
      renderEditor();
      const grid = screen.getByTestId("rgl-grid");
      const [firstRemoveBtn] = within(grid).getAllByTitle("Remove widget");
      fireEvent.click(firstRemoveBtn);

      expect(
        screen.getByRole("button", { name: /add widget/i }),
      ).not.toBeDisabled();
    });

    test("noGrid widget type (EnrichmentLookup) does NOT appear in the Add Widget dropdown", () => {
      // Remove a grid widget so the dropdown opens with at least one item
      useDashboardStore.setState({
        widgetConfigs: WIDGET_CONFIGS.filter(
          (c) => c.type !== "FeedsTypesChart",
        ),
        layouts: {
          lg: DASHBOARD_LAYOUTS.lg.filter((i) => i.i !== "FeedsTypesChart"),
          md: DASHBOARD_LAYOUTS.md.filter((i) => i.i !== "FeedsTypesChart"),
          sm: DASHBOARD_LAYOUTS.sm.filter((i) => i.i !== "FeedsTypesChart"),
        },
        isDirty: true,
      });

      renderEditor();
      fireEvent.click(screen.getByRole("button", { name: /add widget/i }));

      // FeedsTypesChart should appear as an option
      expect(screen.getByText("Feeds: Types")).toBeInTheDocument();
      // EnrichmentLookup (noGrid) must NOT appear in the dropdown
      const dropdownMenu = screen.getByRole("menu");
      expect(
        within(dropdownMenu).queryByText("Enrichment Lookup"),
      ).not.toBeInTheDocument();
    });
  });

  // empty state
  describe("empty state", () => {
    test("shows empty-state message when all grid widgets are removed", () => {
      useDashboardStore.setState({
        widgetConfigs: WIDGET_CONFIGS.filter((c) => c.noGrid),
        layouts: { lg: [], md: [], sm: [] },
        isDirty: true,
      });

      renderEditor();

      expect(screen.getByText(/no widgets/i)).toBeInTheDocument();
      expect(screen.queryByTestId("rgl-grid")).not.toBeInTheDocument();
    });
  });
});
