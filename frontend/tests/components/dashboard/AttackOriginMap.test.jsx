import React from "react";
import "@testing-library/jest-dom";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import axios from "axios";
import AttackOriginMap from "../../../src/components/dashboard/AttackOriginMap";
import { IOC_ATTACKER_COUNTRIES_URI } from "../../../src/constants/api";
import { clearWidgetDataCache } from "../../../src/hooks/useWidgetData";

vi.mock("axios");

vi.mock("../../../src/components/common/gb-ui/index", () => ({
  useTimePickerStore: () => ({ range: "7d" }),
}));

// Stub TopoJSON fetch (undici rejects the relative URL used in production).
globalThis.fetch = vi.fn(() =>
  Promise.resolve({ ok: true, json: () => Promise.resolve({}) }),
);

// Mock the map library. Each mock geography carries a numeric ISO id
// (geo.id) so that AttackOriginMap can resolve it to an alpha-2 code via
// i18n-iso-countries, matching the alpha-2-keyed countryDataMap.
vi.mock("@vnedyalk0v/react19-simple-maps", () => ({
  ComposableMap: ({ children, onMouseMove, onMouseLeave }) => (
    <div
      data-testid="composable-map"
      onMouseMove={onMouseMove}
      onMouseLeave={onMouseLeave}
    >
      {children}
    </div>
  ),
  Geographies: ({ children }) =>
    children({
      geographies: [
        { rsmKey: "geo-cn", id: "156", properties: { name: "China" } },
        {
          rsmKey: "geo-usa",
          id: "840",
          properties: { name: "United States of America" },
        },
        { rsmKey: "geo-fr", id: "250", properties: { name: "France" } },
      ],
    }),
  Geography: ({ fill, onMouseEnter, onMouseLeave, geography }) => (
    <div
      data-testid={`geography-${geography.rsmKey}`}
      data-fill={fill}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    />
  ),
  ZoomableGroup: ({ children }) => <div>{children}</div>,
}));

const COUNTRIES_DATA = [
  { country: "China", code: "CN", count: 120 },
  { country: "United States", code: "US", count: 80 },
  { country: "Germany", code: "DE", count: 40 },
];

describe("AttackOriginMap", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearWidgetDataCache();
  });

  test("shows loading state while request is in flight", () => {
    axios.get.mockReturnValue(new Promise(() => {}));
    render(<AttackOriginMap />);
    expect(screen.getByText("Loading map…")).toBeInTheDocument();
  });

  test("shows error state when request fails", async () => {
    axios.get.mockRejectedValue(new Error("Network error"));
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByText("Failed to load data.")).toBeInTheDocument(),
    );
  });

  test("calls the countries endpoint with the range param", async () => {
    axios.get.mockResolvedValue({ data: [] });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(
        IOC_ATTACKER_COUNTRIES_URI,
        expect.objectContaining({
          params: expect.objectContaining({ range: "7d" }),
        }),
      ),
    );
  });

  test("renders map and hides legend when response is empty", async () => {
    axios.get.mockResolvedValue({ data: [] });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByTestId("composable-map")).toBeInTheDocument(),
    );
    // maxCount stays 0 (legend must not render)
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  test("renders map and shows legend with correct maxCount when data is present", async () => {
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByTestId("composable-map")).toBeInTheDocument(),
    );
    // Legend: left label "0" and right label matching the max value
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getByText("120")).toBeInTheDocument();
  });

  test("geographies are rendered for each geo in the response", async () => {
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByTestId("geography-geo-cn")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("geography-geo-usa")).toBeInTheDocument();
  });

  test("empty country for a geo gets the empty fill colour", async () => {
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByTestId("geography-geo-fr")).toBeInTheDocument(),
    );
    // France (id="250") is not in COUNTRIES_DATA so it must receive the empty/default colour
    const franceEl = screen.getByTestId("geography-geo-fr");
    expect(franceEl.dataset.fill).toBe("#2a2a3a");
    // China (id="156") IS in the data so it must not receive the empty colour
    const chinaEl = screen.getByTestId("geography-geo-cn");
    expect(chinaEl.dataset.fill).not.toBe("#2a2a3a");
  });

  test("geo.id numeric lookup correctly colours a country regardless of API name variant", async () => {
    // The API returns "United States" but the map looks up by geo.id="840" → alpha-2 "US"
    // so the geography is coloured even though the name doesn't match the TopoJSON name
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(screen.getByTestId("geography-geo-usa")).toBeInTheDocument(),
    );

    const usaEl = screen.getByTestId("geography-geo-usa");
    expect(usaEl.dataset.fill).not.toBe("#2a2a3a");
  });

  describe("tooltip", () => {
    const TOOLTIP_SIZE = { width: 100, height: 40 };
    let rectSpy;

    const hoverChina = async (clientX, clientY) => {
      axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
      const view = render(<AttackOriginMap />);
      await waitFor(() =>
        expect(screen.getByTestId("geography-geo-cn")).toBeInTheDocument(),
      );
      fireEvent.mouseEnter(screen.getByTestId("geography-geo-cn"), {
        clientX,
        clientY,
      });
      return view;
    };

    beforeEach(() => {
      // jsdom does no layout, so give the tooltip a size to flip against
      rectSpy = vi
        .spyOn(Element.prototype, "getBoundingClientRect")
        .mockReturnValue(TOOLTIP_SIZE);
    });

    afterEach(() => {
      rectSpy.mockRestore();
    });

    test("is rendered in document.body, outside the widget", async () => {
      const { container } = await hoverChina(100, 100);
      const tooltip = screen.getByTestId("map-tooltip");
      expect(tooltip).toHaveTextContent("China");
      expect(tooltip).toHaveTextContent("120 IOCs");
      expect(tooltip.parentElement).toBe(document.body);
      expect(container).not.toContainElement(tooltip);
    });

    test("sits below and to the right of the cursor when there is room", async () => {
      await hoverChina(100, 100);
      const tooltip = screen.getByTestId("map-tooltip");
      expect(tooltip.style.left).toBe("114px");
      expect(tooltip.style.top).toBe("114px");
    });

    test("flips above and to the left near the bottom-right viewport edge", async () => {
      await hoverChina(window.innerWidth - 10, window.innerHeight - 10);
      const tooltip = screen.getByTestId("map-tooltip");
      expect(tooltip.style.left).toBe(`${window.innerWidth - 10 - 14 - 100}px`);
      expect(tooltip.style.top).toBe(`${window.innerHeight - 10 - 14 - 40}px`);
    });

    test("follows the cursor and hides on mouse leave", async () => {
      await hoverChina(100, 100);
      fireEvent.mouseMove(screen.getByTestId("composable-map"), {
        clientX: 200,
        clientY: 150,
      });
      const tooltip = screen.getByTestId("map-tooltip");
      expect(tooltip.style.left).toBe("214px");
      expect(tooltip.style.top).toBe("164px");
      fireEvent.mouseLeave(screen.getByTestId("geography-geo-cn"));
      expect(screen.queryByTestId("map-tooltip")).not.toBeInTheDocument();
    });
  });
});
