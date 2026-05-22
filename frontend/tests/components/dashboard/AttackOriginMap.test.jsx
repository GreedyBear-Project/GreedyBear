import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import axios from "axios";
import AttackOriginMap from "../../../src/components/dashboard/AttackOriginMap";
import { IOC_ATTACKER_COUNTRIES_URI } from "../../../src/constants/api";
import useAttackerCountriesStore from "../../../src/stores/useAttackerCountriesStore";

vi.mock("axios");

vi.mock("@greedybear/gb-ui", () => ({
  useTimePickerStore: () => ({ range: "7d" }),
}));

// Stub TopoJSON fetch (undici rejects the relative URL used in production).
globalThis.fetch = vi.fn(() =>
  Promise.resolve({ ok: true, json: () => Promise.resolve({}) }),
);

// Mock the map library. Each mock geography carries a numeric ISO id
// (geo.id) so that AttackOriginMap can resolve it to an alpha-2 code via
// i18n-iso-countries, matching the alpha-2-keyed countryDataMap from the store.
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
    useAttackerCountriesStore.setState({
      normalizedData: [],
      countryDataMap: {},
      maxCount: 0,
      loading: false,
      error: null,
      lastRange: null,
      currentController: null,
    });
    vi.clearAllMocks();
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
      expect(
        screen.getByText("Failed to load attacker countries data."),
      ).toBeInTheDocument(),
    );
  });

  test("calls the countries endpoint with the range param", async () => {
    axios.get.mockResolvedValue({ data: [] });
    render(<AttackOriginMap />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(
        IOC_ATTACKER_COUNTRIES_URI,
        expect.objectContaining({
          params: { range: "7d" },
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
});
