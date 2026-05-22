import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import axios from "axios";
import { AttackOriginCountriesChart } from "../../../src/components/dashboard/utils/charts";
import { IOC_ATTACKER_COUNTRIES_URI } from "../../../src/constants/api";
import useAttackerCountriesStore from "../../../src/stores/useAttackerCountriesStore";

vi.mock("axios");

vi.mock("@greedybear/gb-ui", () => ({
  useTimePickerStore: () => ({ range: "7d" }),
  getRandomColorsArray: (n) => Array(n).fill("#aabbcc"),
  AnyChartWidget: () => <div />,
}));

// ResponsiveContainer requires a DOM-measured width; give it fixed dimensions in jsdom
vi.mock("recharts", async (importOriginal) => {
  const original = await importOriginal();
  const ResponsiveContainer = ({ children, height }) => (
    <div data-testid="responsive-container" style={{ width: 800, height }}>
      {React.cloneElement(React.Children.only(children), {
        width: 800,
        height,
      })}
    </div>
  );
  return { ...original, ResponsiveContainer };
});

const COUNTRIES_DATA = [
  { country: "China", code: "CN", count: 120 },
  { country: "United States", code: "US", count: 80 },
  { country: "Russia", code: "RU", count: 60 },
  { country: "Germany", code: "DE", count: 40 },
  { country: "India", code: "IN", count: 30 },
];

// 16 entries (one more than the 15-entry limit).
// Each entry needs a code so the store doesn't skip codeless items.
const SIXTEEN_COUNTRIES = Array.from({ length: 16 }, (_, i) => ({
  country: `Country${i + 1}`,
  code: `T${String(i + 1).padStart(1, "0")}`.slice(0, 2), // fictional alpha-2
  count: 100 - i,
}));

describe("AttackOriginCountriesChart", () => {
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
    render(<AttackOriginCountriesChart />);
    expect(screen.getByText("Loading...")).toBeInTheDocument();
  });

  test("shows error message when request fails", async () => {
    axios.get.mockRejectedValue(new Error("Network error"));
    render(<AttackOriginCountriesChart />);
    await waitFor(() =>
      expect(
        screen.getByText("Failed to load attacker countries data."),
      ).toBeInTheDocument(),
    );
  });

  test("shows empty-state message when response is an empty array", async () => {
    axios.get.mockResolvedValue({ data: [] });
    render(<AttackOriginCountriesChart />);
    await waitFor(() =>
      expect(
        screen.getByText(
          "No country data available for the selected time range.",
        ),
      ).toBeInTheDocument(),
    );
  });

  test("calls the countries endpoint with the range param", async () => {
    axios.get.mockResolvedValue({ data: [] });
    render(<AttackOriginCountriesChart />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(
        IOC_ATTACKER_COUNTRIES_URI,
        expect.objectContaining({
          params: { range: "7d" },
        }),
      ),
    );
  });

  test("renders the chart container when data is present", async () => {
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    render(<AttackOriginCountriesChart />);
    await waitFor(() =>
      expect(screen.getByTestId("responsive-container")).toBeInTheDocument(),
    );
  });

  test("caps rendered data at 15 entries", async () => {
    axios.get.mockResolvedValue({ data: SIXTEEN_COUNTRIES });
    render(<AttackOriginCountriesChart />);
    await waitFor(() =>
      expect(screen.getByTestId("responsive-container")).toBeInTheDocument(),
    );
    // The 16th country name must not appear in the rendered output
    expect(screen.queryByText("Country16")).not.toBeInTheDocument();
  });

  test("chart height scales with number of entries", async () => {
    axios.get.mockResolvedValue({ data: COUNTRIES_DATA });
    const { container } = render(<AttackOriginCountriesChart />);
    await waitFor(() =>
      expect(screen.getByTestId("responsive-container")).toBeInTheDocument(),
    );
    const rc = screen.getByTestId("responsive-container");
    // 5 entries × 28px = 140, but minimum is 180
    expect(rc.style.height).toBe("180px");
  });
});
