import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import axios from "axios";

import {
  FeedsSourcesChart,
  FeedsDownloadsChart,
  EnrichmentSourcesChart,
  EnrichmentRequestsChart,
  FeedsTypesChart,
} from "../../../src/components/dashboard/utils/charts";

import {
  FEEDS_STATISTICS_SOURCES_URI,
  FEEDS_STATISTICS_DOWNLOADS_URI,
  ENRICHMENT_STATISTICS_SOURCES_URI,
  ENRICHMENT_STATISTICS_REQUESTS_URI,
  FEEDS_STATISTICS_TYPES_URI,
} from "../../../src/constants/api";

import { clearWidgetDataCache } from "../../../src/hooks/useWidgetData";

vi.mock("axios");

vi.mock("../../../src/components/common/gb-ui/index", () => ({
  useTimePickerStore: () => ({ range: "7d", dateFormat: "yyyy-MM-dd" }),
  getRandomColorsArray: (n) => Array(n).fill("#aabbcc"),
}));

vi.mock("recharts", async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    ResponsiveContainer: ({ children, height }) => (
      <div data-testid="responsive-container" style={{ width: 800, height }}>
        {React.cloneElement(React.Children.only(children), {
          width: 800,
          height,
        })}
      </div>
    ),
    ComposedChart: ({ children }) => (
      <div data-testid="composed-chart">{children}</div>
    ),
    BarChart: ({ children }) => <div data-testid="bar-chart">{children}</div>,
    Bar: ({ dataKey }) => <div data-testid={`bar-${dataKey}`} />,
    Area: ({ dataKey }) => <div data-testid={`area-${dataKey}`} />,
    XAxis: () => null,
    YAxis: () => null,
    CartesianGrid: () => null,
    Legend: () => null,
    Tooltip: () => null,
    Cell: () => null,
  };
});

const ONE_DAY_FEED = [{ date: "2024-01-01", Sources: 10, Downloads: 5 }];
const ONE_DAY_TYPES = [{ date: "2024-01-01", cowrie: 100, honeytrap: 50 }];
const ONE_DAY_ENRICHMENT = [{ date: "2024-01-01", Sources: 3, Requests: 9 }];

describe("Charts Components", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearWidgetDataCache();
  });

  test("createAreaChart sets correct displayName", () => {
    expect(FeedsSourcesChart.displayName).toBe("FeedsSourcesChart");
    expect(FeedsDownloadsChart.displayName).toBe("FeedsDownloadsChart");
    expect(EnrichmentSourcesChart.displayName).toBe("EnrichmentSourcesChart");
    expect(EnrichmentRequestsChart.displayName).toBe("EnrichmentRequestsChart");
  });

  test("shows loading state initially", () => {
    axios.get.mockReturnValue(new Promise(() => {}));
    render(<FeedsSourcesChart />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
  });

  test("FeedsSourcesChart fetches the correct endpoint", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_FEED });
    render(<FeedsSourcesChart />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(
        FEEDS_STATISTICS_SOURCES_URI,
        expect.objectContaining({
          params: expect.objectContaining({ range: "7d" }),
        }),
      ),
    );
  });

  test("FeedsDownloadsChart fetches the correct endpoint", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_FEED });
    render(<FeedsDownloadsChart />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(
        FEEDS_STATISTICS_DOWNLOADS_URI,
        expect.anything(),
      ),
    );
  });

  test("EnrichmentSourcesChart fetches the correct endpoint", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_ENRICHMENT });
    render(<EnrichmentSourcesChart />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(
        ENRICHMENT_STATISTICS_SOURCES_URI,
        expect.anything(),
      ),
    );
  });

  test("EnrichmentRequestsChart fetches the correct endpoint", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_ENRICHMENT });
    render(<EnrichmentRequestsChart />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(
        ENRICHMENT_STATISTICS_REQUESTS_URI,
        expect.anything(),
      ),
    );
  });

  test("FeedsTypesChart fetches the correct endpoint", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_TYPES });
    render(<FeedsTypesChart />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(
        FEEDS_STATISTICS_TYPES_URI,
        expect.anything(),
      ),
    );
  });

  test("FeedsSourcesChart renders an Area for each colorMap key in its slice", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_FEED });
    render(<FeedsSourcesChart />);
    await waitFor(() =>
      expect(screen.getByTestId("responsive-container")).toBeInTheDocument(),
    );
    // FEED_COLOR_MAP slice [0,1] => first key is "Sources"
    expect(screen.getByTestId("area-Sources")).toBeInTheDocument();
  });

  test("FeedsDownloadsChart renders an Area for its colorMap slice", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_FEED });
    render(<FeedsDownloadsChart />);
    await waitFor(() =>
      expect(screen.getByTestId("responsive-container")).toBeInTheDocument(),
    );
    // FEED_COLOR_MAP slice [1,2] => second key is "Downloads"
    expect(screen.getByTestId("area-Downloads")).toBeInTheDocument();
  });

  test("FeedsSourcesChart renders a chart after data loads", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_FEED });
    render(<FeedsSourcesChart />);
    await waitFor(() =>
      expect(screen.getByTestId("responsive-container")).toBeInTheDocument(),
    );
  });

  test("FeedsTypesChart renders a Bar for each feed type key", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_TYPES });
    render(<FeedsTypesChart />);
    await waitFor(() => {
      expect(screen.getByTestId("bar-cowrie")).toBeInTheDocument();
      expect(screen.getByTestId("bar-honeytrap")).toBeInTheDocument();
    });
  });

  test("FeedsTypesChart renders a chart after data loads", async () => {
    axios.get.mockResolvedValue({ data: ONE_DAY_TYPES });
    render(<FeedsTypesChart />);
    await waitFor(() =>
      expect(screen.getByTestId("responsive-container")).toBeInTheDocument(),
    );
  });

  test("FeedsTypesChart shows empty-state for no data", async () => {
    axios.get.mockResolvedValue({ data: [] });
    render(<FeedsTypesChart />);
    await waitFor(() =>
      expect(
        screen.getByText("No data in the selected range."),
      ).toBeInTheDocument(),
    );
  });

  test("FeedsTypesChart only reads feed types from first element of respData", async () => {
    // Second element introduces a "telnet" key absent from the first element.
    // The chart must only create Bars for keys found in respData[0] (excluding "date").
    axios.get.mockResolvedValue({
      data: [
        { date: "2024-01-01", ssh: 5 },
        { date: "2024-01-02", ssh: 8, telnet: 3 },
      ],
    });
    render(<FeedsTypesChart />);
    await waitFor(() =>
      expect(screen.getByTestId("bar-ssh")).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("bar-telnet")).not.toBeInTheDocument();
  });
});
