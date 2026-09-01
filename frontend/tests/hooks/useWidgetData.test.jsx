import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import axios from "axios";
import useWidgetData, {
  clearWidgetDataCache,
  normalizeAttackerCountries,
} from "../../src/hooks/useWidgetData";

vi.mock("axios");

vi.mock("@greedybear/gb-ui", () => ({
  useTimePickerStore: () => ({ range: "7d" }),
}));

// Simple consumer component
function DataConsumer({ url, params }) {
  const { data, loading, error } = useWidgetData(url, params);
  if (loading) return <div>loading</div>;
  if (error) return <div>error: {error}</div>;
  if (!data) return <div>no data</div>;
  return <div>data: {JSON.stringify(data)}</div>;
}

const TEST_URL = "/api/test";

describe("useWidgetData", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearWidgetDataCache();
  });

  test("shows loading initially and resolves to data", async () => {
    axios.get.mockResolvedValue({ data: [1, 2, 3] });
    render(<DataConsumer url={TEST_URL} />);

    expect(screen.getByText("loading")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByText("data: [1,2,3]")).toBeInTheDocument(),
    );
  });

  test("shows error when request fails", async () => {
    axios.get.mockRejectedValue(new Error("boom"));
    render(<DataConsumer url={`${TEST_URL}/fail`} />);
    await waitFor(() =>
      expect(
        screen.getByText("error: Failed to load data."),
      ).toBeInTheDocument(),
    );
  });

  test("passes url and range to axios", async () => {
    axios.get.mockResolvedValue({ data: [] });
    render(<DataConsumer url={`${TEST_URL}/params`} />);
    await waitFor(() =>
      expect(axios.get).toHaveBeenCalledWith(
        `${TEST_URL}/params`,
        expect.objectContaining({
          params: expect.objectContaining({ range: "7d" }),
        }),
      ),
    );
  });

  test("does not fire a second request when the same key is cached", async () => {
    const CACHED_URL = `${TEST_URL}/cached`;
    axios.get.mockResolvedValue({ data: [42] });

    // First render: populates cache
    const { unmount } = render(<DataConsumer url={CACHED_URL} />);
    await waitFor(() =>
      expect(screen.getByText("data: [42]")).toBeInTheDocument(),
    );
    unmount();

    // Second render with same url+range: should hit cache, no new axios call
    render(<DataConsumer url={CACHED_URL} />);
    await waitFor(() =>
      expect(screen.getByText("data: [42]")).toBeInTheDocument(),
    );

    // axios.get was called exactly once across both renders
    expect(axios.get).toHaveBeenCalledTimes(1);
  });

  test("deduplicates concurrent in-flight requests for the same key", async () => {
    const INFLIGHT_URL = `${TEST_URL}/inflight`;

    // Expose resolve so we control when the request settles
    let resolve;
    axios.get.mockReturnValue(
      new Promise((res) => {
        resolve = () => res({ data: [99] });
      }),
    );

    // Mount two consumers simultaneously - both see the same unresolved promise
    render(
      <>
        <DataConsumer url={INFLIGHT_URL} />
        <DataConsumer url={INFLIGHT_URL} />
      </>,
    );

    // Both show loading while in-flight
    expect(screen.getAllByText("loading")).toHaveLength(2);

    // Settle the single request
    resolve();

    await waitFor(() => {
      expect(screen.getAllByText("data: [99]")).toHaveLength(2);
    });

    // Only one GET was ever issued
    expect(axios.get).toHaveBeenCalledTimes(1);
  });
});

describe("normalizeAttackerCountries", () => {
  test("returns empty structures for null input", () => {
    const result = normalizeAttackerCountries(null);
    expect(result.countryDataMap).toEqual({});
    expect(result.maxCount).toBe(0);
    expect(result.normalizedData).toEqual([]);
  });

  test("returns empty structures for non-array input", () => {
    expect(normalizeAttackerCountries("bad").normalizedData).toEqual([]);
    expect(normalizeAttackerCountries(42).normalizedData).toEqual([]);
    expect(normalizeAttackerCountries({}).normalizedData).toEqual([]);
  });

  test("basic happy path — single country", () => {
    const raw = [{ code: "US", country: "United States", count: 50 }];
    const { countryDataMap, maxCount, normalizedData } =
      normalizeAttackerCountries(raw);
    expect(countryDataMap).toEqual({ US: 50 });
    expect(maxCount).toBe(50);
    expect(normalizedData).toEqual([
      { code: "US", country: "United States", count: 50 },
    ]);
  });

  test("aggregates duplicate ISO codes (regression for old store test)", () => {
    // Two rows for the same country
    const raw = [
      { code: "CN", country: "China", count: 100 },
      { code: "CN", country: "China (duplicate row)", count: 40 },
    ];
    const { countryDataMap, maxCount, normalizedData } =
      normalizeAttackerCountries(raw);
    expect(countryDataMap).toEqual({ CN: 140 });
    expect(maxCount).toBe(140);
    expect(normalizedData).toHaveLength(1);
    expect(normalizedData[0]).toEqual({
      code: "CN",
      country: "China",
      count: 140,
    });
  });

  test("normalises code to uppercase", () => {
    const raw = [{ code: "gb", country: "United Kingdom", count: 10 }];
    const { countryDataMap } = normalizeAttackerCountries(raw);
    expect(countryDataMap).toHaveProperty("GB", 10);
    expect(countryDataMap).not.toHaveProperty("gb");
  });

  test("skips items with missing or non-string code", () => {
    const raw = [
      null,
      undefined,
      42,
      { country: "No code", count: 5 }, // missing code
      { code: null, country: "Null code", count: 5 },
      { code: 123, country: "Numeric code", count: 5 },
      { code: "US", country: "United States", count: 20 }, // only valid entry
    ];
    const { normalizedData } = normalizeAttackerCountries(raw);
    expect(normalizedData).toHaveLength(1);
    expect(normalizedData[0].code).toBe("US");
  });

  test("clamps negative counts to zero", () => {
    const raw = [{ code: "DE", country: "Germany", count: -50 }];
    const { countryDataMap, maxCount } = normalizeAttackerCountries(raw);
    expect(countryDataMap).toEqual({ DE: 0 });
    expect(maxCount).toBe(0);
  });

  test("coerces non-numeric count to zero", () => {
    const raw = [{ code: "FR", country: "France", count: "bad" }];
    const { countryDataMap } = normalizeAttackerCountries(raw);
    expect(countryDataMap).toEqual({ FR: 0 });
  });

  test("sorts normalizedData by count descending", () => {
    const raw = [
      { code: "US", country: "United States", count: 10 },
      { code: "CN", country: "China", count: 300 },
      { code: "RU", country: "Russia", count: 150 },
    ];
    const { normalizedData } = normalizeAttackerCountries(raw);
    expect(normalizedData.map((d) => d.code)).toEqual(["CN", "RU", "US"]);
  });

  test("maxCount reflects highest aggregated country, not individual row", () => {
    const raw = [
      { code: "US", country: "United States", count: 80 },
      { code: "CN", country: "China", count: 60 },
      { code: "CN", country: "China", count: 60 }, // duplicate
    ];
    const { maxCount } = normalizeAttackerCountries(raw);
    expect(maxCount).toBe(120);
  });
});
