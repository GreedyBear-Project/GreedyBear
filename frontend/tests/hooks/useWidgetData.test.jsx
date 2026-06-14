import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import axios from "axios";
import useWidgetData, {
  clearWidgetDataCache,
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
});
