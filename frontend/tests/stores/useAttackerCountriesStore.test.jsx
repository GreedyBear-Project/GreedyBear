import { describe, test, expect, vi, beforeEach } from "vitest";
import axios from "axios";
import useAttackerCountriesStore from "../../src/stores/useAttackerCountriesStore";
import { IOC_ATTACKER_COUNTRIES_URI } from "../../src/constants/api";

vi.mock("axios");

const createDeferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
};

describe("useAttackerCountriesStore", () => {
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

  describe("Initial State", () => {
    test("initial state is correct", () => {
      const state = useAttackerCountriesStore.getState();
      expect(state.normalizedData).toEqual([]);
      expect(state.countryDataMap).toEqual({});
      expect(state.maxCount).toBe(0);
      expect(state.loading).toBe(false);
      expect(state.error).toBe(null);
    });
  });

  describe("fetchData", () => {
    const mockRange = "24h";
    const rangeStr = JSON.stringify(mockRange);
    const mockData = [
      { country: "United States", code: "US", count: 100 },
      { country: "Italy", code: "IT", count: 50 },
    ];

    test("successfully fetches and normalizes data", async () => {
      axios.get.mockResolvedValue({ data: mockData });

      await useAttackerCountriesStore.getState().fetchData(mockRange);

      const state = useAttackerCountriesStore.getState();
      // countryDataMap is keyed by alpha-2; normalizedData uses raw API name
      expect(state.normalizedData).toEqual([
        { country: "United States", code: "US", count: 100 },
        { country: "Italy", code: "IT", count: 50 },
      ]);
      expect(state.countryDataMap).toEqual({
        US: 100,
        IT: 50,
      });
      expect(state.maxCount).toBe(100);
      expect(state.loading).toBe(false);
      expect(state.lastRange).toBe(rangeStr);
      expect(axios.get).toHaveBeenCalledWith(
        IOC_ATTACKER_COUNTRIES_URI,
        expect.any(Object),
      );
    });

    test("prevents redundant fetches for the same range (caching)", async () => {
      axios.get.mockResolvedValue({ data: mockData });

      // First call
      await useAttackerCountriesStore.getState().fetchData(mockRange);
      expect(axios.get).toHaveBeenCalledTimes(1);

      // Second call for same range
      await useAttackerCountriesStore.getState().fetchData(mockRange);
      expect(axios.get).toHaveBeenCalledTimes(1); // Still 1
    });

    test("handles empty results correctly and caches them", async () => {
      axios.get.mockResolvedValue({ data: [] });

      await useAttackerCountriesStore.getState().fetchData(mockRange);
      expect(axios.get).toHaveBeenCalledTimes(1);

      // Second call for same range (empty)
      await useAttackerCountriesStore.getState().fetchData(mockRange);
      expect(axios.get).toHaveBeenCalledTimes(1); // Caching still works for empty data
    });

    test("prevents simultaneous calls for the same range", async () => {
      const deferred = createDeferred();
      axios.get.mockReturnValue(deferred.promise);

      const fetchPromise1 = useAttackerCountriesStore
        .getState()
        .fetchData(mockRange);
      const fetchPromise2 = useAttackerCountriesStore
        .getState()
        .fetchData(mockRange);

      expect(useAttackerCountriesStore.getState().loading).toBe(true);

      deferred.resolve({ data: mockData });
      await Promise.all([fetchPromise1, fetchPromise2]);

      expect(axios.get).toHaveBeenCalledTimes(1);
    });

    test("cancels in-flight requests when a new range is selected (race condition)", async () => {
      const deferred1 = createDeferred();
      const deferred2 = createDeferred();

      // First mock returns pending promise
      axios.get.mockReturnValueOnce(deferred1.promise);
      // Second mock returns another pending promise
      axios.get.mockReturnValueOnce(deferred2.promise);

      const { fetchData } = useAttackerCountriesStore.getState();

      // Start first fetch
      const fetch1 = fetchData("24h");
      const controller1 =
        useAttackerCountriesStore.getState().currentController;
      const abortSpy1 = vi.spyOn(controller1, "abort");

      // Start second fetch for a different range
      const fetch2 = fetchData("7d");

      // Verify first controller was aborted
      expect(abortSpy1).toHaveBeenCalled();

      deferred1.resolve({ data: [] });
      deferred2.resolve({ data: mockData });

      await Promise.all([fetch1, fetch2]);

      expect(axios.get).toHaveBeenCalledTimes(2);
      expect(useAttackerCountriesStore.getState().normalizedData).toEqual([
        { country: "United States", code: "US", count: 100 },
        { country: "Italy", code: "IT", count: 50 },
      ]);
    });

    test("aggregates data correctly when same ISO code has different names", async () => {
      const complexMockData = [
        { country: "United States", code: "US", count: 100 },
        { country: "USA", code: "US", count: 50 },
        { country: "Italy", code: "IT", count: 30 },
      ];
      axios.get.mockResolvedValue({ data: complexMockData });

      await useAttackerCountriesStore.getState().fetchData("all");

      const state = useAttackerCountriesStore.getState();
      // Aggregated by alpha-2; display name is the first-seen value
      expect(state.normalizedData).toEqual([
        { country: "United States", code: "US", count: 150 },
        { country: "Italy", code: "IT", count: 30 },
      ]);
      expect(state.countryDataMap).toEqual({
        US: 150,
        IT: 30,
      });
      expect(state.maxCount).toBe(150);
    });

    test("skips items that have no ISO code", async () => {
      const mixedData = [
        { country: "United States", code: "US", count: 100 },
        { country: "Unknown", code: null, count: 50 },
        { country: "Italy", code: "IT", count: 30 },
      ];
      axios.get.mockResolvedValue({ data: mixedData });

      await useAttackerCountriesStore.getState().fetchData(mockRange);

      const state = useAttackerCountriesStore.getState();
      // The entry with no code is excluded
      expect(state.normalizedData).toEqual([
        { country: "United States", code: "US", count: 100 },
        { country: "Italy", code: "IT", count: 30 },
      ]);
    });

    test("sets error state on failure", async () => {
      axios.get.mockRejectedValue(new Error("Network Error"));

      await useAttackerCountriesStore.getState().fetchData(mockRange);

      const state = useAttackerCountriesStore.getState();
      expect(state.error).toBe("Failed to load attacker countries data.");
      expect(state.loading).toBe(false);
    });

    test("maintains loading state when a request is cancelled by a newer one", async () => {
      const deferred1 = createDeferred();
      const deferred2 = createDeferred();

      axios.get.mockReturnValueOnce(deferred1.promise);
      axios.get.mockReturnValueOnce(deferred2.promise);

      const { fetchData } = useAttackerCountriesStore.getState();

      // Start first fetch
      const fetch1 = fetchData("24h");
      expect(useAttackerCountriesStore.getState().loading).toBe(true);

      // Start second fetch (cancels first)
      const fetch2 = fetchData("7d");

      // Simulate first request's rejection due to cancellation
      axios.isCancel = vi.fn().mockReturnValue(true);
      deferred1.reject(new Error("Canceled"));
      await fetch1;

      // Verify loading is STILL true because the second request is still in flight
      expect(useAttackerCountriesStore.getState().loading).toBe(true);
      expect(useAttackerCountriesStore.getState().error).toBe(null);

      // Finish second request
      deferred2.resolve({ data: mockData });
      await fetch2;

      // Now loading should be false
      expect(useAttackerCountriesStore.getState().loading).toBe(false);
      expect(useAttackerCountriesStore.getState().normalizedData).toEqual([
        { country: "United States", code: "US", count: 100 },
        { country: "Italy", code: "IT", count: 50 },
      ]);
    });
  });
});
