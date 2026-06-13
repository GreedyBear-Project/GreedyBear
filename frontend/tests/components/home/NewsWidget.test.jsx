import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import {
  MAX_NEWS_ITEMS,
  NewsWidget,
} from "../../../src/components/home/NewsWidget";
import { GREEDYBEAR_NEWS_URL } from "../../../src/constants/api";
import "@testing-library/jest-dom";

global.fetch = vi.fn();

describe("NewsWidget", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe("Loading State", () => {
    it("should display loading spinner while fetching data", () => {
      fetch.mockImplementation(() => new Promise(() => {}));

      render(<NewsWidget />);
      expect(screen.getByText("Loading news...")).toBeInTheDocument();
      expect(screen.getByRole("status")).toBeInTheDocument();
    });
  });

  describe("Success State", () => {
    it("should display news items when data is fetched successfully", async () => {
      const mockNewsData = [
        {
          date: "2024-01-15",
          title: "Test News Title 1",
          subtext: "Test subtext 1",
          link: "https://example.com/news1",
        },
        {
          date: "2024-02-20",
          title: "Test News Title 2",
          subtext: "Test subtext 2",
          link: "https://example.com/news2",
        },
      ];

      fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockNewsData,
      });

      render(<NewsWidget />);

      // Wait for the first title to appear
      expect(await screen.findByText("Test News Title 1")).toBeInTheDocument();

      // Check the rest without waitFor
      expect(screen.getByText("Test News Title 2")).toBeInTheDocument();
      expect(screen.getByText("Test subtext 1")).toBeInTheDocument();
      expect(screen.getByText("Test subtext 2")).toBeInTheDocument();
    });

    it("should call the correct API endpoint", async () => {
      fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [],
      });

      render(<NewsWidget />);

      await waitFor(() => {
        expect(fetch).toHaveBeenCalledWith(GREEDYBEAR_NEWS_URL);
      });
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it("should render 'Read more' links with correct href", async () => {
      const mockNewsData = [
        {
          date: "2024-01-15",
          title: "Test News",
          subtext: "Test subtext",
          link: "https://example.com/news",
        },
      ];

      fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockNewsData,
      });

      render(<NewsWidget />);

      const link = await screen.findByText("Read more");
      expect(link).toHaveAttribute("href", "https://example.com/news");
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noopener noreferrer");
    });

    it("should display message when no news is available", async () => {
      fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => [],
      });

      render(<NewsWidget />);

      expect(
        await screen.findByText("No news available at the moment."),
      ).toBeInTheDocument();
    });
  });

  describe("Error State", () => {
    it("should display error message when fetch fails", async () => {
      fetch.mockRejectedValueOnce(new Error("Network error"));

      render(<NewsWidget />);

      expect(
        await screen.findByText("Unable to load news. Please try again later."),
      ).toBeInTheDocument();
    });

    it("should display error message when response is not ok", async () => {
      fetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      render(<NewsWidget />);

      expect(
        await screen.findByText("Unable to load news. Please try again later."),
      ).toBeInTheDocument();
    });

    it("should log error to console when fetch fails", async () => {
      const consoleErrorSpy = vi
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const mockError = new Error("Network error");

      fetch.mockRejectedValueOnce(mockError);

      render(<NewsWidget />);

      await waitFor(() => {
        expect(consoleErrorSpy).toHaveBeenCalledWith(
          "Error fetching news:",
          mockError,
        );
      });

      consoleErrorSpy.mockRestore();
    });
  });

  describe("Date Formatting", () => {
    it("should format date correctly in non-utc timezones", async () => {
      const originalTZ = process.env.TZ;
      process.env.TZ = "America/Los_Angeles";

      try {
        const mockNewsDataUTC = [
          {
            date: "2024-01-01",
            title: "updated_timezone",
            subtext: "Testing for utc formating",
            link: "L1_utc",
          },
        ];
        fetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockNewsDataUTC,
        });
        render(<NewsWidget />);

        const dateElement = await screen.findByText("1st Jan 2024");
        expect(dateElement).toBeInTheDocument();
        expect(screen.queryByText("31st Dec 2023")).not.toBeInTheDocument();
      } finally {
        process.env.TZ = originalTZ;
      }
    });
    it("should format date correctly with ordinal suffix", async () => {
      const mockNewsData = [
        { date: "2024-01-01", title: "N1", subtext: "T", link: "L1" },
        { date: "2024-02-02", title: "N2", subtext: "T", link: "L2" },
        { date: "2024-03-03", title: "N3", subtext: "T", link: "L3" },
        { date: "2024-04-21", title: "N4", subtext: "T", link: "L4" },
      ];

      fetch.mockResolvedValueOnce({ ok: true, json: async () => mockNewsData });

      render(<NewsWidget />);

      expect(await screen.findByText("1st Jan 2024")).toBeInTheDocument();
      expect(screen.getByText("2nd Feb 2024")).toBeInTheDocument();
      expect(screen.getByText("3rd Mar 2024")).toBeInTheDocument();
      expect(screen.queryByText("21st Apr 2024")).not.toBeInTheDocument();
    });

    it("should handle items without date", async () => {
      const mockNewsData = [{ title: "No date", subtext: "T", link: "L" }];
      fetch.mockResolvedValueOnce({ ok: true, json: async () => mockNewsData });

      render(<NewsWidget />);

      expect(await screen.findByText("No date")).toBeInTheDocument();
      expect(screen.queryByText(/Jan|Feb|Mar/)).not.toBeInTheDocument();
    });

    it("should handle invalid date strings gracefully", async () => {
      const mockNewsData = [
        { date: "invalid-date", title: "Invalid", subtext: "T", link: "L" },
      ];
      fetch.mockResolvedValueOnce({ ok: true, json: async () => mockNewsData });

      render(<NewsWidget />);

      expect(await screen.findByText("Invalid")).toBeInTheDocument();
      expect(screen.getByText("invalid-date")).toBeInTheDocument();
    });

    it("should format dates with correct ordinal suffix for 11th-13th", async () => {
      const mockNewsData = [
        { date: "2024-01-11", title: "11", subtext: "T", link: "L1" },
        { date: "2024-01-12", title: "12", subtext: "T", link: "L2" },
        { date: "2024-01-13", title: "13", subtext: "T", link: "L3" },
      ];

      fetch.mockResolvedValueOnce({ ok: true, json: async () => mockNewsData });

      render(<NewsWidget />);

      expect(await screen.findByText("11th Jan 2024")).toBeInTheDocument();
      expect(screen.getByText("12th Jan 2024")).toBeInTheDocument();
      expect(screen.getByText("13th Jan 2024")).toBeInTheDocument();
    });
  });

  describe("Component Behavior", () => {
    it("should fetch data only once on mount", async () => {
      fetch.mockResolvedValueOnce({ ok: true, json: async () => [] });
      const { rerender } = render(<NewsWidget />);

      await waitFor(() => {
        expect(fetch).toHaveBeenCalledTimes(1);
      });

      rerender(<NewsWidget />);
      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it("should render multiple news items correctly", async () => {
      const mockNewsData = Array.from({ length: MAX_NEWS_ITEMS }, (_, i) => ({
        date: `2024-01-${i + 1}`,
        title: `News Title ${i + 1}`,
        subtext: `Subtext ${i + 1}`,
        link: `https://example.com/news${i + 1}`,
      }));

      fetch.mockResolvedValueOnce({ ok: true, json: async () => mockNewsData });

      render(<NewsWidget />);

      expect(await screen.findByText("News Title 1")).toBeInTheDocument();

      mockNewsData.slice(0, MAX_NEWS_ITEMS).forEach((item) => {
        expect(screen.getByText(item.title)).toBeInTheDocument();
        expect(screen.getByText(item.subtext)).toBeInTheDocument();
      });

      expect(screen.getAllByText("Read more")).toHaveLength(MAX_NEWS_ITEMS);
    });
  });
  describe("Limits news item to max_news_item", () => {
    it("should have the MAX_NEWS_ITEMS constraint and hide excess items", async () => {
      const mockNewsData = Array.from({ length: 10 }, (_, i) => ({
        date: `2024-01-${10 + i}`,
        title: `News item ${i + 1}`,
        subtext: `Text ${i + 1}`,
        link: `https://example.com${i + 1}`,
      }));

      fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockNewsData,
      });

      render(<NewsWidget />);

      await screen.findByText("News item 1");

      const links = screen.getAllByText("Read more");
      expect(links).toHaveLength(MAX_NEWS_ITEMS);
    });
  });
  describe("Memoization", () => {
    it("should be wrapped with React.memo", () => {
      expect(NewsWidget.$$typeof).toBeDefined();
    });
  });
});
