import React from "react";
import "@testing-library/jest-dom";
import { fireEvent, render, screen } from "@testing-library/react";

import FeedsTrending from "../../../src/components/feeds/FeedsTrending";
import { useAxiosComponentLoader } from "@greedybear/gb-ui";
import { FEEDS_TRENDING_URI } from "../../../src/constants/api";

vi.mock("@greedybear/gb-ui", async () => {
  const actual = await vi.importActual("@greedybear/gb-ui");
  return {
    ...actual,
    ContentSection: ({ children, className }) => (
      <section className={className}>{children}</section>
    ),
    useAxiosComponentLoader: vi.fn(),
  };
});

describe("FeedsTrending", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("renders trending attackers table", () => {
    useAxiosComponentLoader.mockImplementation(() => {
      const Loader = ({ render: renderFn }) => renderFn();
      return [
        {
          count: 2,
          current_window: {
            start: "2026-03-20T09:00:00Z",
            end: "2026-03-20T10:00:00Z",
          },
          attackers: [
            {
              attacker_ip: "1.1.1.1",
              current_interactions: 10,
              previous_interactions: 2,
              interaction_delta: 8,
              growth_score: 4,
              rank_delta: 3,
            },
            {
              attacker_ip: "2.2.2.2",
              current_interactions: 5,
              previous_interactions: 5,
              interaction_delta: 0,
              growth_score: 0,
              rank_delta: null,
            },
          ],
        },
        Loader,
      ];
    });

    render(<FeedsTrending />);

    expect(useAxiosComponentLoader).toHaveBeenCalledWith(
      expect.objectContaining({
        url: FEEDS_TRENDING_URI,
        params: {
          feed_type: "all",
          window_minutes: "60",
          limit: "10",
        },
      }),
    );
    expect(screen.getByRole("heading", { name: "Trending Feed" })).toBeInTheDocument();
    expect(screen.getByText("attackers")).toBeInTheDocument();
    expect(screen.getByText("1.1.1.1")).toBeInTheDocument();
    expect(screen.getByText("2.2.2.2")).toBeInTheDocument();
    expect(screen.getByText("+8")).toBeInTheDocument();
    expect(screen.getByText("4.00")).toBeInTheDocument();
    expect(
      screen.getByText("2026-03-20T09:00:00Z to 2026-03-20T10:00:00Z"),
    ).toBeInTheDocument();
  });

  test("renders empty state when no attackers are returned", () => {
    useAxiosComponentLoader.mockImplementation(() => {
      const Loader = ({ render: renderFn }) => renderFn();
      return [
        {
          count: 0,
          current_window: {
            start: "2026-03-20T09:00:00Z",
            end: "2026-03-20T10:00:00Z",
          },
          attackers: [],
        },
        Loader,
      ];
    });

    render(<FeedsTrending />);

    expect(
      screen.getByText("No trending attackers found for the selected window."),
    ).toBeInTheDocument();
  });

  test("submits updated params", async () => {
    useAxiosComponentLoader.mockImplementation(() => {
      const Loader = ({ render: renderFn }) => renderFn();
      return [
        {
          count: 0,
          current_window: {
            start: "2026-03-20T09:00:00Z",
            end: "2026-03-20T10:00:00Z",
          },
          attackers: [],
        },
        Loader,
      ];
    });

    render(<FeedsTrending />);

    const feedTypeInput = screen.getByLabelText("Feed type");
    const windowMinutesInput = screen.getByLabelText("Window minutes");
    const limitInput = screen.getByLabelText("Limit");

    fireEvent.change(feedTypeInput, { target: { value: "cowrie,heralding" } });
    fireEvent.change(windowMinutesInput, { target: { value: "120" } });
    fireEvent.change(limitInput, { target: { value: "25" } });
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    const latestCall =
      useAxiosComponentLoader.mock.calls[
        useAxiosComponentLoader.mock.calls.length - 1
      ][0];

    expect(latestCall).toEqual(
      expect.objectContaining({
        url: FEEDS_TRENDING_URI,
        params: {
          feed_type: "cowrie,heralding",
          window_minutes: "120",
          limit: "25",
        },
      }),
    );
  });
});
