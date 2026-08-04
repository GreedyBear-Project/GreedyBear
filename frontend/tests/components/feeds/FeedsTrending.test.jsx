import React from "react";
import "@testing-library/jest-dom";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import FeedsTrending from "../../../src/components/feeds/FeedsTrending";
import { useAxiosComponentLoader } from "@greedybear/gb-ui";
import { FEEDS_TRENDING_URI, HONEYPOT_URI } from "../../../src/constants/api";

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
  const mockUseAxiosComponentLoader = (payload) => {
    const refetchTrending = vi.fn();

    useAxiosComponentLoader.mockImplementation(({ url }) => {
      const Loader = ({ render: renderFn }) => renderFn();

      if (url.startsWith(HONEYPOT_URI)) {
        return [["Cowrie", "Heralding"], Loader, vi.fn()];
      }

      return [payload, Loader, refetchTrending];
    });

    return { refetchTrending };
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("renders trending attackers table", () => {
    mockUseAxiosComponentLoader({
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
    expect(
      screen.getByRole("heading", { name: "Trending Feed" }),
    ).toBeInTheDocument();
    expect(screen.getByText("attackers")).toBeInTheDocument();
    expect(screen.getByText("1.1.1.1")).toBeInTheDocument();
    expect(screen.getByText("2.2.2.2")).toBeInTheDocument();
    expect(screen.getByText("+8")).toBeInTheDocument();
    expect(screen.getByText("4.00")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Mar 20, 2026, 9:00 AM UTC to Mar 20, 2026, 10:00 AM UTC",
      ),
    ).toBeInTheDocument();
  });

  test("renders empty state when no attackers are returned", () => {
    mockUseAxiosComponentLoader({
      count: 0,
      current_window: {
        start: "2026-03-20T09:00:00Z",
        end: "2026-03-20T10:00:00Z",
      },
      attackers: [],
    });

    render(<FeedsTrending />);

    expect(
      screen.getByText("No trending attackers found for the selected window."),
    ).toBeInTheDocument();
  });

  test("submits updated params", async () => {
    const user = userEvent.setup();

    const { refetchTrending } = mockUseAxiosComponentLoader({
      count: 0,
      current_window: {
        start: "2026-03-20T09:00:00Z",
        end: "2026-03-20T10:00:00Z",
      },
      attackers: [],
    });

    render(<FeedsTrending />);

    await user.click(screen.getByRole("button", { name: "Feed type" }));
    await user.click(screen.getByText("Cowrie"));

    const windowMinutesInput = screen.getByLabelText("Window size");
    const limitInput = screen.getByLabelText("Limit");

    await user.selectOptions(limitInput, "25");
    await user.selectOptions(windowMinutesInput, "120");

    await waitFor(() => {
      expect(windowMinutesInput).toHaveValue("120");
      expect(limitInput).toHaveValue("25");
    });

    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(screen.getByRole("button", { name: "Feed type" })).toHaveTextContent(
      "Cowrie",
    );
    expect(windowMinutesInput).toHaveValue("120");
    expect(limitInput).toHaveValue("25");
    expect(refetchTrending).not.toHaveBeenCalled();
  });

  test("refreshes even when submitting the same params twice", async () => {
    const { refetchTrending } = mockUseAxiosComponentLoader({
      count: 0,
      current_window: {
        start: "2026-03-20T09:00:00Z",
        end: "2026-03-20T10:00:00Z",
      },
      attackers: [],
    });

    render(<FeedsTrending />);

    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect(refetchTrending).toHaveBeenCalledTimes(1);
  });

  test("renders placeholders for missing delta and invalid growth score", () => {
    mockUseAxiosComponentLoader({
      count: 1,
      current_window: {
        start: "2026-03-20T09:00:00Z",
        end: "2026-03-20T10:00:00Z",
      },
      attackers: [
        {
          attacker_ip: "3.3.3.3",
          current_interactions: 7,
          previous_interactions: 4,
          interaction_delta: null,
          growth_score: undefined,
          rank_delta: 1,
        },
      ],
    });

    render(<FeedsTrending />);

    expect(screen.getByText("3.3.3.3")).toBeInTheDocument();
    expect(screen.getAllByText("-")).toHaveLength(2);
  });
});
