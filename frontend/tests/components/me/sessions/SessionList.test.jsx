import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import SessionsList from "../../../../src/components/me/sessions/SessionList";
import {
  deleteOtherSessions,
  deleteTokenById,
} from "../../../../src/components/me/sessions/api";
import { confirm, useAxiosComponentLoader } from "@greedybear/gb-ui";

vi.mock("../../../../src/components/me/sessions/api", () => ({
  deleteOtherSessions: vi.fn(),
  deleteTokenById: vi.fn(),
}));

const refetchMock = vi.fn();

vi.mock("@greedybear/gb-ui", async () => {
  const actual = await vi.importActual("@greedybear/gb-ui");
  return {
    ...actual,
    confirm: vi.fn(),
    IconButton: ({ id, title, onClick }) => (
      <button
        type="button"
        data-testid={id}
        aria-label={title}
        onClick={onClick}
      >
        {title}
      </button>
    ),
    DateHoverable: ({ id }) => <span data-testid={id} />,
    useAxiosComponentLoader: vi.fn(),
  };
});

describe("SessionsList", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });

    const unsortedSessions = [
      {
        id: 2,
        client: "Firefox",
        created: 200,
        expiry: 300,
        has_expired: false,
        is_current: false,
      },
      {
        id: 1,
        client: "Current Browser",
        created: 100,
        expiry: 400,
        has_expired: false,
        is_current: true,
      },
      {
        id: 3,
        client: "Safari",
        created: 300,
        expiry: 500,
        has_expired: false,
        is_current: false,
      },
      {
        id: 4,
        client: "Old Browser",
        created: 50,
        expiry: 150,
        has_expired: true,
        is_current: false,
      },
    ];

    useAxiosComponentLoader.mockImplementation((_, transformer) => {
      const tokenSessions = transformer(unsortedSessions);
      const Loader = ({ render: renderFn }) => renderFn();
      return [tokenSessions, Loader, refetchMock];
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("renders sessions with current one first and hides revoke button for current session", () => {
    render(<SessionsList />);

    const deviceLabels = screen
      .getAllByText(/Current Browser|Firefox|Safari|Old Browser/)
      .map((el) => el.textContent.replace(/^Device\s*/i, "").trim());
    expect(deviceLabels).toEqual([
      "Current Browser",
      "Safari",
      "Firefox",
      "Old Browser",
    ]);

    expect(screen.getByText("current")).toBeInTheDocument();
    expect(screen.getByText("expired")).toBeInTheDocument();
    expect(
      screen.queryByTestId("sessionslist-1__revoke-btn"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByTestId("sessionslist-2__revoke-btn"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("sessionslist-3__revoke-btn"),
    ).toBeInTheDocument();
  });

  test("revoke other sessions is cancelled when confirmation is rejected", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    confirm.mockResolvedValue(false);

    render(<SessionsList />);

    await user.click(screen.getByTestId("sessionslist__revoke-others-btn"));

    expect(confirm).toHaveBeenCalled();
    expect(deleteOtherSessions).not.toHaveBeenCalled();
    expect(refetchMock).not.toHaveBeenCalled();
  });

  test("revoke other sessions calls API and triggers delayed refetch", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    confirm.mockResolvedValue(true);
    deleteOtherSessions.mockResolvedValue({});

    render(<SessionsList />);

    await user.click(screen.getByTestId("sessionslist__revoke-others-btn"));

    await waitFor(() => {
      expect(deleteOtherSessions).toHaveBeenCalledTimes(1);
    });

    expect(refetchMock).not.toHaveBeenCalled();
    vi.advanceTimersByTime(500);
    expect(refetchMock).toHaveBeenCalledTimes(1);
  });

  test("revoke single session is cancelled when confirmation is rejected", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    confirm.mockResolvedValue(false);

    render(<SessionsList />);

    await user.click(screen.getByTestId("sessionslist-2__revoke-btn"));

    expect(confirm).toHaveBeenCalled();
    expect(deleteTokenById).not.toHaveBeenCalled();
    vi.advanceTimersByTime(500);
    expect(refetchMock).not.toHaveBeenCalled();
  });

  test("revoke single session passes id and client name then triggers delayed refetch", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    confirm.mockResolvedValue(true);
    deleteTokenById.mockResolvedValue({});

    render(<SessionsList />);

    await user.click(screen.getByTestId("sessionslist-2__revoke-btn"));

    await waitFor(() => {
      expect(deleteTokenById).toHaveBeenCalledWith(2, "Firefox");
    });

    vi.advanceTimersByTime(500);
    expect(refetchMock).toHaveBeenCalledTimes(1);
  });
});
