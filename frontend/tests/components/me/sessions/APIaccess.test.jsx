import "@testing-library/jest-dom";
import {
  render,
  screen,
  waitFor,
  act,
  fireEvent,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import APIAccess from "../../../../src/components/me/sessions/APIaccess";
import {
  createNewToken,
  deleteToken,
} from "../../../../src/components/me/sessions/api";
import { confirm, useAxiosComponentLoader } from "@greedybear/gb-ui";

vi.mock("../../../../src/components/me/sessions/api", () => ({
  createNewToken: vi.fn(),
  deleteToken: vi.fn(),
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
    CopyToClipboardButton: ({ children, text }) => (
      <div data-testid="copy-to-clipboard" data-text={text}>
        {children}
      </div>
    ),
    DateHoverable: ({ id, value }) => <span data-testid={id}>{value}</span>,
    useAxiosComponentLoader: vi.fn(),
  };
});

describe("APIAccess", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("renders 'No active API key' when loader returns 404", () => {
    useAxiosComponentLoader.mockImplementation(() => {
      const Loader = ({ renderError }) =>
        renderError({
          error: { response: { status: 404 } },
        });
      return [null, Loader, refetchMock];
    });

    render(<APIAccess />);

    expect(screen.getByText("No active API key")).toBeInTheDocument();
    expect(screen.getByTestId("create-apikey-btn")).toBeInTheDocument();
  });

  test("calls createNewToken and refetches when 'Create' button is clicked", async () => {
    vi.useFakeTimers();
    useAxiosComponentLoader.mockImplementation(() => {
      const Loader = ({ renderError }) =>
        renderError({
          error: { response: { status: 404 } },
        });
      return [null, Loader, refetchMock];
    });
    createNewToken.mockResolvedValue({});

    render(<APIAccess />);

    // Use fireEvent instead of userEvent to avoid hanging on async onClick with fake timers
    await act(async () => {
      fireEvent.click(screen.getByTestId("create-apikey-btn"));
    });

    expect(createNewToken).toHaveBeenCalledTimes(1);
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(refetchMock).toHaveBeenCalledTimes(1);
  });

  test("renders token details and handles visibility toggle", async () => {
    const user = userEvent.setup();
    const mockData = {
      token: "secret-token-123",
      created: "2024-01-01T10:00:00Z",
      expiry: "2025-01-01T10:00:00Z",
    };
    useAxiosComponentLoader.mockImplementation(() => {
      const Loader = ({ render: renderFn }) => renderFn();
      return [mockData, Loader, refetchMock];
    });

    render(<APIAccess />);

    // Check dates are rendered
    expect(screen.getByTestId("apikey__created")).toHaveTextContent(
      mockData.created,
    );
    expect(screen.getByTestId("apikey__expires")).toHaveTextContent(
      mockData.expiry,
    );

    // Initially blurry/hidden
    expect(screen.queryByText(mockData.token)).not.toBeInTheDocument();
    expect(
      screen.getByText("tokentokentokentokentokentoken"),
    ).toBeInTheDocument();

    // Toggle visibility
    await user.click(screen.getByTestId("toggle-show-apikey-btn"));

    // Now visible
    await waitFor(() => {
      expect(screen.getByText(mockData.token)).toBeInTheDocument();
    });
    expect(
      screen.queryByText("tokentokentokentokentokentoken"),
    ).not.toBeInTheDocument();

    // Toggle back
    await user.click(screen.getByTestId("toggle-show-apikey-btn"));
    await waitFor(() => {
      expect(screen.queryByText(mockData.token)).not.toBeInTheDocument();
    });
    expect(
      screen.getByText("tokentokentokentokentokentoken"),
    ).toBeInTheDocument();
  });

  test("calls deleteToken and refetches when confirmed", async () => {
    vi.useFakeTimers();
    const mockData = { token: "token-to-delete" };
    useAxiosComponentLoader.mockImplementation(() => {
      const Loader = ({ render: renderFn }) => renderFn();
      return [mockData, Loader, refetchMock];
    });
    confirm.mockResolvedValue(true);
    deleteToken.mockResolvedValue({});

    render(<APIAccess />);

    // Use fireEvent instead of userEvent to avoid hanging on async onClick with fake timers
    await act(async () => {
      fireEvent.click(screen.getByTestId("delete-apikey-btn"));
    });

    expect(confirm).toHaveBeenCalled();
    expect(deleteToken).toHaveBeenCalledTimes(1);
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(refetchMock).toHaveBeenCalledTimes(1);
  });

  test("does not call deleteToken when cancelled", async () => {
    vi.useFakeTimers();
    const mockData = { token: "token-to-stay" };
    useAxiosComponentLoader.mockImplementation(() => {
      const Loader = ({ render: renderFn }) => renderFn();
      return [mockData, Loader, refetchMock];
    });
    confirm.mockResolvedValue(false);

    render(<APIAccess />);

    // Use fireEvent instead of userEvent to avoid hanging on async onClick with fake timers
    await act(async () => {
      fireEvent.click(screen.getByTestId("delete-apikey-btn"));
    });

    expect(confirm).toHaveBeenCalled();
    expect(deleteToken).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(500);
    });
    expect(refetchMock).not.toHaveBeenCalled();
  });

  test("renders ErrorAlert when loader returns a non-404 error", () => {
    const mockError = {
      message: "Internal Server Error",
      response: { status: 500 },
    };
    useAxiosComponentLoader.mockImplementation(() => {
      const Loader = ({ renderError }) => renderError({ error: mockError });
      return [null, Loader, refetchMock];
    });

    render(<APIAccess />);

    expect(screen.getByText(/Error!/)).toBeInTheDocument();
    expect(screen.getByText("500")).toBeInTheDocument();
  });
});
