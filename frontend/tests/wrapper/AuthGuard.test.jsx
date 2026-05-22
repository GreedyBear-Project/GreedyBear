import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import AuthGuard from "../../src/wrappers/AuthGuard";
import { AUTHENTICATION_STATUSES } from "../../src/constants";
import { addToast } from "@greedybear/gb-ui";

const mockUseAuthStore = vi.fn();
vi.mock("../../src/stores", () => ({
  useAuthStore: (selector) => mockUseAuthStore(selector),
}));

vi.mock("@greedybear/gb-ui", async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    addToast: vi.fn(),
    FallBackLoading: () => <div>Loading...</div>,
  };
});

describe("AuthGuard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("shows fallback loading when authentication status is pending", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.PENDING }),
    );

    render(
      <MemoryRouter initialEntries={["/me/sessions"]}>
        <Routes>
          <Route
            path="/me/sessions"
            element={
              <AuthGuard>
                <div>Protected Content</div>
              </AuthGuard>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Loading...")).toBeInTheDocument();
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
  });

  test("renders children when user is authenticated", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );

    render(
      <MemoryRouter initialEntries={["/me/sessions"]}>
        <Routes>
          <Route
            path="/me/sessions"
            element={
              <AuthGuard>
                <div>Protected Content</div>
              </AuthGuard>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Protected Content")).toBeInTheDocument();
  });

  test("redirects unauthenticated user to /login with ?next param", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE }),
    );

    render(
      <MemoryRouter initialEntries={["/me/sessions"]}>
        <Routes>
          <Route
            path="/me/sessions"
            element={
              <AuthGuard>
                <div>Protected Content</div>
              </AuthGuard>
            }
          />
          <Route path="/login" element={<div>Login Page</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Login Page")).toBeInTheDocument();
    expect(screen.queryByText("Protected Content")).not.toBeInTheDocument();
    expect(addToast).toHaveBeenCalledWith(
      "Login required to access the requested page.",
      null,
      "info",
    );
  });

  test("redirects to / when user visits /logout while unauthenticated", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE }),
    );

    render(
      <MemoryRouter initialEntries={["/logout"]}>
        <Routes>
          <Route
            path="/logout"
            element={
              <AuthGuard>
                <div>Protected Content</div>
              </AuthGuard>
            }
          />
          <Route path="/" element={<div>Home Page</div>} />
          <Route path="/login" element={<div>Login Page</div>} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText("Home Page")).toBeInTheDocument();
    expect(screen.queryByText("Login Page")).not.toBeInTheDocument();
    expect(addToast).not.toHaveBeenCalled();
  });
});
