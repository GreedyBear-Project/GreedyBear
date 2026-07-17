import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import SuperuserGuard from "../../src/wrappers/SuperuserGuard";

// Mock useAuthStore
const mockUseAuthStore = vi.fn();
vi.mock("../../src/stores", () => ({
  useAuthStore: (selector) => mockUseAuthStore(selector),
}));

describe("SuperuserGuard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("renders children when user is a superuser", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isSuperuser: true }),
    );

    render(
      <SuperuserGuard>
        <div>Admin Content</div>
      </SuperuserGuard>,
    );

    expect(screen.getByText("Admin Content")).toBeInTheDocument();
    expect(screen.queryByText("Access Restricted")).not.toBeInTheDocument();
  });

  test("shows access-restricted message when user is NOT a superuser", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isSuperuser: false }),
    );

    render(
      <SuperuserGuard>
        <div>Admin Content</div>
      </SuperuserGuard>,
    );

    expect(screen.queryByText("Admin Content")).not.toBeInTheDocument();
    expect(screen.getByText("Access Restricted")).toBeInTheDocument();
    expect(
      screen.getByText("This page is only available to superusers."),
    ).toBeInTheDocument();
  });

  test("shows the lock emoji in the restricted view", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isSuperuser: false }),
    );

    render(
      <SuperuserGuard>
        <div>Admin Content</div>
      </SuperuserGuard>,
    );

    expect(screen.getByText("🔒")).toBeInTheDocument();
  });

  test("renders multiple children correctly for superusers", () => {
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isSuperuser: true }),
    );

    render(
      <SuperuserGuard>
        <div>Child A</div>
        <div>Child B</div>
      </SuperuserGuard>,
    );

    expect(screen.getByText("Child A")).toBeInTheDocument();
    expect(screen.getByText("Child B")).toBeInTheDocument();
  });
});
