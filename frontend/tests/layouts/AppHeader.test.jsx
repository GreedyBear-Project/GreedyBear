import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import AppHeader from "../../src/layouts/AppHeader";
import { AUTHENTICATION_STATUSES } from "../../src/constants";
import {
  GREEDYBEAR_DOCS_URL,
  GREEDYBEAR_API_SWAGGER_URL,
  GREEDYBEAR_API_REDOC_URL,
} from "../../src/constants/environment";

// Mock useAuthStore so the header renders the guest links
// and never reaches into the real (persisted) store.
const mockUseAuthStore = vi.fn();
vi.mock("../../src/stores", () => ({
  useAuthStore: (selector) => mockUseAuthStore(selector),
}));

const renderHeader = () =>
  render(
    <MemoryRouter>
      <AppHeader />
    </MemoryRouter>,
  );

// The dropdown items are only exposed to the accessibility tree
// once the menu is open, so every link assertion opens it first.
const openDocsMenu = async () => {
  renderHeader();
  await userEvent.click(screen.getByText("Docs"));
};

describe("AppHeader docs menu", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE }),
    );
  });

  test("renders the Docs dropdown toggle", () => {
    renderHeader();
    expect(screen.getByText("Docs")).toBeInTheDocument();
  });

  test("links to the wiki and both API doc UIs", async () => {
    await openDocsMenu();

    const expectedLinks = [
      ["Wiki", GREEDYBEAR_DOCS_URL],
      ["Swagger UI", GREEDYBEAR_API_SWAGGER_URL],
      ["Redoc", GREEDYBEAR_API_REDOC_URL],
    ];

    expectedLinks.forEach(([label, href]) => {
      const link = screen.getByRole("menuitem", { name: label });
      expect(link).toHaveAttribute("href", href);
    });
  });

  test("opens every docs link in a new tab safely", async () => {
    await openDocsMenu();

    ["Wiki", "Swagger UI", "Redoc"].forEach((label) => {
      const link = screen.getByRole("menuitem", { name: label });
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noopener noreferrer");
    });
  });
});
