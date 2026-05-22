import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";

import Sessions from "../../../../src/components/me/sessions/Sessions";

// Mock sub-components
vi.mock("../../../../src/components/me/sessions/SessionList", () => ({
  default: () => <div data-testid="mock-session-list">Mock Session List</div>,
}));
vi.mock("../../../../src/components/me/sessions/APIaccess", () => ({
  default: () => <div data-testid="mock-api-access">Mock API Access</div>,
}));

// Mock @greedybear/gb-ui components used in Sessions
vi.mock("@greedybear/gb-ui", () => ({
  ContentSection: ({ children, className }) => (
    <div data-testid="content-section" className={className}>
      {children}
    </div>
  ),
}));

describe("Sessions", () => {
  test("renders layout and both sub-components", () => {
    render(<Sessions />);

    // Check titles
    expect(screen.getByText("API Access")).toBeInTheDocument();
    expect(screen.getByText("Browser Sessions")).toBeInTheDocument();

    // Check alert text
    expect(screen.getByText(/You can generate an API key/)).toBeInTheDocument();

    // Check sub-components are present
    expect(screen.getByTestId("mock-api-access")).toBeInTheDocument();
    expect(screen.getByTestId("mock-session-list")).toBeInTheDocument();

    // Check ContentSections
    const sections = screen.getAllByTestId("content-section");
    expect(sections).toHaveLength(2);
  });
});
