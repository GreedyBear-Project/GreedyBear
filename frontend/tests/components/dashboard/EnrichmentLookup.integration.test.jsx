import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import Dashboard from "../../../src/components/dashboard/Dashboard";
import { ENRICHMENT_URI } from "../../../src/constants/api";
import { AUTHENTICATION_STATUSES } from "../../../src/constants";

vi.mock("axios");

// Mock charts module
vi.mock(
  "../../../src/components/dashboard/utils/charts",
  async (importOriginal) => {
    const originalChartModule = await importOriginal();
    const FeedsSourcesChart = () => <div />;
    const FeedsDownloadsChart = () => <div />;
    const EnrichmentSourcesChart = () => <div />;
    const EnrichmentRequestsChart = () => <div />;
    const FeedsTypesChart = () => <div />;
    const AttackOriginCountriesChart = () => <div />;

    return {
      ...originalChartModule,
      FeedsSourcesChart,
      FeedsDownloadsChart,
      EnrichmentSourcesChart,
      EnrichmentRequestsChart,
      FeedsTypesChart,
      AttackOriginCountriesChart,
    };
  },
);

vi.mock("../../../src/components/dashboard/AttackOriginMap", () => ({
  default: () => <div />,
}));

// Mock useAuthStore
const mockUseAuthStore = vi.fn();
vi.mock("../../../src/stores", () => ({
  useAuthStore: (selector) => mockUseAuthStore(selector),
}));

// Import store to set serverSynced before Dashboard mounts
import useDashboardStore from "../../../src/stores/useDashboardStore";

describe("Enrichment Lookup Integration Tests", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Prevent axios.get from firing
    // by marking the store as already synced this session.
    useDashboardStore.setState({ serverSynced: true });
  });

  test("enrichment lookup section is visible on dashboard page", () => {
    // Mock authenticated state to see the enrichment section
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    // Verify the Enrichment Lookup section header is present
    expect(screen.getByText("Enrichment Lookup")).toBeInTheDocument();

    // Verify the form elements are present
    expect(screen.getByLabelText("IP Address or Domain:")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Search/i })).toBeInTheDocument();
  });

  test("try looking up an IP without authentication", async () => {
    const user = userEvent.setup();

    // Mock unauthenticated state
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE }),
    );

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    // Verify enrichment lookup section is still visible (publicly visible)
    expect(screen.getByText("Enrichment Lookup")).toBeInTheDocument();

    // Get form elements
    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    // Input and submit should be disabled for unauthenticated users
    expect(inputElement).toBeDisabled();
    expect(submitButton).toBeDisabled();

    // Helper text should indicate authentication is required
    expect(
      screen.getByPlaceholderText(/You need to be logged in to search!/i),
    ).toBeInTheDocument();

    // Verify API was NOT called
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("look up an IP with authentication - found scenario", async () => {
    const user = userEvent.setup();

    // Mock authenticated state
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );

    // Mock successful API response with IOC data
    const mockIocData = {
      name: "192.168.1.100",
      type: "ip",
      attack_count: 42,
      interaction_count: 150,
      login_attempts: 25,
      first_seen: "2024-01-01",
      last_seen: "2024-01-15",
      scanner: true,
      payload_request: true,
      ip_reputation: "malicious",
      asn: "12345",
      destination_ports: [22, 80, 443],
      firehol_categories: ["abuse"],
      general_honeypot: ["Cowrie", "Heralding"],
      recurrence_probability: 0.85,
      expected_interactions: 120.5,
    };

    axios.get.mockResolvedValue({
      data: {
        found: true,
        query: "192.168.1.100",
        ioc: mockIocData,
      },
    });

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    // Get form elements
    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    // Search for an IP with authentication
    await user.type(inputElement, "192.168.1.100");
    await user.click(submitButton);

    // Verify API was called with correct parameters
    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(ENRICHMENT_URI, {
        params: { query: "192.168.1.100" },
        headers: { "Content-Type": "application/json" },
      });
    });

    // Verify IOC details are displayed
    await waitFor(() => {
      expect(
        screen.getByText(/IOC Details for: 192.168.1.100/i),
      ).toBeInTheDocument();
      expect(screen.getByText("42")).toBeInTheDocument(); // attack_count
      expect(screen.getByText("150")).toBeInTheDocument(); // interaction_count
      expect(screen.getByText("malicious")).toBeInTheDocument(); // ip_reputation
      expect(screen.getByText("Cowrie")).toBeInTheDocument(); // honeypot
    });
  });

  test("look up an IP with authentication - not found scenario", async () => {
    const user = userEvent.setup();

    // Mock authenticated state
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );

    // Mock API response - IP not found in database
    axios.get.mockResolvedValue({
      data: {
        found: false,
        query: "1.2.3.4",
        ioc: null,
      },
    });

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    // Get form elements
    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    // Search for an IP that doesn't exist in the database
    await user.type(inputElement, "1.2.3.4");
    await user.click(submitButton);

    // Verify API was called
    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(ENRICHMENT_URI, {
        params: { query: "1.2.3.4" },
        headers: { "Content-Type": "application/json" },
      });
    });

    // Verify "not found" message is displayed
    await waitFor(() => {
      expect(
        screen.getByText(/No data available for "1.2.3.4" in our database/i),
      ).toBeInTheDocument();
    });
  });

  test("client-side validation prevents obvious invalid queries", async () => {
    const user = userEvent.setup();

    // Mock authenticated state
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    // Get form elements
    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    const invalidInputs = [
      "invalid ip", // space
      "http://example.com", // protocol
      "exa mple.com", // space in domain
      "!!!", // invalid characters
      "justtext", // no dot, not IP-like
    ];

    for (const value of invalidInputs) {
      await user.clear(inputElement);
      await user.type(inputElement, value);
      await user.click(submitButton);

      expect(
        screen.getByText(
          /Please enter a value that looks like an IP or domain/i,
        ),
      ).toBeInTheDocument();
    }

    // Verify API was NOT called due to client-side validation
    await waitFor(() => {
      expect(axios.get).not.toHaveBeenCalled();
    });
  });

  test("accepts domains with underscores (e.g., service records)", async () => {
    const user = userEvent.setup();

    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );

    axios.get.mockResolvedValue({
      data: { found: false, query: "_acme-challenge.example.com", ioc: null },
    });

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    // Search for a domain starting with an underscore
    await user.type(inputElement, "_acme-challenge.example.com");
    await user.click(submitButton);

    // Verify API WAS called (validation passed)
    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(ENRICHMENT_URI, {
        params: { query: "_acme-challenge.example.com" },
        headers: { "Content-Type": "application/json" },
      });
    });
  });

  test("uses only formik isSubmitting for button state, no redundant loading state", async () => {
    const user = userEvent.setup();

    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );

    // Mock a delayed API response to catch in-flight state
    axios.get.mockImplementation(
      () =>
        new Promise((resolve) =>
          setTimeout(
            () => resolve({ data: { found: false, query: "1.1.1.1" } }),
            100,
          ),
        ),
    );

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    await user.type(inputElement, "1.1.1.1");
    await user.click(submitButton);

    // While request is in flight, button should say "Searching..."
    expect(
      screen.getByRole("button", { name: /Searching/i }),
    ).toBeInTheDocument();
    expect(submitButton).toBeDisabled();

    // After request completes, button should say "Search" again
    await waitFor(() => {
      expect(
        screen.getByRole("button", { name: /^Search$/i }),
      ).toBeInTheDocument();
    });
  });

  test("look up an IP with authentication - sensors display scenario", async () => {
    const user = userEvent.setup();

    // Mock authenticated state
    mockUseAuthStore.mockImplementation((selector) =>
      selector({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE }),
    );

    // Mock successful API response with sensors data
    const mockIocData = {
      name: "8.8.8.8",
      type: "ip",
      attack_count: 10,
      interaction_count: 20,
      login_attempts: 5,
      first_seen: "2024-01-01",
      last_seen: "2024-01-15",
      scanner: true,
      payload_request: false,
      sensors: [
        { address: "10.0.0.1", label: "AWS-Prod" },
        { address: "10.0.0.2", label: "" },
      ],
    };

    axios.get.mockResolvedValue({
      data: {
        found: true,
        query: "8.8.8.8",
        ioc: mockIocData,
      },
    });

    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    const inputElement = screen.getByLabelText("IP Address or Domain:");
    const submitButton = screen.getByRole("button", { name: /Search/i });

    await user.type(inputElement, "8.8.8.8");
    await user.click(submitButton);

    // Verify sensors are displayed
    await waitFor(() => {
      expect(screen.getByText(/Sensors:/i)).toBeInTheDocument();
      expect(screen.getByText(/10\.0\.0\.1/i)).toBeInTheDocument();
      expect(screen.getByText(/\(AWS-Prod\)/i)).toBeInTheDocument();
      expect(screen.getByText(/10\.0\.0\.2/i)).toBeInTheDocument();
    });
  });
});
