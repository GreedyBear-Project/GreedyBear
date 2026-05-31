import React from "react";
import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import Dashboard from "../../../src/components/dashboard/Dashboard";

vi.mock("axios");

const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
// mock charts module
vi.mock(
  "../../../src/components/dashboard/utils/charts",
  async (importOriginal) => {
    const originalChartModule = await importOriginal();
    const FeedsSourcesChart = () => <div />;
    const FeedsDownloadsChart = () => <div />;
    const EnrichmentSourcesChart = () => <div />;
    const EnrichmentRequestsChart = () => <div />;
    const FeedsTypesChart = () => <div />;
    const AttackOriginCountriesChart = () => {
      throw new Error("Widget failure");
    };

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

describe("Dashboard component", () => {
  afterEach(() => {
    consoleErrorSpy.mockClear();
  });

  test("Dashboard", () => {
    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    const FeedsSourcesChart = screen.getByText("Feeds: Sources");
    expect(FeedsSourcesChart).toBeInTheDocument();
    const FeedsDownloadsChart = screen.getByText("Feeds: Downloads");
    expect(FeedsDownloadsChart).toBeInTheDocument();
    const FeedsTypesChart = screen.getByText("Feeds: Types");
    expect(FeedsTypesChart).toBeInTheDocument();
    const EnrichmentSourcesChart = screen.getByText(
      "Enrichment Service: Sources",
    );
    expect(EnrichmentSourcesChart).toBeInTheDocument();
    const EnrichmentRequestsChart = screen.getByText(
      "Enrichment Service: Requests",
    );
    expect(EnrichmentRequestsChart).toBeInTheDocument();
  });

  test("renders a fallback for a throwing widget while keeping the dashboard alive", () => {
    render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>,
    );

    expect(screen.getByText("Widget failed to render.")).toBeInTheDocument();
    expect(screen.getByText("Widget failure")).toBeInTheDocument();
    expect(screen.getByText("Feeds: Sources")).toBeInTheDocument();
    expect(screen.getByText("Attack Origins: World Map")).toBeInTheDocument();
  });
});
