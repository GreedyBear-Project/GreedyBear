import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter, MemoryRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import Feeds from "../../../src/components/feeds/Feeds";

// mock the multiselectdrop as a native select multiple
vi.mock("../../../src/components/feeds/MultiSelectDropdown", () => {
  const MultiSelectDropdown = ({ id, options, value, onChange }) => (
    <select
      id={id}
      multiple
      value={value ? value.map((o) => o.value) : []}
      onChange={(e) => {
        const selected = Array.from(e.target.selectedOptions).map((opt) =>
          options.find((o) => o.value === opt.value),
        );
        onChange(selected);
      }}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
  return { MultiSelectDropdown };
});

vi.mock("@greedybear/gb-ui", async (importOriginal) => {
  const originalModule = await importOriginal();

  const feeds = {
    count: 1,
    total_pages: 1,
    results: {
      license: "licenseTest",
      iocs: [
        {
          value: "test",
          SCANNER: true,
          PAYLOAD_REQUEST: true,
          first_seen: "2023-03-15",
          last_seen: "2023-03-15",
          attack_count: 1,
          feed_type: "cowrie",
        },
      ],
    },
  };

  const MockTableComponent = () => <div>table</div>;
  const loader = (props) => {
    return <originalModule.Loader loading={false} {...props} />;
  };

  // Mock the Select component to render a real select for testing
  const Select = ({ id, choices, value, onChange, name }) => (
    <select
      id={id}
      data-testid={id}
      value={value}
      onChange={onChange}
      name={name}
    >
      {choices.map((c) => (
        <option key={c.value} value={c.value}>
          {c.label}
        </option>
      ))}
    </select>
  );

  return {
    ...originalModule,
    Select,
    useAxiosComponentLoader: vi.fn(() => [
      ["Honeytrap", "Glutton", "CitrixHoneypot", "Cowrie"],
      loader,
    ]),

    useDataTable: vi.fn(() => [
      feeds,
      <MockTableComponent key="mock-table" />,
      vi.fn(),
      vi.fn(),
    ]),
  };
});

describe("Feeds component", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("Feeds", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <Feeds />
      </BrowserRouter>,
    );

    const buttonFeedsLicense = screen.getByRole("link", {
      name: /Feeds license/i,
    });
    expect(buttonFeedsLicense).toHaveAttribute(
      "href",
      "https://github.com/GreedyBear-Project/GreedyBear/blob/main/FEEDS_LICENSE.md",
    );

    const feedTypeSelectElement = screen.getByLabelText("Feed type:");
    expect(feedTypeSelectElement).toBeInTheDocument();
    const attackTypeSelectElement = screen.getByLabelText("Attack type:");
    expect(attackTypeSelectElement).toBeInTheDocument();
    const iocTypeSelectElement = screen.getByLabelText("IOC type:");
    expect(iocTypeSelectElement).toBeInTheDocument();
    const prioritizationSelectElement = screen.getByLabelText("Prioritize:");
    expect(prioritizationSelectElement).toBeInTheDocument();

    const buttonRawData = screen.getByRole("link", { name: /Raw data/i });
    expect(buttonRawData).toHaveAttribute(
      "href",
      "/api/feeds/all/all/recent.json?ioc_type=all",
    );

    await user.selectOptions(feedTypeSelectElement, "cowrie");
    await user.selectOptions(attackTypeSelectElement, "scanner");
    await user.selectOptions(iocTypeSelectElement, "ip");
    await user.selectOptions(prioritizationSelectElement, "persistent");

    expect(feedTypeSelectElement).toHaveValue(["cowrie"]);
    expect(attackTypeSelectElement).toHaveValue("scanner");
    expect(iocTypeSelectElement).toHaveValue("ip");
    expect(prioritizationSelectElement).toHaveValue("persistent");

    await waitFor(() => {
      // check link has been changed including ioc_type parameter
      expect(buttonRawData).toHaveAttribute(
        "href",
        "/api/feeds/cowrie/scanner/persistent.json?ioc_type=ip",
      );
    });

    // Test selecting domain IOC type
    await user.selectOptions(iocTypeSelectElement, "domain");
    await waitFor(() => {
      expect(buttonRawData).toHaveAttribute(
        "href",
        "/api/feeds/cowrie/scanner/persistent.json?ioc_type=domain",
      );
    });

    expect(iocTypeSelectElement).toHaveValue("domain");
  });

  test("resets prioritize to recent when ordering is present and prioritize overrides ordering", async () => {
    window.history.replaceState({}, "", "/?ordering=asc");
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <Feeds />
      </BrowserRouter>,
    );

    const prioritizationSelectElement = screen.getByLabelText("Prioritize:");
    const buttonRawData = screen.getByRole("link", { name: /Raw data/i });

    await user.selectOptions(prioritizationSelectElement, "likely_to_recur");

    await waitFor(() => {
      expect(prioritizationSelectElement).toHaveValue("recent");
      expect(buttonRawData).toHaveAttribute(
        "href",
        "/api/feeds/all/all/recent.json?ioc_type=all",
      );
    });
  });

  describe("Feed type multi-select", () => {
    // helper to render the Feeds component from a clean
    // state regardless of anything left from previous test
    async function renderFeeds() {
      const user = userEvent.setup();
      render(
        <BrowserRouter>
          <Feeds />
        </BrowserRouter>,
      );
      const feedTypeSelect = screen.getByLabelText("Feed type:");
      const buttonRawData = screen.getByRole("link", { name: /Raw data/i });

      // Clear any options that were pre-selected due to shared module state
      const alreadySelected = Array.from(feedTypeSelect.selectedOptions).map(
        (o) => o.value,
      );
      if (alreadySelected.length > 0) {
        await user.deselectOptions(feedTypeSelect, alreadySelected);
        await waitFor(() => {
          expect(buttonRawData.getAttribute("href")).toMatch(
            /\/api\/feeds\/all\//,
          );
        });
      }

      return { user, feedTypeSelect, buttonRawData };
    }

    test("selecting a single type sets it in the raw data URL", async () => {
      const { user, feedTypeSelect, buttonRawData } = await renderFeeds();

      await user.selectOptions(feedTypeSelect, ["honeytrap"]);

      await waitFor(() => {
        expect(buttonRawData.getAttribute("href")).toMatch(
          /\/api\/feeds\/honeytrap\//,
        );
      });
    });

    test("selecting multiple types passes them comma-separated in the raw data URL", async () => {
      const { user, feedTypeSelect, buttonRawData } = await renderFeeds();

      await user.selectOptions(feedTypeSelect, ["cowrie", "honeytrap"]);

      await waitFor(() => {
        const href = buttonRawData.getAttribute("href");
        // Both types should appear in the URL path, comma-separated (order follows DOM)
        expect(href).toMatch(
          /\/api\/feeds\/(cowrie,honeytrap|honeytrap,cowrie)\//,
        );
      });
    });

    test("selecting multiple types passes comma-separated feed_type to the table", async () => {
      const { useDataTable } = await import("@greedybear/gb-ui");
      const { user, feedTypeSelect } = await renderFeeds();

      await user.selectOptions(feedTypeSelect, ["cowrie", "honeytrap"]);

      await waitFor(() => {
        const lastCall =
          useDataTable.mock.calls[useDataTable.mock.calls.length - 1];
        const feedTypes = lastCall[0].params.feed_type.split(",");

        expect(feedTypes).toContain("cowrie");
        expect(feedTypes).toContain("honeytrap");
        expect(feedTypes).toHaveLength(2);
      });
    });

    test("deselecting all types resets to 'all'", async () => {
      const { user, feedTypeSelect, buttonRawData } = await renderFeeds();

      // Select one type first
      await user.selectOptions(feedTypeSelect, ["cowrie"]);
      await waitFor(() => {
        expect(buttonRawData.getAttribute("href")).toMatch(
          /\/api\/feeds\/cowrie\//,
        );
      });

      // empty selection should revert to "all"
      await user.deselectOptions(feedTypeSelect, ["cowrie"]);
      await waitFor(() => {
        expect(buttonRawData.getAttribute("href")).toMatch(
          /\/api\/feeds\/all\//,
        );
      });
    });
  });

  describe("Reset filters button", () => {
    test("is disabled when all filters are at default values", () => {
      render(
        <BrowserRouter>
          <Feeds />
        </BrowserRouter>,
      );

      const resetButton = screen.getByTitle("Reset filters");
      expect(resetButton).toBeDisabled();
    });

    test("becomes enabled when a filter is changed from its default", async () => {
      const user = userEvent.setup();
      render(
        <BrowserRouter>
          <Feeds />
        </BrowserRouter>,
      );

      const attackTypeSelect = screen.getByLabelText("Attack type:");
      const resetButton = screen.getByTitle("Reset filters");

      expect(resetButton).toBeDisabled();

      await user.selectOptions(attackTypeSelect, "scanner");

      await waitFor(() => {
        expect(resetButton).not.toBeDisabled();
      });
    });

    test("resets all filters to defaults and disables itself when clicked", async () => {
      const user = userEvent.setup();
      render(
        <BrowserRouter>
          <Feeds />
        </BrowserRouter>,
      );

      const feedTypeSelect = screen.getByLabelText("Feed type:");
      const attackTypeSelect = screen.getByLabelText("Attack type:");
      const iocTypeSelect = screen.getByLabelText("IOC type:");
      const prioritizationSelect = screen.getByLabelText("Prioritize:");
      const buttonRawData = screen.getByRole("link", { name: /Raw data/i });
      const resetButton = screen.getByTitle("Reset filters");

      // change all filters away from defaults
      await user.selectOptions(feedTypeSelect, ["cowrie"]);
      await user.selectOptions(attackTypeSelect, "scanner");
      await user.selectOptions(iocTypeSelect, "ip");
      await user.selectOptions(prioritizationSelect, "persistent");

      await waitFor(() => {
        expect(resetButton).not.toBeDisabled();
        expect(buttonRawData).toHaveAttribute(
          "href",
          "/api/feeds/cowrie/scanner/persistent.json?ioc_type=ip",
        );
      });

      // click reset
      await user.click(resetButton);

      await waitFor(() => {
        expect(attackTypeSelect).toHaveValue("all");
        expect(iocTypeSelect).toHaveValue("all");
        expect(prioritizationSelect).toHaveValue("recent");
        expect(feedTypeSelect).toHaveValue([]);
        expect(buttonRawData).toHaveAttribute(
          "href",
          "/api/feeds/all/all/recent.json?ioc_type=all",
        );
        expect(resetButton).toBeDisabled();
      });
    });
  });

  // ─── NEW: URL query param persistence tests ───────────────────────────────

  describe("URL query param persistence", () => {
    test("initializes filters from URL query params on page load", async () => {
      render(
        <MemoryRouter
          initialEntries={[
            "/?attack_type=scanner&ioc_type=ip&prioritize=persistent",
          ]}
        >
          <Feeds />
        </MemoryRouter>,
      );

      await waitFor(() => {
        expect(screen.getByLabelText("Attack type:")).toHaveValue("scanner");
        expect(screen.getByLabelText("IOC type:")).toHaveValue("ip");
        expect(screen.getByLabelText("Prioritize:")).toHaveValue("persistent");
      });
    });

    test("updates raw data URL when a filter is changed", async () => {
      const user = userEvent.setup();

      render(
        <MemoryRouter initialEntries={["/"]}>
          <Feeds />
        </MemoryRouter>,
      );

      const attackTypeSelect = screen.getByLabelText("Attack type:");
      await user.selectOptions(attackTypeSelect, "scanner");

      await waitFor(() => {
        expect(screen.getByRole("link", { name: /Raw data/i })).toHaveAttribute(
          "href",
          "/api/feeds/all/scanner/recent.json?ioc_type=all",
        );
      });
    });

    test("raw data URL starts with defaults when no query params present", () => {
      render(
        <MemoryRouter initialEntries={["/"]}>
          <Feeds />
        </MemoryRouter>,
      );

      expect(screen.getByRole("link", { name: /Raw data/i })).toHaveAttribute(
        "href",
        "/api/feeds/all/all/recent.json?ioc_type=all",
      );
    });
    test("clears filters when reset button is clicked after loading from query params", async () => {
      const user = userEvent.setup();

      render(
        <MemoryRouter initialEntries={["/?attack_type=scanner&ioc_type=ip"]}>
          <Feeds />
        </MemoryRouter>,
      );

      const resetButton = screen.getByTitle("Reset filters");
      const attackTypeSelect = screen.getByLabelText("Attack type:");
      const iocTypeSelect = screen.getByLabelText("IOC type:");

      await waitFor(() => {
        expect(attackTypeSelect).toHaveValue("scanner");
        expect(iocTypeSelect).toHaveValue("ip");
        expect(resetButton).not.toBeDisabled();
      });

      await user.click(resetButton);

      await waitFor(() => {
        expect(attackTypeSelect).toHaveValue("all");
        expect(iocTypeSelect).toHaveValue("all");
        expect(resetButton).toBeDisabled();
      });
    });

    test("raw data URL reflects filters loaded from query params", async () => {
      render(
        <MemoryRouter
          initialEntries={[
            "/?feed_type=cowrie&attack_type=scanner&ioc_type=ip&prioritize=persistent",
          ]}
        >
          <Feeds />
        </MemoryRouter>,
      );

      await waitFor(() => {
        expect(screen.getByRole("link", { name: /Raw data/i })).toHaveAttribute(
          "href",
          "/api/feeds/cowrie/scanner/persistent.json?ioc_type=ip",
        );
      });
    });
  });
});
