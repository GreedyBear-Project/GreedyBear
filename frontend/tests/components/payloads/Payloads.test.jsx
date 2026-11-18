import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import axiosHooks from "axios-hooks";
import Payloads from "../../../src/components/payloads/Payloads";

const SHA = "a".repeat(64);

const fixture = vi.hoisted(() => ({
  count: 1,
  total_pages: 1,
  results: [
    {
      id: 1,
      sha256: "a".repeat(64),
      md5: "b".repeat(32),
      sha1: "c".repeat(40),
      mime_type: "application/x-dosexec",
      size: 1234,
      source_honeypots: ["Cowrie"],
      iocs: [],
      cowrie_sessions: [],
    },
  ],
}));

const auth = vi.hoisted(() => ({ canDownloadPayloads: true }));

vi.mock("axios-hooks", () => ({
  default: vi.fn(() => [
    { data: fixture, loading: false, error: undefined },
    vi.fn(),
  ]),
}));

vi.mock("../../../src/stores", () => ({
  useAuthStore: (selector) => selector(auth),
}));

vi.mock(
  "../../../src/components/common/gb-ui/index",
  async (importOriginal) => {
    const originalModule = await importOriginal();
    const loader = (props) => (
      <originalModule.Loader loading={false} {...props} />
    );
    const Select = ({ id, choices, value, onChange, name }) => (
      <select id={id} value={value} onChange={onChange} name={name}>
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
      useAxiosComponentLoader: vi.fn(() => [["Cowrie", "Dionaea"], loader]),
    };
  },
);

const renderPage = () =>
  render(
    <BrowserRouter>
      <Payloads />
    </BrowserRouter>,
  );

const allRequests = () =>
  axiosHooks.mock.calls.map((call) => JSON.stringify(call[0]));

describe("Payloads", () => {
  beforeEach(() => {
    auth.canDownloadPayloads = true;
    axiosHooks.mockClear();
    window.history.replaceState({}, "", "/");
  });

  test("renders payload rows and total count", async () => {
    renderPage();
    expect(await screen.findByText(SHA)).toBeInTheDocument();
    expect(screen.getByText("application/x-dosexec")).toBeInTheDocument();
    expect(screen.getByText(/1 total/)).toBeInTheDocument();
  });

  test("download link is shown for authorized users", async () => {
    renderPage();
    await screen.findByText(SHA);
    const link = screen.getByRole("link", { name: "Download" });
    expect(link.getAttribute("href")).toContain(`${SHA}/download`);
  });

  test("download link is hidden for unauthorized users", async () => {
    auth.canDownloadPayloads = false;
    renderPage();
    await screen.findByText(SHA);
    expect(screen.queryByRole("link", { name: "Download" })).toBeNull();
  });

  test("honeypot dropdown lists the active honeypots", async () => {
    renderPage();
    const select = await screen.findByLabelText("Honeypot:");
    expect(select).toHaveTextContent("Cowrie");
    expect(select).toHaveTextContent("Dionaea");
  });

  test("typing does not request; Search submits the filters", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(SHA);
    await user.type(screen.getByLabelText("Hash:"), "abc123");
    expect(allRequests().some((r) => r.includes("abc123"))).toBe(false);
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() =>
      expect(allRequests().some((r) => r.includes("abc123"))).toBe(true),
    );
  });

  test("selecting a honeypot submits the filter", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.selectOptions(
      await screen.findByLabelText("Honeypot:"),
      "Cowrie",
    );
    await waitFor(() =>
      expect(allRequests().some((r) => r.includes("Cowrie"))).toBe(true),
    );
  });
});
