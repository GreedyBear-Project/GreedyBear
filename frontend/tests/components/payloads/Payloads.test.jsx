import React from "react";
import "@testing-library/jest-dom";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import Payloads from "../../../src/components/payloads/Payloads";

const SHA = "a".repeat(64);

const payload = {
  id: 1,
  sha256: SHA,
  md5: "b".repeat(32),
  sha1: "c".repeat(40),
  mime_type: "application/x-dosexec",
  size: 1234,
  source_honeypots: ["Cowrie"],
  iocs: [],
  cowrie_sessions: [],
};

const okResponse = (data) => ({
  ok: true,
  status: 200,
  json: async () => data,
});

const lastUrl = () => global.fetch.mock.calls.at(-1)[0];

describe("Payloads", () => {
  beforeEach(() => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        okResponse({ count: 1, total_pages: 1, results: [payload] }),
      );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("renders payload rows from the API", async () => {
    render(<Payloads />);
    expect(await screen.findByText(SHA)).toBeInTheDocument();
    expect(screen.getByText("application/x-dosexec")).toBeInTheDocument();
    expect(screen.getByText("1 payloads found")).toBeInTheDocument();
  });

  test("download link points to the download endpoint", async () => {
    render(<Payloads />);
    await screen.findByText(SHA);
    const link = screen.getByRole("link", { name: "Download" });
    expect(link.getAttribute("href")).toMatch(`${SHA}/download`);
  });

  test("hash search is sent to the server", async () => {
    render(<Payloads />);
    await screen.findByText(SHA);
    fireEvent.change(screen.getByLabelText("Search hash"), {
      target: { value: "abc123" },
    });
    await waitFor(() => expect(lastUrl()).toContain("search=abc123"));
  });

  test("MIME type and honeypot filters are sent to the server", async () => {
    render(<Payloads />);
    await screen.findByText(SHA);
    fireEvent.change(screen.getByLabelText("MIME type"), {
      target: { value: "text/x-shellscript" },
    });
    fireEvent.change(screen.getByLabelText("Source honeypot"), {
      target: { value: "Cowrie" },
    });
    await waitFor(() => {
      expect(lastUrl()).toContain("mime_type=text%2Fx-shellscript");
      expect(lastUrl()).toContain("honeypot=Cowrie");
    });
  });

  test("Next requests the next page", async () => {
    global.fetch.mockResolvedValue(
      okResponse({ count: 12, total_pages: 2, results: [payload] }),
    );
    render(<Payloads />);
    await screen.findByText(SHA);
    const next = screen.getByRole("button", { name: "Next" });
    await waitFor(() => expect(next).not.toBeDisabled());
    fireEvent.click(next);
    await waitFor(() => expect(lastUrl()).toContain("page=2"));
  });

  test("shows an error when the API fails", async () => {
    global.fetch.mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({}),
    });
    render(<Payloads />);
    expect(
      await screen.findByText("Failed to load payloads (500)"),
    ).toBeInTheDocument();
  });
});
