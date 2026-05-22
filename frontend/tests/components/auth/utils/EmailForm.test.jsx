import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import userEvent from "@testing-library/user-event";
import EmailForm from "../../../../src/components/auth/utils/EmailForm";
import { requestPasswordReset } from "../../../../src/components/auth/api";
import axios from "axios";

vi.mock("axios");

vi.mock("@greedybear/gb-ui", () => ({
  addToast: vi.fn(),
}));

describe("EmailForm component", () => {
  test("Submit email form", async () => {
    // mock user interaction: reccomanded to put this at the start of the test
    const user = userEvent.setup();
    const mockApi = vi.fn();

    render(
      <BrowserRouter>
        <EmailForm apiCallback={mockApi} onFormSubmit={vi.fn()} />
      </BrowserRouter>,
    );

    const emailInputElement = screen.getByLabelText("Email Address");
    expect(emailInputElement).toBeInTheDocument();
    const submitButtonElement = screen.getByRole("button", { name: /Send/i });
    expect(submitButtonElement).toBeInTheDocument();

    // user populates the reset password form and submit
    await user.type(emailInputElement, "test@test.com");
    await user.click(submitButtonElement);
  });

  test("Double-clicking submit while submitting does not trigger duplicate API requests", async () => {
    const user = userEvent.setup();
    // a promise to simulate a pending request
    let resolveApi;
    const mockApi = vi.fn(
      () =>
        new Promise((resolve) => {
          resolveApi = resolve;
        }),
    );
    const mockOnFormSubmit = vi.fn();

    render(
      <BrowserRouter>
        <EmailForm apiCallback={mockApi} onFormSubmit={mockOnFormSubmit} />
      </BrowserRouter>,
    );

    const emailInputElement = screen.getByLabelText("Email Address");
    const submitButtonElement = screen.getByRole("button", { name: /Send/i });

    // Populating the email input and submitting
    await user.type(emailInputElement, "test@test.com");

    // First submit
    await user.click(submitButtonElement);

    // Checking the button is disabled while submitting
    await waitFor(() => {
      expect(submitButtonElement).toBeDisabled();
    });

    // Second submit
    await user.click(submitButtonElement);

    // Only one api call was made?
    expect(mockApi).toHaveBeenCalledTimes(1);

    resolveApi();

    // Waiting for submission to fully settle by checking the button re-enables
    await waitFor(() => {
      expect(submitButtonElement).not.toBeDisabled();
    });
  });

  test("Does not trigger onFormSubmit and re-enables button when API request fails", async () => {
    const user = userEvent.setup();

    vi.mocked(axios.post).mockRejectedValueOnce(new Error("Network Error"));
    const mockOnFormSubmit = vi.fn();

    render(
      <BrowserRouter>
        <EmailForm
          apiCallback={requestPasswordReset}
          onFormSubmit={mockOnFormSubmit}
        />
      </BrowserRouter>,
    );

    const emailInputElement = screen.getByLabelText("Email Address");
    const submitButtonElement = screen.getByRole("button", { name: /Send/i });

    await user.type(emailInputElement, "test@test.com");
    await user.click(submitButtonElement);

    expect(axios.post).toHaveBeenCalledTimes(1);

    await waitFor(() => {
      expect(submitButtonElement).not.toBeDisabled();
    });

    expect(mockOnFormSubmit).not.toHaveBeenCalled();
  });
});
