import React from "react";
import "@testing-library/jest-dom";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import axios from "axios";
import userEvent from "@testing-library/user-event";
import ChangePassword from "../../../../src/components/me/changepassword/ChangePassword";
import { CHANGE_PASSWORD_URI } from "../../../../src/constants/api";

vi.mock("axios");
vi.mock("@greedybear/gb-ui", async () => {
  const actual = await vi.importActual("@greedybear/gb-ui");
  return {
    ...actual,
    addToast: vi.fn(),
  };
});

describe("ChangePassword component", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    axios.post.mockResolvedValue({
      data: { message: "Password changed successfully" },
    });
  });

  test("renders change password form fields and show-password toggle", () => {
    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    expect(screen.getByLabelText("Old Password")).toBeInTheDocument();
    expect(screen.getByLabelText("New Password")).toBeInTheDocument();
    expect(screen.getByLabelText("Confirm New Password")).toBeInTheDocument();
    expect(screen.getByLabelText("Show password")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Change Password/i }),
    ).toBeInTheDocument();
  });

  test("show-password toggle switches input types", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    const oldPwInput = screen.getByLabelText("Old Password");
    const newPwInput = screen.getByLabelText("New Password");
    const confirmPwInput = screen.getByLabelText("Confirm New Password");
    const toggle = screen.getByLabelText("Show password");

    // initially password type
    expect(oldPwInput).toHaveAttribute("type", "password");
    expect(newPwInput).toHaveAttribute("type", "password");
    expect(confirmPwInput).toHaveAttribute("type", "password");

    await user.click(toggle);

    expect(oldPwInput).toHaveAttribute("type", "text");
    expect(newPwInput).toHaveAttribute("type", "text");
    expect(confirmPwInput).toHaveAttribute("type", "text");
  });

  test("successful password change calls API", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    await user.type(screen.getByLabelText("Old Password"), "oldPassword123!");
    await user.type(
      screen.getByLabelText("New Password"),
      "newValidPassword123!",
    );
    await user.type(
      screen.getByLabelText("Confirm New Password"),
      "newValidPassword123!",
    );
    await user.click(screen.getByRole("button", { name: /Change Password/i }));

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        CHANGE_PASSWORD_URI,
        expect.objectContaining({
          old_password: "oldPassword123!",
          new_password: "newValidPassword123!",
        }),
        {
          headers: { "Content-Type": "application/json" },
          certegoUIenableProgressBar: false,
        },
      );
    });
  });

  test("shows inline error when new password matches old password", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    const samePassword = "samePassword123!";
    await user.type(screen.getByLabelText("Old Password"), samePassword);
    await user.type(screen.getByLabelText("New Password"), samePassword);
    // tab out to trigger onBlur / touched
    await user.tab();

    await waitFor(() => {
      expect(
        screen.getByText("New password must be different from old password"),
      ).toBeInTheDocument();
    });

    // Submit the form first before asserting axio.post was not called
    await user.click(screen.getByRole("button", { name: /Change Password/i }));
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("shows inline error when new password fails policy", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    await user.type(screen.getByLabelText("Old Password"), "oldPassword123!");
    await user.type(screen.getByLabelText("New Password"), "short");
    // tab out to trigger onBlur / touched
    await user.tab();

    await waitFor(() => {
      expect(
        screen.getByText("Must be 12 characters or more"),
      ).toBeInTheDocument();
    });

    // Submit the form first before asserting axio.post was not called
    await user.click(screen.getByRole("button", { name: /Change Password/i }));
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("shows inline error when passwords do not match", async () => {
    const user = userEvent.setup();

    render(
      <BrowserRouter>
        <ChangePassword />
      </BrowserRouter>,
    );

    await user.type(
      screen.getByLabelText("New Password"),
      "newValidPassword123!",
    );
    await user.type(
      screen.getByLabelText("Confirm New Password"),
      "differentPassword123!",
    );
    await user.tab();

    await waitFor(() => {
      // ComparePassword sets the error on both fields,
      // so we expect two matching elements
      const matches = screen.getAllByText("Passwords do not match.");
      expect(matches).toHaveLength(2);
    });

    // Submit the form first before asserting axio.post was not called
    await user.click(screen.getByRole("button", { name: /Change Password/i }));
    expect(axios.post).not.toHaveBeenCalled();
  });
});
