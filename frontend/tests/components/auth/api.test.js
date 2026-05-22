import axios from "axios";
import { addToast } from "@greedybear/gb-ui";

import {
  registerUser,
  verifyEmail,
  resendVerificationMail,
  requestPasswordReset,
  resetPassword,
  checkConfiguration,
} from "../../../src/components/auth/api";
import { AUTH_BASE_URI } from "../../../src/constants/api";

vi.mock("axios");
vi.mock("@greedybear/gb-ui", () => ({
  addToast: vi.fn(),
}));

describe("auth api helpers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // registerUser
  test("registerUser calls endpoint and returns response", async () => {
    const mockResponse = { status: 201 };
    axios.post.mockResolvedValue(mockResponse);

    const body = { username: "testuser", password: "testpass" };
    const result = await registerUser(body);

    expect(axios.post).toHaveBeenCalledWith(`${AUTH_BASE_URI}/register`, body);
    expect(result).toEqual(mockResponse);

    expect(addToast).not.toHaveBeenCalled();
  });

  test("registerUser rejects and shows failure toast", async () => {
    const error = { parsedMsg: "email already exists" };
    axios.post.mockRejectedValue(error);

    await expect(registerUser({ username: "testuser" })).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Registration failed!",
      "email already exists",
      "danger",
      true,
    );
  });

  // verifyEmail
  test("verifyEmail calls endpoint and shows success toast", async () => {
    const mockResponse = { status: 200 };
    axios.post.mockResolvedValue(mockResponse);

    const body = { key: "verification-key" };
    const result = await verifyEmail(body);

    expect(axios.post).toHaveBeenCalledWith(
      `${AUTH_BASE_URI}/verify-email`,
      body,
    );

    expect(addToast).toHaveBeenCalledWith(
      "Your email has been succesfully verified!",
      null,
      "success",
      true,
    );
    expect(result).toEqual(mockResponse);
  });

  test("verifyEmail rejects and shows failure toast", async () => {
    const error = { parsedMsg: "invalid key" };
    axios.post.mockRejectedValue(error);

    await expect(verifyEmail({ key: "bad-key" })).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Email verification failed!",
      "invalid key",
      "danger",
      true,
    );
  });

  // resendVerificationMail
  test("resendVerificationMail calls endpoint and shows success toast", async () => {
    const mockResponse = { status: 200 };
    axios.post.mockResolvedValue(mockResponse);

    const body = { email: "test@test.com" };
    const result = await resendVerificationMail(body);

    expect(axios.post).toHaveBeenCalledWith(
      `${AUTH_BASE_URI}/resend-verification`,
      body,
    );
    expect(addToast).toHaveBeenCalledWith(
      "Verification email sent!",
      null,
      "success",
    );
    expect(result).toEqual(mockResponse);
  });

  test("resendVerificationMail rejects and shows failure toast", async () => {
    const error = { parsedMsg: "user not found" };
    axios.post.mockRejectedValue(error);

    await expect(
      resendVerificationMail({ email: "test@test.com" }),
    ).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Failed to send email!",
      "user not found",
      "danger",
      true,
    );
  });

  // requestPasswordReset
  test("requestPasswordReset calls endpoint and shows success toast", async () => {
    const mockResponse = { status: 200 };
    axios.post.mockResolvedValue(mockResponse);

    const body = { email: "test@test.com" };
    const result = await requestPasswordReset(body);

    expect(axios.post).toHaveBeenCalledWith(
      `${AUTH_BASE_URI}/request-password-reset`,
      body,
    );
    expect(addToast).toHaveBeenCalledWith("Email sent!", null, "success");
    expect(result).toEqual(mockResponse);
  });

  test("requestPasswordReset rejects and shows failure toast", async () => {
    const error = { parsedMsg: "email not found" };
    axios.post.mockRejectedValue(error);

    await expect(
      requestPasswordReset({ email: "test@test.com" }),
    ).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Failed to send email!",
      "email not found",
      "danger",
      true,
    );
  });

  // resetPassword
  test("resetPassword calls endpoint and shows success toast", async () => {
    const mockResponse = { status: 200 };
    axios.post.mockResolvedValue(mockResponse);

    const body = { token: "reset-token", password: "newpass" };
    const result = await resetPassword(body);

    expect(axios.post).toHaveBeenCalledWith(
      `${AUTH_BASE_URI}/reset-password`,
      body,
    );
    expect(addToast).toHaveBeenCalledWith(
      "Password reset successfully!",
      null,
      "success",
      true,
    );
    expect(result).toEqual(mockResponse);
  });

  test("resetPassword rejects and shows failure toast", async () => {
    const error = { parsedMsg: "invalid token" };
    axios.post.mockRejectedValue(error);

    await expect(
      resetPassword({ token: "bad-token", password: "newpass" }),
    ).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Password reset failed!",
      "invalid token",
      "danger",
      true,
    );
  });

  // checkConfiguration
  test("checkConfiguration calls endpoint and returns response", async () => {
    const mockResponse = { status: 200, data: { email_enabled: true } };
    axios.get.mockResolvedValue(mockResponse);

    const body = {};
    const result = await checkConfiguration(body);

    expect(axios.get).toHaveBeenCalledWith(
      `${AUTH_BASE_URI}/configuration`,
      body,
    );
    expect(result).toEqual(mockResponse);

    expect(addToast).not.toHaveBeenCalled();
  });

  test("checkConfiguration rejects on error", async () => {
    const error = { parsedMsg: "server error" };
    axios.get.mockRejectedValue(error);

    await expect(checkConfiguration({})).rejects.toEqual(error);
  });
});
