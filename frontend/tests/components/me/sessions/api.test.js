import axios from "axios";
import { addToast } from "@greedybear/gb-ui";

import {
  createNewToken,
  deleteToken,
  deleteOtherSessions,
  deleteTokenById,
} from "../../../../src/components/me/sessions/api";
import {
  APIACCESS_BASE_URI,
  SESSIONS_BASE_URI,
} from "../../../../src/constants/api";

vi.mock("axios");
vi.mock("@greedybear/gb-ui", () => ({
  addToast: vi.fn(),
}));

describe("sessions api helpers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("createNewToken calls endpoint and shows success toast", async () => {
    axios.post.mockResolvedValue({ status: 201 });

    await createNewToken();

    expect(axios.post).toHaveBeenCalledWith(APIACCESS_BASE_URI);
    expect(addToast).toHaveBeenCalledWith(
      "Generated new API key for you!",
      null,
      "success",
      true,
    );
  });

  test("createNewToken rejects and shows failure toast", async () => {
    const error = { parsedMsg: "creation failed" };
    axios.post.mockRejectedValue(error);

    await expect(createNewToken()).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Failed!",
      "creation failed",
      "danger",
      true,
    );
  });

  test("deleteToken calls endpoint and shows success toast", async () => {
    axios.delete.mockResolvedValue({ status: 204 });

    await deleteToken();

    expect(axios.delete).toHaveBeenCalledWith(APIACCESS_BASE_URI);
    expect(addToast).toHaveBeenCalledWith(
      "API key was deleted!",
      null,
      "success",
      true,
    );
  });

  test("deleteToken rejects and shows failure toast", async () => {
    const error = { message: "deletion failed" };
    axios.delete.mockRejectedValue(error);

    await expect(deleteToken()).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Failed!",
      "deletion failed",
      "danger",
      true,
    );
  });

  test("deleteTokenById calls endpoint and shows success toast", async () => {
    axios.delete.mockResolvedValue({ status: 204 });

    await deleteTokenById(42, "Firefox");

    expect(axios.delete).toHaveBeenCalledWith(`${SESSIONS_BASE_URI}/42`);
    expect(addToast).toHaveBeenCalledWith(
      "Revoked Session (Firefox).",
      null,
      "success",
      true,
      6000,
    );
  });

  test("deleteTokenById rejects and shows failure toast", async () => {
    const error = { parsedMsg: "cannot revoke" };
    axios.delete.mockRejectedValue(error);

    await expect(deleteTokenById(9, "Safari")).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Failed!",
      "cannot revoke",
      "danger",
      true,
    );
  });

  test("deleteOtherSessions calls /others endpoint and shows success toast", async () => {
    axios.delete.mockResolvedValue({ status: 204 });

    await deleteOtherSessions();

    expect(axios.delete).toHaveBeenCalledWith(`${SESSIONS_BASE_URI}/others`);
    expect(addToast).toHaveBeenCalledWith(
      "Revoked all other sessions.",
      null,
      "success",
      true,
      6000,
    );
  });

  test("deleteOtherSessions rejects and shows failure toast", async () => {
    const error = { parsedMsg: "backend error" };
    axios.delete.mockRejectedValue(error);

    await expect(deleteOtherSessions()).rejects.toEqual(error);

    expect(addToast).toHaveBeenCalledWith(
      "Failed!",
      "backend error",
      "danger",
      true,
    );
  });
});
