import { describe, test, expect, vi, beforeEach } from "vitest";
import axios from "axios";
import useAuthStore from "../../src/stores/useAuthStore";
import { AUTHENTICATION_STATUSES } from "../../src/constants";
import {
  CHECK_AUTHENTICATION_URI,
  CHANGE_PASSWORD_URI,
  LOGIN_URI,
  LOGOUT_URI,
  USERACCESS_URI,
} from "../../src/constants/api";
import { addToast } from "@greedybear/gb-ui";

vi.mock("axios");
vi.mock("@greedybear/gb-ui", () => ({
  addToast: vi.fn(),
}));

const INITIAL_USER = {
  full_name: "",
  first_name: "",
  last_name: "",
  email: "",
};

const createDeferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
};

describe("useAuthStore", () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: INITIAL_USER,
      isSuperuser: false,
      isAuthenticated: AUTHENTICATION_STATUSES.FALSE,
    });

    vi.clearAllMocks();
  });

  describe("Initial State", () => {
    test("initial state is correct", () => {
      const state = useAuthStore.getState();

      expect(state.user).toEqual(INITIAL_USER);

      expect(state.isSuperuser).toBe(false);

      expect(state.isAuthenticated).toBe(AUTHENTICATION_STATUSES.FALSE);
    });
  });

  describe("loginUser", () => {
    test("sets authentication PENDING while request is in flight", async () => {
      const deferred = createDeferred();
      axios.post.mockReturnValue(deferred.promise);

      const { loginUser } = useAuthStore.getState().service;
      const loginPromise = loginUser({ username: "test", password: "123" });

      expect(useAuthStore.getState().isAuthenticated).toBe(
        AUTHENTICATION_STATUSES.PENDING,
      );

      deferred.resolve({ data: {} });
      await expect(loginPromise).resolves.toEqual({ data: {} });
    });

    test("sets authentication FALSE and emits error toast on failure", async () => {
      const err = { parsedMsg: "bad credentials" };
      axios.post.mockRejectedValue(err);

      const { loginUser } = useAuthStore.getState().service;

      await expect(
        loginUser({ username: "test", password: "123" }),
      ).rejects.toEqual(err);

      expect(useAuthStore.getState().isAuthenticated).toBe(
        AUTHENTICATION_STATUSES.FALSE,
      );

      expect(addToast).toHaveBeenCalledWith(
        "Login failed!",
        "bad credentials",
        "danger",
        true,
      );
    });

    test("sets authentication TRUE and emits success toast on success", async () => {
      axios.post.mockResolvedValue({ data: {} });

      const { loginUser } = useAuthStore.getState().service;

      await loginUser({ username: "test", password: "123" });

      expect(axios.post).toHaveBeenCalledWith(
        LOGIN_URI,
        { username: "test", password: "123" },
        {
          certegoUIenableProgressBar: false,
          headers: { "Content-Type": "application/json" },
        },
      );

      expect(useAuthStore.getState().isAuthenticated).toBe(
        AUTHENTICATION_STATUSES.TRUE,
      );

      expect(addToast).toHaveBeenCalledWith(
        "You've been logged in!",
        null,
        "success",
      );
    });
  });

  describe("logoutUser", () => {
    test("sets authentication PENDING while logout request is in flight", async () => {
      const deferred = createDeferred();
      axios.post.mockReturnValue(deferred.promise);

      const { logoutUser } = useAuthStore.getState().service;
      const logoutPromise = logoutUser();

      expect(useAuthStore.getState().isAuthenticated).toBe(
        AUTHENTICATION_STATUSES.PENDING,
      );

      deferred.resolve({});
      await logoutPromise;
    });

    test("clears user and auth state with info toast on success", async () => {
      axios.post.mockResolvedValue({});

      useAuthStore.setState({
        isAuthenticated: AUTHENTICATION_STATUSES.TRUE,
        user: {
          full_name: "Test",
          first_name: "Test",
          last_name: "User",
          email: "test@test.com",
        },
        isSuperuser: true,
      });

      const { logoutUser } = useAuthStore.getState().service;

      await logoutUser();

      const state = useAuthStore.getState();

      expect(state.isAuthenticated).toBe(AUTHENTICATION_STATUSES.FALSE);

      expect(state.isSuperuser).toBe(false);

      expect(state.user).toEqual(INITIAL_USER);

      expect(axios.post).toHaveBeenCalledWith(LOGOUT_URI, null, {
        certegoUIenableProgressBar: false,
      });

      expect(addToast).toHaveBeenCalledWith("Logged out!", null, "info");
    });

    test("clears local state, emits warning toast, and rejects on failure", async () => {
      const err = { parsedMsg: "network" };
      axios.post.mockRejectedValue(err);

      useAuthStore.setState({
        isAuthenticated: AUTHENTICATION_STATUSES.TRUE,
        user: {
          full_name: "Test",
          first_name: "Test",
          last_name: "User",
          email: "test@test.com",
        },
        isSuperuser: true,
      });

      const { logoutUser } = useAuthStore.getState().service;

      await expect(logoutUser()).rejects.toEqual(err);

      const state = useAuthStore.getState();
      expect(state.isAuthenticated).toBe(AUTHENTICATION_STATUSES.FALSE);
      expect(state.isSuperuser).toBe(false);
      expect(state.user).toEqual(INITIAL_USER);
      expect(addToast).toHaveBeenCalledWith(
        "Logout request failed. Local session cleared.",
        "network",
        "warning",
        true,
      );
    });
  });

  describe("fetchUserAccess", () => {
    test("stores user data", async () => {
      axios.get.mockResolvedValue({
        data: {
          user: {
            full_name: "user1",
            first_name: "user",
            last_name: "1",
            email: "user1@test.com",
          },
        },
      });

      const { fetchUserAccess } = useAuthStore.getState().service;

      await fetchUserAccess();

      expect(axios.get).toHaveBeenCalledWith(USERACCESS_URI, {
        certegoUIenableProgressBar: false,
        headers: { "Content-Type": "application/json" },
      });

      expect(useAuthStore.getState().user.email).toBe("user1@test.com");
    });

    test("emits error toast when user access fetch fails", async () => {
      const err = { parsedMsg: "access fetch failed" };
      axios.get.mockRejectedValue(err);

      const { fetchUserAccess } = useAuthStore.getState().service;

      await fetchUserAccess();

      expect(addToast).toHaveBeenCalledWith(
        "Error fetching user access information!",
        "access fetch failed",
        "danger",
      );
      expect(useAuthStore.getState().user).toEqual(INITIAL_USER);
    });
  });

  describe("reset", () => {
    test("clears user, isSuperuser and sets isAuthenticated to FALSE", () => {
      useAuthStore.setState({
        isAuthenticated: AUTHENTICATION_STATUSES.TRUE,
        user: { email: "test@test.com" },
        isSuperuser: true,
      });

      useAuthStore.getState().reset();

      const state = useAuthStore.getState();
      expect(state.isAuthenticated).toBe(AUTHENTICATION_STATUSES.FALSE);
      expect(state.isSuperuser).toBe(false);
      expect(state.user).toEqual(INITIAL_USER);
    });
  });

  describe("checkAuthentication", () => {
    test("sets auth TRUE and updates superuser", async () => {
      axios.get.mockResolvedValue({
        data: { is_superuser: true },
      });

      const { checkAuthentication } = useAuthStore.getState();

      await checkAuthentication();

      expect(useAuthStore.getState().isAuthenticated).toBe(
        AUTHENTICATION_STATUSES.TRUE,
      );

      expect(useAuthStore.getState().isSuperuser).toBe(true);
    });

    test("clears all auth data when auth check fails while currently authenticated", async () => {
      useAuthStore.setState({
        isAuthenticated: AUTHENTICATION_STATUSES.TRUE,
        user: { email: "test@test.com" },
        isSuperuser: true,
      });
      axios.get.mockRejectedValue(new Error("auth check failed"));

      const { checkAuthentication } = useAuthStore.getState();

      await checkAuthentication();

      expect(axios.get).toHaveBeenCalledWith(CHECK_AUTHENTICATION_URI, {
        headers: { "Content-Type": "application/json" },
      });
      const state = useAuthStore.getState();
      expect(state.isAuthenticated).toBe(AUTHENTICATION_STATUSES.FALSE);
      expect(state.isSuperuser).toBe(false);
      expect(state.user).toEqual(INITIAL_USER);
    });

    test("keeps auth FALSE when auth check fails while already unauthenticated", async () => {
      useAuthStore.setState({
        isAuthenticated: AUTHENTICATION_STATUSES.FALSE,
      });
      axios.get.mockRejectedValue(new Error("auth check failed"));

      const { checkAuthentication } = useAuthStore.getState();

      await checkAuthentication();

      expect(useAuthStore.getState().isAuthenticated).toBe(
        AUTHENTICATION_STATUSES.FALSE,
      );
    });
  });

  describe("changePassword", () => {
    test("resolves on success and emits success toast", async () => {
      const response = { data: {} };
      axios.post.mockResolvedValue(response);

      const { changePassword } = useAuthStore.getState().service;

      await expect(changePassword({ old: "a", new: "b" })).resolves.toEqual(
        response,
      );

      expect(axios.post).toHaveBeenCalledWith(
        CHANGE_PASSWORD_URI,
        { old: "a", new: "b" },
        {
          headers: { "Content-Type": "application/json" },
          certegoUIenableProgressBar: false,
        },
      );
      expect(addToast).toHaveBeenCalledWith(
        "Password changed successfully!",
        null,
        "success",
      );
    });

    test("rejects on failure and emits error toast", async () => {
      const err = { parsedMsg: "old password incorrect" };
      axios.post.mockRejectedValue(err);

      const { changePassword } = useAuthStore.getState().service;

      await expect(changePassword({ old: "a", new: "b" })).rejects.toEqual(err);

      expect(addToast).toHaveBeenCalledWith(
        "Failed to change password!",
        "old password incorrect",
        "danger",
        true,
      );
    });
  });
});
