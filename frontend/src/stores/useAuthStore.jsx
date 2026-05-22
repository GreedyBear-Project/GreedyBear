import axios from "axios";
import { create } from "zustand";

import { addToast } from "@greedybear/gb-ui";

import {
  USERACCESS_URI,
  CHECK_AUTHENTICATION_URI,
  LOGIN_URI,
  LOGOUT_URI,
  CHANGE_PASSWORD_URI,
} from "../constants/api";
import { AUTHENTICATION_STATUSES } from "../constants";

const INITIAL_USER = {
  full_name: "",
  first_name: "",
  last_name: "",
  email: "",
};

// hook/ store see: https://github.com/pmndrs/zustand
const useAuthStore = create((set, get) => ({
  user: INITIAL_USER,
  isSuperuser: false,
  isAuthenticated: AUTHENTICATION_STATUSES.FALSE,
  reset: () => {
    set({
      isAuthenticated: AUTHENTICATION_STATUSES.FALSE,
      user: INITIAL_USER,
      isSuperuser: false,
    });
  },
  checkAuthentication: async () => {
    try {
      const resp = await axios.get(CHECK_AUTHENTICATION_URI, {
        headers: { "Content-Type": "application/json" },
      });
      if (get().isSuperuser !== resp.data.is_superuser) {
        set({
          isSuperuser: resp.data.is_superuser,
        });
      }
      if (get().isAuthenticated === AUTHENTICATION_STATUSES.FALSE) {
        set({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE });
      }
    } catch (err) {
      if (get().isAuthenticated !== AUTHENTICATION_STATUSES.FALSE) {
        get().reset();
      }
    }
  },
  service: {
    fetchUserAccess: async () => {
      try {
        const resp = await axios.get(USERACCESS_URI, {
          certegoUIenableProgressBar: false,
          headers: { "Content-Type": "application/json" },
        });
        set({
          user: resp.data.user,
        });
      } catch (err) {
        addToast(
          "Error fetching user access information!",
          err.parsedMsg,
          "danger",
        );
      }
    },
    loginUser: async (body) => {
      try {
        set({ isAuthenticated: AUTHENTICATION_STATUSES.PENDING });
        const resp = await axios.post(LOGIN_URI, body, {
          certegoUIenableProgressBar: false,
          headers: { "Content-Type": "application/json" },
        });
        set({ isAuthenticated: AUTHENTICATION_STATUSES.TRUE });
        addToast("You've been logged in!", null, "success");
        return Promise.resolve(resp);
      } catch (err) {
        set({ isAuthenticated: AUTHENTICATION_STATUSES.FALSE });
        addToast("Login failed!", err.parsedMsg, "danger", true);
        return Promise.reject(err);
      }
    },
    logoutUser: async () => {
      set({ isAuthenticated: AUTHENTICATION_STATUSES.PENDING });
      const onLogoutSuccessCb = () => {
        get().reset();
        addToast("Logged out!", null, "info");
      };
      const onLogoutErrorCb = (err) => {
        get().reset();
        addToast(
          "Logout request failed. Local session cleared.",
          err.parsedMsg,
          "warning",
          true,
        );
        return Promise.reject(err);
      };
      return axios
        .post(LOGOUT_URI, null, {
          certegoUIenableProgressBar: false,
        })
        .then(onLogoutSuccessCb)
        .catch(onLogoutErrorCb);
    },
    changePassword: async (body) => {
      try {
        const resp = await axios.post(CHANGE_PASSWORD_URI, body, {
          headers: { "Content-Type": "application/json" },
          certegoUIenableProgressBar: false,
        });
        addToast("Password changed successfully!", null, "success");
        return Promise.resolve(resp);
      } catch (err) {
        addToast("Failed to change password!", err.parsedMsg, "danger", true);
        return Promise.reject(err);
      }
    },
  },
}));

export default useAuthStore;
