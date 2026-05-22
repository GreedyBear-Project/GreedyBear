import React from "react";
import PropTypes from "prop-types";
import { Navigate, useLocation } from "react-router-dom";

import { FallBackLoading, addToast } from "@greedybear/gb-ui";

import { useAuthStore } from "../stores";
import { AUTHENTICATION_STATUSES } from "../constants";

/*
Wrapper for Routes which should be accessible only to a authenticated user
*/
export default function AuthGuard({ children }) {
  // store
  const isAuthenticated = useAuthStore(
    React.useCallback((s) => s.isAuthenticated, []),
  );

  const location = useLocation();
  const didJustLogout = location?.pathname.includes("logout");

  // side effects
  React.useEffect(() => {
    if (!didJustLogout && isAuthenticated === AUTHENTICATION_STATUSES.FALSE) {
      addToast("Login required to access the requested page.", null, "info");
    }
  }, [didJustLogout, isAuthenticated]);

  if (isAuthenticated === AUTHENTICATION_STATUSES.PENDING) {
    return <FallBackLoading />;
  }

  if (isAuthenticated === AUTHENTICATION_STATUSES.FALSE) {
    return (
      <Navigate
        to={{
          pathname: didJustLogout ? "/" : "/login",
          search: didJustLogout ? undefined : `?next=${location.pathname}`,
        }}
      />
    );
  }

  return children;
}

AuthGuard.propTypes = {
  children: PropTypes.node.isRequired,
};
