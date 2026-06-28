import React from "react";
import PropTypes from "prop-types";

import { useAuthStore } from "../stores";

/**
 * SuperuserGuard
 *
 * Renders children only for superusers. Non-superusers see a 403-style
 * message in place of the protected content. The user is NOT redirected
 * the route is simply not shown in navigation for regular users, so reaching
 * it is already unusual.
 */
export default function SuperuserGuard({ children }) {
  const isSuperuser = useAuthStore(
    React.useCallback((s) => s.isSuperuser, []),
  );

  if (!isSuperuser) {
    return (
      <div
        className="d-flex flex-column align-items-center justify-content-center py-5 text-muted"
        style={{ minHeight: 300 }}
      >
        <span style={{ fontSize: "3rem" }}>🔒</span>
        <h4 className="mt-3 fw-bold">Access Restricted</h4>
        <p className="small">This page is only available to superusers.</p>
      </div>
    );
  }

  return children;
}

SuperuserGuard.propTypes = {
  children: PropTypes.node.isRequired,
};
