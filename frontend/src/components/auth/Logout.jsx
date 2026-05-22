import React from "react";
import { useShallow } from "zustand/shallow";

import { FallBackLoading } from "@greedybear/gb-ui";

import { useAuthStore } from "../../stores";
import { AUTHENTICATION_STATUSES } from "../../constants";

export default function Logout() {
  // auth store
  const [isAuthenticated, logoutUser] = useAuthStore(
    useShallow((s) => [s.isAuthenticated, s.service.logoutUser]),
  );

  React.useEffect(() => {
    if (isAuthenticated === AUTHENTICATION_STATUSES.TRUE) {
      void logoutUser().catch(() => {});
    }
  }, [isAuthenticated, logoutUser]);

  return <FallBackLoading text="Logging you out..." />;
}
