import React, { Suspense } from "react";
import { FallBackLoading } from "@greedybear/gb-ui";

import IfAuthRedirectGuard from "../wrappers/ifAuthRedirectGuard";
import AuthGuard from "../wrappers/AuthGuard";
import ErrorBoundary from "../wrappers/ErrorBoundary";

const Home = React.lazy(() => import("./home/Home"));
const Login = React.lazy(() => import("./auth/Login"));
const Logout = React.lazy(() => import("./auth/Logout"));
const Register = React.lazy(() => import("./auth/Register"));
const EmailVerification = React.lazy(() => import("./auth/EmailVerification"));
const ResetPassword = React.lazy(() => import("./auth/ResetPassword"));
const Dashboard = React.lazy(() => import("./dashboard/Dashboard"));
const Sessions = React.lazy(() => import("./me/sessions/Sessions"));
const Feeds = React.lazy(() => import("./feeds/Feeds"));
const ChangePassword = React.lazy(
  () => import("./me/changepassword/ChangePassword"),
);

// public components
const publicRoutesLazy = [
  /* Home */
  {
    index: true,
    element: <Home />,
    withErrorBoundary: true,
  },
  /* Dashboard */
  {
    path: "/dashboard",
    element: <Dashboard />,
    withErrorBoundary: true,
  },
  /* Feeds */
  {
    path: "/feeds",
    element: <Feeds />,
    withErrorBoundary: true,
  },
].map((r) => ({
  ...r,
  element: (
    <ConditionalWrapper
      condition={r.withErrorBoundary}
      wrapper={(children) => <ErrorBoundary>{children}</ErrorBoundary>}
    >
      <Suspense fallback={<FallBackLoading />}>{r.element}</Suspense>
    </ConditionalWrapper>
  ),
}));

// no auth public components
const noAuthRoutesLazy = [
  {
    path: "/login",
    element: <Login />,
    withErrorBoundary: true,
  },
  {
    path: "/register",
    element: <Register />,
    withErrorBoundary: true,
  },
  {
    path: "/verify-email",
    element: <EmailVerification />,
    withErrorBoundary: true,
  },
  {
    path: "/reset-password",
    element: <ResetPassword />,
    withErrorBoundary: true,
  },
].map((r) => ({
  ...r,
  element: (
    <IfAuthRedirectGuard>
      <ConditionalWrapper
        condition={r.withErrorBoundary}
        wrapper={(children) => <ErrorBoundary>{children}</ErrorBoundary>}
      >
        <Suspense fallback={<FallBackLoading />}>{r.element}</Suspense>
      </ConditionalWrapper>
    </IfAuthRedirectGuard>
  ),
}));

// auth components
const authRoutesLazy = [
  /* auth */
  {
    path: "/logout",
    element: <Logout />,
    withErrorBoundary: true,
  },
  /* API Access/Sessions Management */
  {
    path: "/me/sessions",
    element: <Sessions />,
    withErrorBoundary: true,
  },
  /* Change Password */
  {
    path: "/me/change-password",
    element: <ChangePassword />,
    withErrorBoundary: true,
  },
].map((r) => ({
  ...r,
  element: (
    <AuthGuard>
      <ConditionalWrapper
        condition={r.withErrorBoundary}
        wrapper={(children) => <ErrorBoundary>{children}</ErrorBoundary>}
      >
        <Suspense fallback={<FallBackLoading />}>{r.element}</Suspense>
      </ConditionalWrapper>
    </AuthGuard>
  ),
}));

function ConditionalWrapper({ condition, wrapper, children }) {
  return condition ? wrapper(children) : children;
}

export { publicRoutesLazy, noAuthRoutesLazy, authRoutesLazy };
