import React from "react";
import { Spinner } from "reactstrap";

import ErrorAlert from "../alerts/ErrorAlert";

function LoadingBoundary({
  loading = false,
  error = null,
  size = "md",
  render,
  renderError = ErrorAlert,
}) {
  const hasError = Boolean(error?.response || error?.message);
  const RenderError = renderError;

  return (
    <>
      {loading && (
        <Spinner
          type="ripple"
          className={`d-block mx-auto my-5 spinner-border-${size}`}
        />
      )}
      {hasError && <RenderError error={error} size={size} />}
      {!loading && !hasError && render()}
    </>
  );
}

export default LoadingBoundary;
