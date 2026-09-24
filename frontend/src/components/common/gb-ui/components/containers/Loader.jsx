import React from "react";
import { Spinner } from "reactstrap";

import ErrorAlert from "../alerts/ErrorAlert";

function Loader({
  loading,
  error = null,
  render,
  renderError = ErrorAlert,
  size = "md",
}) {
  return (
    <>
      {loading && (
        <Spinner
          type="ripple"
          className={`d-block mx-auto my-5 spinner-border-${size}`}
        />
      )}
      {error && renderError({ error, size })}
      {!(loading || error) && render()}
    </>
  );
}

export default Loader;
