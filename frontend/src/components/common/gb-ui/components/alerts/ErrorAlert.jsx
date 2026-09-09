import React from "react";
import classnames from "classnames";
import { Alert, Col } from "reactstrap";
import { MdError } from "react-icons/md";

const sizeToWidth = {
  sm: 4,
  md: 8,
  lg: 10,
  xl: 12,
};

function ErrorAlert({ error, size = "md", className = undefined, ...rest }) {
  return (
    <Alert
      tag={Col}
      md={sizeToWidth[size]}
      color="danger"
      className={classnames("mx-auto m-3", className)}
      {...rest}
    >
      <h4>
        <MdError />
        &nbsp; Error!
      </h4>
      <hr />
      <h5>
        {[error?.response?.status, error?.response?.statusText]
          .filter(Boolean)
          .join(" | ")}
      </h5>
      <div className="p-2 border border-darker">
        <code className="text-light">{error?.parsedMsg?.toString()}</code>
      </div>
    </Alert>
  );
}

export default ErrorAlert;
