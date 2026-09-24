import React from "react";
import { Spinner } from "reactstrap";

export default function FallBackLoading({ text = "Loading...", ...rest }) {
  return (
    <div className="vertical-center" {...rest}>
      <div className="container text-center">
        <Spinner type="ripple" className="spinner-border-lg" />
        <h4 className="mt-4">{text}</h4>
      </div>
    </div>
  );
}
