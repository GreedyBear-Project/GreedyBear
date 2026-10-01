import React from "react";
import classnames from "classnames";

function ContentSection({ className = null, children, ...rest }) {
  return (
    <div className={classnames("content-section bg-dark", className)} {...rest}>
      {children}
    </div>
  );
}

export default ContentSection;
