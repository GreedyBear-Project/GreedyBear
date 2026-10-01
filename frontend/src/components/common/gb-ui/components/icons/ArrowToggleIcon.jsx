import React from "react";

import { MdExpandLess, MdExpandMore } from "react-icons/md";
import classNames from "classnames";

function ArrowToggleIcon({ isExpanded, className = null, ...rest }) {
  const cls = classNames("pointer bg-tertiary rounded-pill", className);

  return isExpanded ? (
    <MdExpandLess size="20px" className={cls} {...rest} />
  ) : (
    <MdExpandMore size="20px" className={cls} {...rest} />
  );
}

export default ArrowToggleIcon;
