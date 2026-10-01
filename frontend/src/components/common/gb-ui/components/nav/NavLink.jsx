import React from "react";
import classnames from "classnames";
import { NavLink as RRNavLink } from "react-router-dom";

// constants
const type2ClassnameMap = {
  default: "",
  primary: "link-primary",
  primaryUl: "link-ul-primary",
  muted: "link-muted",
  mutedUl: "link-ul-muted",
};

// component
export default function NavLink({
  type = "default",
  children,
  className = null,
  ...props
}) {
  return (
    <RRNavLink
      className={({ isActive }) =>
        classnames(
          "nav-link",
          "text-lg-center",
          type2ClassnameMap[type],
          className,
          { active: isActive },
        )
      }
      {...props}
    >
      {children}
    </RRNavLink>
  );
}
