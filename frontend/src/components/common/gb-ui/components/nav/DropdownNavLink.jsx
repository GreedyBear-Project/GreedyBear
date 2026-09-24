import React from "react";
import { NavLink as RRNavLink } from "react-router-dom";

/**
 * @type {component}
 * @param props
 */
export default function DropdownNavLink(props) {
  const { children, ...toPassProps } = props;

  return (
    <RRNavLink
      className={({ isActive }) => `dropdown-item${isActive ? " active" : ""}`}
      {...toPassProps}
    >
      {children}
    </RRNavLink>
  );
}
