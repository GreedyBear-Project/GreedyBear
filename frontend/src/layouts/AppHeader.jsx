import React from "react";
import {
  Nav,
  Navbar,
  NavItem,
  Collapse,
  NavbarBrand,
  NavbarToggler,
} from "reactstrap";
import { NavLink as RRNavLink } from "react-router-dom";
import { MdHome, MdOutlineFeed, MdDashboard } from "react-icons/md";
import { RiBookReadFill } from "react-icons/ri";

// lib
import { NavLink } from "@greedybear/gb-ui";

// constants
import { GREEDYBEAR_DOCS_URL } from "../constants/environment";

// local
import UserMenu from "./widget/UserMenu";
import { useAuthStore } from "../stores";
import { AUTHENTICATION_STATUSES } from "../constants";

const guestLinks = (
  <>
    <NavItem>
      <RRNavLink id="login-btn" className="btn btn-sm btn-info" end to="/login">
        Login
      </RRNavLink>
    </NavItem>
    {/*  The register button has been temporarily disabled due to not proper Terms of Service */}
    {/* <NavItem className="ms-lg-2">
      <RRNavLink
        id="register-btn"
        className="btn btn-sm btn-accent-2"
        end
        to="/register"
      >
        Register
      </RRNavLink>
    </NavItem> */}
  </>
);

const rightLinks = (
  <NavItem>
    <a
      className="d-flex-start-center btn text-gray"
      href={GREEDYBEAR_DOCS_URL}
      target="_blank"
      rel="noopener noreferrer"
    >
      <RiBookReadFill />
      <span className="ms-1">Docs</span>
    </a>
  </NavItem>
);

function AppHeader() {
  console.debug("AppHeader rendered!");

  // local state
  const [isOpen, setIsOpen] = React.useState(false);

  // auth store
  const isAuthenticated = useAuthStore(
    React.useCallback((s) => s.isAuthenticated, []),
  );

  return (
    <header className="fixed-top">
      {/* nav bar */}
      <Navbar dark expand="lg">
        <NavbarBrand tag={RRNavLink} to="/">
          GreedyBear
        </NavbarBrand>
        <NavbarToggler onClick={() => setIsOpen(!isOpen)} />
        <Collapse navbar isOpen={isOpen}>
          {/* Navbar Left Side */}
          <Nav navbar className="ms-1 d-flex align-items-center">
            <NavItem>
              <NavLink className="d-flex-start-center" end to="/">
                <MdHome />
                <span className="ms-1">Home</span>
              </NavLink>
            </NavItem>
            <NavItem>
              <NavLink className="d-flex-start-center" end to="/dashboard">
                <MdDashboard />
                <span className="ms-1">Dashboard</span>
              </NavLink>
            </NavItem>
            <NavItem>
              <NavLink className="d-flex-start-center" end to="/feeds">
                <MdOutlineFeed />
                <span className="ms-1">Feeds</span>
              </NavLink>
            </NavItem>
          </Nav>
          {/* Navbar Right Side */}
          <Nav navbar className="ms-auto d-flex align-items-center">
            {rightLinks}
            {isAuthenticated === AUTHENTICATION_STATUSES.FALSE ? (
              guestLinks
            ) : (
              <UserMenu />
            )}
          </Nav>
        </Collapse>
      </Navbar>
    </header>
  );
}

export default AppHeader;
