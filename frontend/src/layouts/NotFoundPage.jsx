import React from "react";
import { Link } from "react-router-dom";
import { ButtonGroup, Container, Button } from "reactstrap";
import { useLocation } from "react-router";

function NotFoundPage() {
  const location = useLocation();
  return (
    <Container
      className="d-flex flex-column align-items-center justify-content-center text-center"
      style={{ minHeight: "80vh" }}
    >
      <h1 className="display-1 text-danger font-weight-bold">404</h1>
      <h2 className="mb-3">Page Not Found</h2>

      <p className="text-muted mb-4">
        The requested path{" "}
        <code className="text-white font-weight-bold fs-5">
          {location.pathname}
        </code>{" "}
        does not exist or has been moved.
      </p>

      <div className="mb-4">
        <p className="text-light font-weight-bold">Return to</p>

        <ButtonGroup>
          <Button tag={Link} to="/" color="primary" outline>
            {" "}
            Home{" "}
          </Button>
          <Button tag={Link} to="/feeds" color="primary" outline>
            {" "}
            Feeds{" "}
          </Button>
          <Button tag={Link} to="/dashboard" color="primary" outline>
            {" "}
            Dashboard{" "}
          </Button>
        </ButtonGroup>
      </div>
    </Container>
  );
}

export default NotFoundPage;
