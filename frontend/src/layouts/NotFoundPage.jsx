import React from "react";
import { Link } from "react-router-dom";
import { ButtonGroup, Container,Button } from "reactstrap";
import { useLocation } from 'react-router'


function NotFoundPage() {
  console.debug("NotFoundPage rendered!");
  const location = useLocation();
  console.log("The current location is",location);
  return (
    <Container 
      className="d-flex flex-column align-items-center justify-content-center text-center" 
      style={{ minHeight: '80vh' }}
    >
      <h1 className = "display-1 text-danger font-weight-bold">404</h1>
      <h2 className="mb-3">Page Not Found</h2>

      <p className="text-muted mb-4">
        The requested path <code className="text-light">{location.pathname}
        </code> does not exists or has been moved.
      </p>

      <div className="mb-4">
        <p mb-2 font-weight-bold text-secondary>
         Return to  
        </p>
    
        <ButtonGroup>
          <Button tag={Link} to="/" color="primary" outline> Home </Button>
          <Button tag={Link} to="/feeds" color="primary" outline> Feeds </Button>
          <Button tag={Link} to="/dashboard" color="primary" outline> Dashboard </Button>
        </ButtonGroup>

      </div>
    </Container>
  );
}

export default NotFoundPage;
