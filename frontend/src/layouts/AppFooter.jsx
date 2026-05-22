import React from "react";
import { Row, Col, Container } from "reactstrap";
import { FaXTwitter, FaGithub, FaLinkedin } from "react-icons/fa6";

import { ScrollToTopButton, Toaster, useToastr } from "@greedybear/gb-ui";

import { VERSION } from "../constants/environment";

// constants
const selector = (state) => state.toasts;

function AppFooter() {
  console.debug("AppFooter rendered!");

  // consume store
  const toasts = useToastr(selector);

  return (
    <footer>
      <div className="d-flex flex-column">
        {/* Toasts */}
        <section className="fixed-bottom" id="app-toasts">
          {toasts.map((tProps) => (
            <Toaster key={tProps.id} {...tProps} />
          ))}
        </section>
        {/* Footer */}
        <Container fluid className="border-top mt-2 py-3">
          <Row className="align-items-center">
            <Col md={12} className="text-center">
              <span className="text-white px-2 py-1 rounded">
                Follow us on:
              </span>
              <a
                href="https://github.com/GreedyBear-Project"
                target="_blank"
                rel="noopener noreferrer"
                className="ms-3 text-white text-decoration-none"
                aria-label="GreedyBear on GitHub"
              >
                <FaGithub size={20} />
              </a>
            </Col>
          </Row>
          <Row className="mt-2">
            <Col className="text-center">
              <small className="text-muted">{VERSION}</small>
            </Col>
          </Row>
        </Container>
        {/* Scroll to top button */}
        <ScrollToTopButton />
      </div>
    </footer>
  );
}

export default AppFooter;
