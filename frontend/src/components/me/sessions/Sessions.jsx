import React from "react";
import { Alert, Container, Row } from "reactstrap";

import { ContentSection } from "@greedybear/gb-ui";

import SessionsList from "./SessionList";
import APIAccess from "./APIaccess";

export default function Sessions() {
  console.debug("Sessions rendered!");

  return (
    <Container>
      {/* Alert */}
      <Row className="my-4">
        <Alert color="secondary" className="mx-3 mx-md-auto text-center">
          <span>
            You can generate an API key to access GreedyBear&apos;s RESTful
            API.&nbsp;
          </span>
        </Alert>
      </Row>
      {/* API Access */}
      <h6>API Access</h6>
      <ContentSection className="bg-body border border-dark">
        <APIAccess />
      </ContentSection>
      {/* Sessions List */}
      <h6>Browser Sessions</h6>
      <ContentSection className="bg-body border border-dark">
        <SessionsList />
      </ContentSection>
    </Container>
  );
}
