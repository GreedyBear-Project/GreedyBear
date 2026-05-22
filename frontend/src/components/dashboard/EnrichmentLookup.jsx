import React from "react";
import {
  Button,
  Col,
  Label,
  FormGroup,
  Row,
  Input,
  Alert,
  Card,
  CardBody,
} from "reactstrap";
import { MdSearch } from "react-icons/md";
import { Form, Formik } from "formik";
import axios from "axios";

import { addToast, BooleanIcon } from "@greedybear/gb-ui";
import { ENRICHMENT_URI } from "../../constants/api";
import { useAuthStore } from "../../stores";
import { AUTHENTICATION_STATUSES } from "../../constants";

const initialValues = {
  query: "",
};

// Very simple, human-readable checks:
// - only allow characters that make sense for IPs/domains
// - and make sure the value at least "looks like" an IP or a domain.
// The backend still performs strict validation.
const validCharRegex = /^[a-zA-Z0-9.:_-]+$/;

const looksLikeIp = (value) => {
  // digits, dots and/or colons, and at least one dot or colon
  if (!/^[0-9.:]+$/.test(value)) return false;
  return /[.:]/.test(value);
};

const looksLikeDomain = (value) => {
  // letters/digits/dot/hyphen/underscore, at least one dot, and no leading/trailing dot or hyphen
  if (!/^[a-zA-Z0-9._-]+$/.test(value)) return false;
  if (!value.includes(".")) return false;
  if (/^[-.]/.test(value) || /[-.]$/.test(value)) return false;
  return true;
};

const isValidQuery = (value) => {
  const q = value.trim();
  if (!q) return false;
  if (!validCharRegex.test(q)) return false;
  return looksLikeIp(q) || looksLikeDomain(q);
};

export default function EnrichmentLookup() {
  const [result, setResult] = React.useState(null);

  const [error, setError] = React.useState(null);

  // auth store
  const isAuthenticated = useAuthStore(
    React.useCallback((s) => s.isAuthenticated, []),
  );
  const isAuth = isAuthenticated === AUTHENTICATION_STATUSES.TRUE;

  const onSubmit = React.useCallback(
    async (values, { setSubmitting }) => {
      setError(null);
      setResult(null);

      // Check authentication first
      if (isAuthenticated !== AUTHENTICATION_STATUSES.TRUE) {
        setError(
          "You must be authenticated to use the enrichment feature. Please login to access this functionality.",
        );
        setSubmitting(false);
        return;
      }

      if (!values.query || values.query.trim() === "") {
        setError("Please enter an IP address or domain to search.");
        setSubmitting(false);
        return;
      }

      if (!isValidQuery(values.query)) {
        setError(
          "Please enter a value that looks like an IP or domain (e.g., 192.168.1.1 or example.com).",
        );
        setSubmitting(false);
        return;
      }

      try {
        const resp = await axios.get(ENRICHMENT_URI, {
          params: { query: values.query.trim() },
          headers: { "Content-Type": "application/json" },
        });

        setResult(resp.data);
        if (resp.data.found) {
          addToast("Success!", "IOC data found", "success");
        } else {
          addToast("Not found", "No data found for this observable", "info");
        }
      } catch (err) {
        console.error("Enrichment error:", err);
        const errorMsg =
          err.response?.data?.non_field_errors?.[0] ||
          err.response?.data?.detail ||
          err.parsedMsg ||
          "An error occurred while fetching enrichment data.";
        setError(errorMsg);
        addToast("Error", errorMsg, "danger");
      } finally {
        setSubmitting(false);
      }
    },
    [isAuthenticated],
  );

  return (
    <div className="enrichment-lookup p-3">
      <Formik initialValues={initialValues} onSubmit={onSubmit}>
        {(formik) => (
          <Form>
            <FormGroup row className="align-items-end mx-1">
              <Col sm={12} md={9}>
                <Label
                  className="form-control-label"
                  htmlFor="EnrichmentLookup__query"
                >
                  IP Address or Domain:
                </Label>
                <Input
                  id="EnrichmentLookup__query"
                  name="query"
                  type="text"
                  placeholder={
                    isAuth
                      ? "e.g., 192.168.1.1 or example.com"
                      : "You need to be logged in to search!"
                  }
                  value={formik.values.query}
                  onChange={formik.handleChange}
                  disabled={!isAuth || formik.isSubmitting}
                />
              </Col>
              <Col sm={12} md={3} className="mt-2 mt-md-0">
                <Button
                  type="submit"
                  color="primary"
                  disabled={!isAuth || formik.isSubmitting}
                  block
                >
                  <MdSearch />
                  &nbsp;
                  {formik.isSubmitting ? "Searching..." : "Search"}
                </Button>
              </Col>
            </FormGroup>
          </Form>
        )}
      </Formik>

      {error && (
        <Alert color="danger" className="mt-3">
          {error}
        </Alert>
      )}

      {result && !result.found && (
        <Alert color="info" className="mt-3">
          <strong>Not Found:</strong> No data available for "{result.query}" in
          our database.
        </Alert>
      )}

      {result && result.found && result.ioc && (
        <Card className="mt-4">
          <CardBody>
            <h6 className="mb-3">IOC Details for: {result.query}</h6>
            <Row>
              <Col md={6}>
                <dl className="row mb-0">
                  <dt className="col-sm-5">Name:</dt>
                  <dd className="col-sm-7">{result.ioc.name}</dd>

                  <dt className="col-sm-5">Type:</dt>
                  <dd className="col-sm-7">
                    <span className="badge bg-info">{result.ioc.type}</span>
                  </dd>

                  <dt className="col-sm-5">Attack Count:</dt>
                  <dd className="col-sm-7">{result.ioc.attack_count}</dd>

                  <dt className="col-sm-5">Interaction Count:</dt>
                  <dd className="col-sm-7">{result.ioc.interaction_count}</dd>

                  <dt className="col-sm-5">Login Attempts:</dt>
                  <dd className="col-sm-7">{result.ioc.login_attempts}</dd>

                  <dt className="col-sm-5">First Seen:</dt>
                  <dd className="col-sm-7">
                    {result.ioc.first_seen
                      ? new Date(result.ioc.first_seen).toLocaleString(
                          "en-US",
                          { timeZone: "UTC" },
                        )
                      : "N/A"}
                  </dd>

                  <dt className="col-sm-5">Last Seen:</dt>
                  <dd className="col-sm-7">
                    {result.ioc.last_seen
                      ? new Date(result.ioc.last_seen).toLocaleString("en-US", {
                          timeZone: "UTC",
                        })
                      : "N/A"}
                  </dd>
                </dl>
              </Col>

              <Col md={6}>
                <dl className="row mb-0">
                  <dt className="col-sm-5">Scanner:</dt>
                  <dd className="col-sm-7">
                    <BooleanIcon truthy={result.ioc.scanner} withColors />
                  </dd>

                  <dt className="col-sm-5">Payload Request:</dt>
                  <dd className="col-sm-7">
                    <BooleanIcon
                      truthy={result.ioc.payload_request}
                      withColors
                    />
                  </dd>

                  <dt className="col-sm-5">IP Reputation:</dt>
                  <dd className="col-sm-7">
                    {result.ioc.ip_reputation || "N/A"}
                  </dd>

                  <dt className="col-sm-5">ASN:</dt>
                  <dd className="col-sm-7">{result.ioc.asn || "N/A"}</dd>

                  <dt className="col-sm-5">Destination Ports:</dt>
                  <dd className="col-sm-7">
                    {result.ioc.destination_ports?.length > 0
                      ? result.ioc.destination_ports.join(", ")
                      : "N/A"}
                  </dd>

                  {Array.isArray(result.ioc.firehol_categories) &&
                    result.ioc.firehol_categories.length > 0 && (
                      <>
                        <dt className="col-sm-5">Firehol Categories:</dt>
                        <dd className="col-sm-7">
                          {result.ioc.firehol_categories.map(
                            (category, idx) => (
                              <span
                                key={idx}
                                className="badge bg-secondary me-1"
                              >
                                {category}
                              </span>
                            ),
                          )}
                        </dd>
                      </>
                    )}
                </dl>
              </Col>
            </Row>

            {result.ioc.general_honeypot &&
              result.ioc.general_honeypot.length > 0 && (
                <Row className="mt-3">
                  <Col>
                    <strong>Honeypots:</strong>
                    <div className="mt-2">
                      {result.ioc.general_honeypot.map((hp, idx) => (
                        <span key={idx} className="badge bg-primary me-2">
                          {hp}
                        </span>
                      ))}
                    </div>
                  </Col>
                </Row>
              )}
            {result.ioc.sensors && result.ioc.sensors.length > 0 && (
              <Row className="mt-3">
                <Col>
                  <strong>Sensors:</strong>
                  <div className="mt-2 text-primary font-monospace small">
                    {result.ioc.sensors.map((sensor, idx) => (
                      <div key={idx} className="mb-1">
                        {sensor.address}
                        {sensor.label && (
                          <span className="text-muted italic ml-1">
                            &nbsp;({sensor.label})
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </Col>
              </Row>
            )}

            {result.ioc.recurrence_probability !== undefined && (
              <Row className="mt-3">
                <Col md={6}>
                  <dt>Recurrence Probability:</dt>
                  <dd>
                    {result.ioc.recurrence_probability == null
                      ? "N/A"
                      : `${(result.ioc.recurrence_probability * 100).toFixed(
                          2,
                        )}%`}
                  </dd>
                </Col>
                {result.ioc.expected_interactions !== undefined && (
                  <Col md={6}>
                    <dt>Expected Interactions:</dt>
                    <dd>
                      {result.ioc.expected_interactions == null
                        ? "N/A"
                        : Number(result.ioc.expected_interactions).toFixed(2)}
                    </dd>
                  </Col>
                )}
              </Row>
            )}
          </CardBody>
        </Card>
      )}
    </div>
  );
}
