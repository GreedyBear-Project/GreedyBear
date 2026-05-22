import React from "react";
import { Container, Row, Col } from "reactstrap";

import {
  ElasticTimePicker,
  useTimePickerStore,
  SmallInfoCard,
} from "@greedybear/gb-ui";

import {
  FeedsSourcesChart,
  FeedsDownloadsChart,
  EnrichmentSourcesChart,
  EnrichmentRequestsChart,
  FeedsTypesChart,
  AttackOriginCountriesChart,
} from "./utils/charts";

import EnrichmentLookup from "./EnrichmentLookup";
import AttackOriginMap from "./AttackOriginMap";

const feedsChartList = [
  ["FeedsSourcesChart", "Feeds: Sources", FeedsSourcesChart],
  ["FeedsDownloadsChart", "Feeds: Downloads", FeedsDownloadsChart],
];

const feedsTypesChartList = [
  ["FeedsTypesChart", "Feeds: Types", FeedsTypesChart],
];

const enrichmentChartList = [
  [
    "EnrichmentSourcesChart",
    "Enrichment Service: Sources",
    EnrichmentSourcesChart,
  ],
  [
    "EnrichmentRequestsChart",
    "Enrichment Service: Requests",
    EnrichmentRequestsChart,
  ],
];

function Dashboard() {
  console.debug("Dashboard rendered!");
  const { range, onTimeIntervalChange } = useTimePickerStore();

  return (
    <Container fluid id="Dashboard">
      <div className="g-0 d-flex align-items-baseline flex-column flex-lg-row mb-2">
        <h3 className="fw-bold">Dashboard</h3>
        <ElasticTimePicker
          className="ms-auto"
          size="sm"
          defaultSelected={range}
          onChange={onTimeIntervalChange}
        />
      </div>

      {/* Enrichment Lookup Section - Publicly visible */}
      <Row className="mb-4">
        <Col md={12}>
          <SmallInfoCard
            id="enrichment-lookup"
            header="Enrichment Lookup"
            body={
              <div className="pt-2">
                <EnrichmentLookup />
              </div>
            }
          />
        </Col>
      </Row>

      <Row className="d-flex flex-wrap flex-lg-nowrap">
        {feedsTypesChartList.map(([id, header, Component]) => (
          <Col key={id} md={12} lg={12}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component />
                </div>
              }
              style={{ minHeight: 360 }}
            />
          </Col>
        ))}
      </Row>
      <Row className="d-flex flex-wrap flex-lg-nowrap mt-4">
        {feedsChartList.map(([id, header, Component]) => (
          <Col key={id} md={12} lg={6}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component />
                </div>
              }
              style={{ minHeight: 360 }}
            />
          </Col>
        ))}
      </Row>
      <Row className="d-flex flex-wrap flex-lg-nowrap mt-4">
        {enrichmentChartList.map(([id, header, Component]) => (
          <Col key={id} md={12} lg={6}>
            <SmallInfoCard
              id={id}
              header={header}
              body={
                <div className="pt-2">
                  <Component />
                </div>
              }
              style={{ minHeight: 360 }}
            />
          </Col>
        ))}
      </Row>
      <Row className="mt-4 d-flex flex-wrap flex-lg-nowrap">
        <Col md={12} lg={8}>
          <SmallInfoCard
            id="AttackOriginMap"
            header="Attack Origins: World Map"
            body={
              <div className="pt-2">
                <AttackOriginMap />
              </div>
            }
            style={{ height: "100%" }}
          />
        </Col>
        <Col md={12} lg={4} className="mt-3 mt-lg-0">
          <SmallInfoCard
            id="AttackOriginCountriesChart"
            header="Attack Origins: Top Countries"
            body={
              <div className="pt-2">
                <AttackOriginCountriesChart />
              </div>
            }
            style={{ height: "100%" }}
          />
        </Col>
      </Row>
    </Container>
  );
}

export default Dashboard;
