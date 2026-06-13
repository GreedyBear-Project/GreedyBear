import React from "react";
import { Container } from "reactstrap";

import { ElasticTimePicker, useTimePickerStore } from "@greedybear/gb-ui";

import DashboardRenderer from "./DashboardRenderer";
import { WIDGET_CONFIGS, DASHBOARD_LAYOUTS } from "./defaultDashboardConfig";

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

      <DashboardRenderer
        widgetConfigs={WIDGET_CONFIGS}
        layouts={DASHBOARD_LAYOUTS}
      />
    </Container>
  );
}

export default Dashboard;
