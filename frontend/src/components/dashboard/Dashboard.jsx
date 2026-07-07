import React from "react";
import { Link } from "react-router-dom";
import { Container } from "reactstrap";
import { MdSettings } from "react-icons/md";
import { useShallow } from "zustand/shallow";

import { ElasticTimePicker, useTimePickerStore } from "@greedybear/gb-ui";

import DashboardRenderer from "./DashboardRenderer";
import useDashboardStore from "../../stores/useDashboardStore";
import { useAuthStore } from "../../stores";

function Dashboard() {
  console.debug("Dashboard rendered!");
  const { range, onTimeIntervalChange } = useTimePickerStore();

  const isSuperuser = useAuthStore(React.useCallback((s) => s.isSuperuser, []));

  const { widgetConfigs, layouts, savedVersion } = useDashboardStore(
    useShallow((s) => ({
      widgetConfigs: s.widgetConfigs,
      layouts: s.layouts,
      savedVersion: s.savedVersion,
    })),
  );

  const staticLayouts = React.useMemo(() => {
    const freeze = (arr) =>
      (arr ?? []).map((item) => ({ ...item, static: true }));
    return {
      lg: freeze(layouts.lg),
      md: freeze(layouts.md),
      sm: freeze(layouts.sm),
    };
  }, [layouts]);

  return (
    <Container fluid id="Dashboard">
      <div className="g-0 d-flex align-items-baseline flex-column flex-lg-row mb-2">
        <h3 className="fw-bold">Dashboard</h3>

        <div className="ms-auto d-flex align-items-center gap-2">
          {isSuperuser && (
            <Link
              to="/dashboard/config"
              id="dashboard-configure-btn"
              className="btn btn-sm btn-outline-secondary d-flex align-items-center gap-1"
              title="Configure dashboard layout"
            >
              <MdSettings />
              Configure
            </Link>
          )}
          <ElasticTimePicker
            size="sm"
            defaultSelected={range}
            onChange={onTimeIntervalChange}
          />
        </div>
      </div>

      <DashboardRenderer
        key={savedVersion}
        widgetConfigs={widgetConfigs}
        layouts={staticLayouts}
      />
    </Container>
  );
}

export default Dashboard;
