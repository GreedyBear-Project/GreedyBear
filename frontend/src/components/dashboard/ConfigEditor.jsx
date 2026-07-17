import React from "react";
import { Link } from "react-router-dom";
import {
  Container,
  Badge,
  Dropdown,
  DropdownToggle,
  DropdownMenu,
  DropdownItem,
  Row,
  Col,
} from "reactstrap";
import { Responsive, useContainerWidth } from "react-grid-layout";
import {
  MdArrowBack,
  MdAdd,
  MdClose,
  MdSave,
  MdRestartAlt,
} from "react-icons/md";
import { useShallow } from "zustand/shallow";

import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";

import widgetRegistry from "./widgetRegistry";
import WidgetWrapper from "./WidgetWrapper";
import useDashboardStore from "../../stores/useDashboardStore";

const DEFAULT_H = 9;

function buildLayoutEntry(id, currentLgLayout, w = 12) {
  const maxY = currentLgLayout.reduce(
    (acc, item) => Math.max(acc, item.y + item.h),
    0,
  );
  return { i: id, x: 0, y: maxY, w, h: 9, static: false };
}

// ---------------------------------------------------------------------------
// EditableWidgetCard
// Renders the real widget. A small floating X button sits in the top-right
// corner for removal. The whole card is the drag target.
// ---------------------------------------------------------------------------
function EditableWidgetCard({ cfg, definition, onRemove }) {
  const {
    component: WidgetComponent,
    displayName,
    defaultProps: registryDefaultProps,
  } = definition;
  const mergedProps = { ...(registryDefaultProps ?? {}), ...(cfg.props ?? {}) };

  return (
    <div style={{ height: "100%", position: "relative" }}>
      <WidgetWrapper id={cfg.id} header={displayName} fillHeight>
        <WidgetComponent {...mergedProps} />
      </WidgetWrapper>

      {/* remove button */}
      <button
        title="Remove widget"
        onMouseDown={(e) => e.stopPropagation()}
        onClick={(e) => {
          e.stopPropagation();
          onRemove(cfg.id);
        }}
        style={{
          position: "absolute",
          top: 6,
          right: 8,
          zIndex: 10,
          background: "rgba(224,82,82,0.85)",
          border: "none",
          borderRadius: "50%",
          width: 22,
          height: 22,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          cursor: "pointer",
          color: "#fff",
          fontSize: "0.85rem",
          boxShadow: "0 1px 4px rgba(0,0,0,0.4)",
        }}
      >
        <MdClose />
      </button>
    </div>
  );
}

function AddWidgetDropdown({ availableWidgets, addedTypes, onAdd }) {
  const [open, setOpen] = React.useState(false);
  const unadded = availableWidgets.filter(([type]) => !addedTypes.has(type));

  return (
    <Dropdown isOpen={open} toggle={() => setOpen((o) => !o)}>
      <DropdownToggle
        id="config-add-widget-btn"
        className="btn btn-sm btn-outline-primary d-flex align-items-center gap-1"
        tag="button"
        disabled={unadded.length === 0}
        style={{ opacity: 1 }}
        title={
          unadded.length === 0
            ? "All widgets are already on the dashboard"
            : "Add a widget"
        }
      >
        <MdAdd />
        Add Widget
      </DropdownToggle>
      <DropdownMenu
        end
        style={{
          background: "#1e1e2e",
          border: "1px solid rgba(99,102,241,0.35)",
          boxShadow: "0 4px 16px rgba(0,0,0,0.5)",
        }}
      >
        {unadded.map(([type, def]) => (
          <DropdownItem
            key={type}
            onClick={() => {
              onAdd(type);
              setOpen(false);
            }}
          >
            {def.displayName}
          </DropdownItem>
        ))}
      </DropdownMenu>
    </Dropdown>
  );
}

export default function ConfigEditor() {
  console.debug("ConfigEditor rendered!");

  const {
    layouts,
    widgetConfigs,
    isDirty,
    setLayouts,
    setWidgetConfigs,
    save,
    resetToDefault,
  } = useDashboardStore(
    useShallow((s) => ({
      layouts: s.layouts,
      widgetConfigs: s.widgetConfigs,
      isDirty: s.isDirty,
      setLayouts: s.setLayouts,
      setWidgetConfigs: s.setWidgetConfigs,
      save: s.save,
      resetToDefault: s.resetToDefault,
    })),
  );

  const { width, containerRef } = useContainerWidth();

  const gridConfigs = React.useMemo(
    () => widgetConfigs.filter((cfg) => !cfg.noGrid),
    [widgetConfigs],
  );

  const noGridConfigs = React.useMemo(
    () => widgetConfigs.filter((cfg) => cfg.noGrid),
    [widgetConfigs],
  );

  const addedTypes = React.useMemo(
    () => new Set(gridConfigs.map((cfg) => cfg.type)),
    [gridConfigs],
  );

  // Widget types that are already rendered above the grid (noGrid: true).
  const noGridTypes = React.useMemo(
    () =>
      new Set(widgetConfigs.filter((cfg) => cfg.noGrid).map((cfg) => cfg.type)),
    [widgetConfigs],
  );

  // All grid-capable widgets
  const availableWidgets = React.useMemo(
    () =>
      [...widgetRegistry.entries()].filter(
        ([type, def]) => def.fillHeight !== undefined && !noGridTypes.has(type),
      ),
    [noGridTypes],
  );

  const handleAdd = React.useCallback(
    (type) => {
      const def = widgetRegistry.get(type);
      if (!def) return;
      const id = type;
      const nextConfigs = [...widgetConfigs, { type, id, noGrid: false }];
      setWidgetConfigs(nextConfigs);
      const lgEntry = buildLayoutEntry(id, layouts.lg ?? [], 12);
      setLayouts({
        lg: [...(layouts.lg ?? []), lgEntry],
        md: [...(layouts.md ?? []), { ...lgEntry, w: 12 }],
        sm: [...(layouts.sm ?? []), { ...lgEntry, w: 12 }],
      });
    },
    [widgetConfigs, layouts, setWidgetConfigs, setLayouts],
  );

  const handleRemove = React.useCallback(
    (id) => {
      setWidgetConfigs(widgetConfigs.filter((cfg) => cfg.id !== id));
      setLayouts({
        lg: (layouts.lg ?? []).filter((item) => item.i !== id),
        md: (layouts.md ?? []).filter((item) => item.i !== id),
        sm: (layouts.sm ?? []).filter((item) => item.i !== id),
      });
    },
    [widgetConfigs, layouts, setWidgetConfigs, setLayouts],
  );

  const handleLayoutChange = React.useCallback(
    (_currentLayout, allLayouts) => {
      setLayouts({
        lg: allLayouts.lg ?? layouts.lg,
        md: allLayouts.md ?? layouts.md,
        sm: allLayouts.sm ?? layouts.sm,
      });
    },
    [setLayouts, layouts],
  );

  const handleReset = React.useCallback(() => {
    if (
      window.confirm("Reset dashboard to defaults? All changes will be lost.")
    ) {
      resetToDefault();
    }
  }, [resetToDefault]);

  const editableLayouts = React.useMemo(() => {
    const makeEditable = (arr) =>
      (arr ?? []).map((item) => ({ ...item, static: false }));
    return {
      lg: makeEditable(layouts.lg),
      md: makeEditable(layouts.md),
      sm: makeEditable(layouts.sm),
    };
  }, [layouts]);

  return (
    <Container fluid id="ConfigEditor" className="py-3">
      <div className="d-flex align-items-center flex-wrap gap-2 mb-3">
        <Link
          to="/dashboard"
          className="btn btn-sm btn-outline-secondary d-flex align-items-center gap-1"
          id="config-back-btn"
        >
          <MdArrowBack />
          Dashboard
        </Link>

        <h5 className="fw-bold mb-0 ms-1">Dashboard Config</h5>

        {isDirty && (
          <Badge color="warning" className="align-self-center">
            Unsaved changes
          </Badge>
        )}

        <div className="ms-auto d-flex gap-2">
          <AddWidgetDropdown
            availableWidgets={availableWidgets}
            addedTypes={addedTypes}
            onAdd={handleAdd}
          />
          <button
            id="config-reset-btn"
            className="btn btn-sm btn-outline-danger d-flex align-items-center gap-1"
            onClick={handleReset}
            title="Reset to defaults"
          >
            <MdRestartAlt />
            Reset
          </button>
          <button
            id="config-save-btn"
            className="btn btn-sm btn-primary d-flex align-items-center gap-1"
            onClick={save}
            disabled={!isDirty}
            title="Save layout"
          >
            <MdSave />
            Save
          </button>
        </div>
      </div>

      {noGridConfigs.map((cfg, idx) => {
        const definition = widgetRegistry.get(cfg.type);
        if (!definition) return null;
        const {
          component: WidgetComponent,
          displayName,
          defaultHeight,
          defaultProps: registryDefaultProps,
        } = definition;
        const mergedProps = {
          ...(registryDefaultProps ?? {}),
          ...(cfg.props ?? {}),
        };
        return (
          <Row key={cfg.id} className={`${idx > 0 ? "mt-4 " : ""}mb-4`}>
            <Col md={12}>
              <WidgetWrapper
                id={cfg.id}
                header={displayName}
                minHeight={defaultHeight}
              >
                <WidgetComponent {...mergedProps} />
              </WidgetWrapper>
            </Col>
          </Row>
        );
      })}

      <p className="small text-muted mb-3" style={{ fontSize: 12 }}>
        Drag any widget to reorder · drag the bottom-right corner to resize
      </p>

      <div ref={containerRef}>
        {gridConfigs.length === 0 ? (
          <div
            className="d-flex align-items-center justify-content-center text-muted"
            style={{
              minHeight: 200,
              border: "2px dashed rgba(99,102,241,0.25)",
              borderRadius: 10,
            }}
          >
            <span className="small">
              No widgets — use <strong>Add Widget</strong> above to add one.
            </span>
          </div>
        ) : (
          <Responsive
            width={width || 800}
            layouts={editableLayouts}
            breakpoints={{ lg: 992, md: 768, sm: 576, xs: 480, xxs: 0 }}
            cols={{ lg: 12, md: 12, sm: 12, xs: 1, xxs: 1 }}
            rowHeight={30}
            margin={[16, 16]}
            containerPadding={[0, 0]}
            onLayoutChange={handleLayoutChange}
            resizeHandles={["se"]}
          >
            {gridConfigs.map((cfg) => {
              const definition = widgetRegistry.get(cfg.type);
              if (!definition) return null;
              return (
                <div
                  key={cfg.id}
                  style={{ height: "100%", overflow: "hidden" }}
                >
                  <EditableWidgetCard
                    cfg={cfg}
                    definition={definition}
                    onRemove={handleRemove}
                  />
                </div>
              );
            })}
          </Responsive>
        )}
      </div>
    </Container>
  );
}
