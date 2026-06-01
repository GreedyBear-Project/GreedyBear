import React from "react";
import PropTypes from "prop-types";
import { Row, Col } from "reactstrap";
import { Responsive, useContainerWidth } from "react-grid-layout";

// react-grid-layout base styles
import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";

import widgetRegistry from "./widgetRegistry";
import WidgetWrapper from "./WidgetWrapper";

/**
 * @typedef {Object} WidgetConfig
 * @property {string}  type      - Registry key (must exist in widgetRegistry.js)
 * @property {string}  id        - Unique DOM id for this widget instance
 * @property {boolean} [noGrid]  - When true, widget is rendered as a Bootstrap
 *                                  Row ABOVE the RGL grid. Use for auto-height
 *                                  widgets like EnrichmentLookup that expand
 *                                  dynamically when results are displayed.
 * @property {object}  [props]   - Extra props forwarded to the widget component;
 *                                  merged with the registry entry's defaultProps
 */

/**
 * DashboardRenderer
 *   1. noGrid widgets: Bootstrap Rows stacked above the RGL grid.
 *                        Cards auto-size to their content (no fixed height).
 *   2. grid widgets: Inside a react-grid-layout `Responsive` grid driven
 *                    by the `layouts` prop.
 *
 * @param {object}       props
 * @param {WidgetConfig[]} props.widgetConfigs
 * @param {object}         props.layouts
 */
function DashboardRenderer({ widgetConfigs, layouts = {} }) {
  const { width, containerRef } = useContainerWidth();

  const noGridConfigs = widgetConfigs.filter((cfg) => cfg.noGrid);
  const gridConfigs = widgetConfigs.filter((cfg) => !cfg.noGrid);

  /**
   * Look up the registry and return a fully-wrapped widget.
   * Falls back to a visible warning if the registry key is unknown.
   */
  const renderWidget = React.useCallback((cfg) => {
    const definition = widgetRegistry.get(cfg.type);

    if (!definition) {
      console.warn(
        `[DashboardRenderer] Unknown widget type: "${cfg.type}". ` +
          `Make sure it is registered in widgetRegistry.js.`,
      );
      return (
        <div className="alert alert-warning small">
          Unknown widget: <code>{cfg.type}</code>
        </div>
      );
    }

    const {
      component: WidgetComponent,
      displayName,
      defaultHeight,
      fillHeight,
      defaultProps: registryDefaultProps,
    } = definition;

    // Per-instance props win over registry defaults
    const mergedProps = {
      ...(registryDefaultProps ?? {}),
      ...(cfg.props ?? {}),
    };

    return (
      <WidgetWrapper
        id={cfg.id}
        header={displayName}
        // minHeight is only meaningful for noGrid (auto-sized) widgets.
        // Grid widgets control height via their RGL layout item's `h` value.
        minHeight={cfg.noGrid ? (defaultHeight ?? undefined) : undefined}
        fillHeight={fillHeight ?? false}
      >
        <WidgetComponent {...mergedProps} />
      </WidgetWrapper>
    );
  }, []);

  return (
    <>
      {noGridConfigs.map((cfg, idx) => (
        <Row key={cfg.id} className={`${idx > 0 ? "mt-4 " : ""}mb-4`}>
          <Col md={12}>{renderWidget(cfg)}</Col>
        </Row>
      ))}

      {gridConfigs.length > 0 && (
        <div ref={containerRef}>
          <Responsive
            width={width}
            layouts={layouts}
            breakpoints={{ lg: 992, md: 768, sm: 576, xs: 480, xxs: 0 }}
            cols={{ lg: 12, md: 12, sm: 12, xs: 1, xxs: 1 }}
            rowHeight={30}
            margin={[16, 16]}
            containerPadding={[0, 0]}
            /*
             * note to self: enable these when implementing drag and drop
             */
            dragConfig={{ enabled: false }}
            resizeConfig={{ enabled: false }}
          >
            {gridConfigs.map((cfg) => (
              <div
                key={cfg.id}
                data-widget-id={cfg.id}
                style={{ height: "100%", overflow: "hidden" }}
              >
                {renderWidget(cfg)}
              </div>
            ))}
          </Responsive>
        </div>
      )}
    </>
  );
}

DashboardRenderer.propTypes = {
  widgetConfigs: PropTypes.arrayOf(
    PropTypes.shape({
      type: PropTypes.string.isRequired,
      id: PropTypes.string.isRequired,
      noGrid: PropTypes.bool,
      props: PropTypes.object,
    }),
  ).isRequired,
  layouts: PropTypes.objectOf(
    PropTypes.arrayOf(
      PropTypes.shape({
        i: PropTypes.string.isRequired,
        x: PropTypes.number.isRequired,
        y: PropTypes.number.isRequired,
        w: PropTypes.number.isRequired,
        h: PropTypes.number.isRequired,
        static: PropTypes.bool,
      }),
    ),
  ),
};



export default DashboardRenderer;
