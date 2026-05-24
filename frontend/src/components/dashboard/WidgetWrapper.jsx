import React from "react";
import PropTypes from "prop-types";
import { SmallInfoCard } from "@greedybear/gb-ui";

class WidgetErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error(
      `[WidgetErrorBoundary] Widget "${this.props.widgetId}" threw:`,
      error,
      info,
    );
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          className="d-flex flex-column justify-content-center align-items-center py-4 text-muted"
          style={{ minHeight: 120 }}
        >
          <span className="small">
            Widget failed to render.
            <br />
            <code className="small">{this.state.error?.message}</code>
          </span>
        </div>
      );
    }
    return this.props.children;
  }
}

WidgetErrorBoundary.propTypes = {
  widgetId: PropTypes.string.isRequired,
  children: PropTypes.node.isRequired,
};

// ---------------------------------------------------------------------------
// Props:
//   id         {string}       DOM id forwarded to SmallInfoCard
//   header     {string}       Card header text (widget displayName)
//   minHeight  {number|null}  Optional min-height in px (noGrid widgets)
//   fillHeight {boolean}      When true, card takes full container height
//                             (used inside react-grid-layout slots)
//   children   {ReactNode}    The widget component
// ---------------------------------------------------------------------------
function WidgetWrapper({ id, header, minHeight, fillHeight, children }) {
  const cardStyle = React.useMemo(() => {
    if (fillHeight) return { height: "100%" };
    if (minHeight != null) return { minHeight };
    return undefined;
  }, [fillHeight, minHeight]);

  return (
    <SmallInfoCard
      id={id}
      header={header}
      body={<div className="pt-2">{children}</div>}
      style={cardStyle}
    />
  );
}

WidgetWrapper.propTypes = {
  id: PropTypes.string.isRequired,
  header: PropTypes.string.isRequired,
  minHeight: PropTypes.number,
  fillHeight: PropTypes.bool,
  children: PropTypes.node.isRequired,
};

WidgetWrapper.defaultProps = {
  minHeight: null,
  fillHeight: false,
};

function SafeWidgetWrapper({ id, header, minHeight, fillHeight, children }) {
  return (
    <WidgetErrorBoundary widgetId={id}>
      <WidgetWrapper
        id={id}
        header={header}
        minHeight={minHeight}
        fillHeight={fillHeight}
      >
        {children}
      </WidgetWrapper>
    </WidgetErrorBoundary>
  );
}

SafeWidgetWrapper.propTypes = {
  id: PropTypes.string.isRequired,
  header: PropTypes.string.isRequired,
  minHeight: PropTypes.number,
  fillHeight: PropTypes.bool,
  children: PropTypes.node.isRequired,
};

SafeWidgetWrapper.defaultProps = {
  minHeight: null,
  fillHeight: false,
};

export default SafeWidgetWrapper;
