/**
 * A Map<string, WidgetDefinition> registry for all dashboard widgets
 *
 * Each entry shape:
 * {
 *   component:    React.ComponentType  - the widget component to render
 *   displayName:  string               - card header
 *   defaultColSpan: number             - default Bootstrap column width (1–12)
 *                                        (legacy; used by old DashboardRenderer)
 *   defaultHeight:  number | null      - min-height in px for noGrid widgets
 *   fillHeight:   boolean              - true = card fills its react-grid-layout slot (height 100%)
 *   endpoints:    string[]             - API endpoints this widget consumes
 *   defaultProps: object               - default props forwarded to the component
 *                                        by DashboardRenderer
 * }
 */

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

import {
  FEEDS_STATISTICS_SOURCES_URI,
  FEEDS_STATISTICS_DOWNLOADS_URI,
  FEEDS_STATISTICS_TYPES_URI,
  ENRICHMENT_STATISTICS_SOURCES_URI,
  ENRICHMENT_STATISTICS_REQUESTS_URI,
  IOC_ATTACKER_COUNTRIES_URI,
  ENRICHMENT_URI,
} from "../../constants/api";

/**
 * @typedef {Object} WidgetDefinition
 * @property {React.ComponentType} component
 * @property {string}   displayName
 * @property {number}   defaultColSpan
 * @property {number|null} defaultHeight
 * @property {boolean}  fillHeight
 * @property {string[]} endpoints
 * @property {object}   defaultProps
 */

/** @type {Map<string, WidgetDefinition>} */
const widgetRegistry = new Map([
  [
    "EnrichmentLookup",
    {
      component: EnrichmentLookup,
      displayName: "Enrichment Lookup",
      defaultColSpan: 12,
      defaultHeight: null, // auto-sizes via Bootstrap row
      fillHeight: false,
      endpoints: [ENRICHMENT_URI],
      defaultProps: {},
    },
  ],
  [
    "FeedsTypesChart",
    {
      component: FeedsTypesChart,
      displayName: "Feeds: Types",
      defaultColSpan: 12,
      defaultHeight: 360,
      fillHeight: true,
      endpoints: [FEEDS_STATISTICS_TYPES_URI],
      defaultProps: {},
    },
  ],
  [
    "FeedsSourcesChart",
    {
      component: FeedsSourcesChart,
      displayName: "Feeds: Sources",
      defaultColSpan: 6,
      defaultHeight: 360,
      fillHeight: true,
      endpoints: [FEEDS_STATISTICS_SOURCES_URI],
      defaultProps: {},
    },
  ],
  [
    "FeedsDownloadsChart",
    {
      component: FeedsDownloadsChart,
      displayName: "Feeds: Downloads",
      defaultColSpan: 6,
      defaultHeight: 360,
      fillHeight: true,
      endpoints: [FEEDS_STATISTICS_DOWNLOADS_URI],
      defaultProps: {},
    },
  ],
  [
    "EnrichmentSourcesChart",
    {
      component: EnrichmentSourcesChart,
      displayName: "Enrichment Service: Sources",
      defaultColSpan: 6,
      defaultHeight: 360,
      fillHeight: true,
      endpoints: [ENRICHMENT_STATISTICS_SOURCES_URI],
      defaultProps: {},
    },
  ],
  [
    "EnrichmentRequestsChart",
    {
      component: EnrichmentRequestsChart,
      displayName: "Enrichment Service: Requests",
      defaultColSpan: 6,
      defaultHeight: 360,
      fillHeight: true,
      endpoints: [ENRICHMENT_STATISTICS_REQUESTS_URI],
      defaultProps: {},
    },
  ],
  [
    "AttackOriginMap",
    {
      component: AttackOriginMap,
      displayName: "Attack Origins: World Map",
      defaultColSpan: 8,
      defaultHeight: null,
      fillHeight: true,
      endpoints: [IOC_ATTACKER_COUNTRIES_URI],
      defaultProps: {},
    },
  ],
  [
    "AttackOriginCountriesChart",
    {
      component: AttackOriginCountriesChart,
      displayName: "Attack Origins: Top Countries",
      defaultColSpan: 4,
      defaultHeight: null,
      fillHeight: false, // chart height is data-driven
      endpoints: [IOC_ATTACKER_COUNTRIES_URI],
      defaultProps: {},
    },
  ],
]);

export default widgetRegistry;
