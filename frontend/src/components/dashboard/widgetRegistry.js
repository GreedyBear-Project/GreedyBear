/**
 * A Map<string, WidgetDefinition> registry for all dashboard widgets
 *
 * Each entry shape:
 * {
 *   component:    React.ComponentType  - the widget component to render
 *   displayName:  string               - card header
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
      defaultHeight: null,
      fillHeight: false, // chart height is data-driven
      endpoints: [IOC_ATTACKER_COUNTRIES_URI],
      defaultProps: {},
    },
  ],
]);

export default widgetRegistry;
