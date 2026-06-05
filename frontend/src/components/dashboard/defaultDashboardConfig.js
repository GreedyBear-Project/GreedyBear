export const WIDGET_CONFIGS = [
  // EnrichmentLookup must auto-size because its card grows when results appear.
  {
    type: "EnrichmentLookup",
    id: "enrichment-lookup",
    noGrid: true,
  },

  // rendered inside react-grid-layout
  { type: "FeedsTypesChart", id: "FeedsTypesChart" },
  { type: "FeedsSourcesChart", id: "FeedsSourcesChart" },
  { type: "FeedsDownloadsChart", id: "FeedsDownloadsChart" },
  { type: "EnrichmentSourcesChart", id: "EnrichmentSourcesChart" },
  { type: "EnrichmentRequestsChart", id: "EnrichmentRequestsChart" },
  { type: "AttackOriginMap", id: "AttackOriginMap" },
  { type: "AttackOriginCountriesChart", id: "AttackOriginCountriesChart" },
];

// `static: true` prevents dragging/resizing
// set this to false for admin sessions and persist user layouts.

export const DASHBOARD_LAYOUTS = {
  lg: [
    { i: "FeedsTypesChart", x: 0, y: 0, w: 12, h: 9, static: true },
    { i: "FeedsSourcesChart", x: 0, y: 9, w: 6, h: 9, static: true },
    { i: "FeedsDownloadsChart", x: 6, y: 9, w: 6, h: 9, static: true },
    { i: "EnrichmentSourcesChart", x: 0, y: 18, w: 6, h: 9, static: true },
    { i: "EnrichmentRequestsChart", x: 6, y: 18, w: 6, h: 9, static: true },
    { i: "AttackOriginMap", x: 0, y: 27, w: 8, h: 12, static: true },
    { i: "AttackOriginCountriesChart", x: 8, y: 27, w: 4, h: 12, static: true },
  ],

  md: [
    { i: "FeedsTypesChart", x: 0, y: 0, w: 12, h: 9, static: true },
    { i: "FeedsSourcesChart", x: 0, y: 9, w: 12, h: 9, static: true },
    { i: "FeedsDownloadsChart", x: 0, y: 18, w: 12, h: 9, static: true },
    { i: "EnrichmentSourcesChart", x: 0, y: 27, w: 12, h: 9, static: true },
    { i: "EnrichmentRequestsChart", x: 0, y: 36, w: 12, h: 9, static: true },
    { i: "AttackOriginMap", x: 0, y: 45, w: 12, h: 12, static: true },
    {
      i: "AttackOriginCountriesChart",
      x: 0,
      y: 55,
      w: 12,
      h: 12,
      static: true,
    },
  ],

  sm: [
    { i: "FeedsTypesChart", x: 0, y: 0, w: 12, h: 9, static: true },
    { i: "FeedsSourcesChart", x: 0, y: 9, w: 12, h: 9, static: true },
    { i: "FeedsDownloadsChart", x: 0, y: 18, w: 12, h: 9, static: true },
    { i: "EnrichmentSourcesChart", x: 0, y: 27, w: 12, h: 9, static: true },
    { i: "EnrichmentRequestsChart", x: 0, y: 36, w: 12, h: 9, static: true },
    { i: "AttackOriginMap", x: 0, y: 45, w: 12, h: 12, static: true },
    {
      i: "AttackOriginCountriesChart",
      x: 0,
      y: 55,
      w: 12,
      h: 12,
      static: true,
    },
  ],
};
