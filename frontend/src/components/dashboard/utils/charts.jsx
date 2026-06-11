import React from "react";
import {
  Bar,
  Area,
  BarChart,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Cell,
  ComposedChart,
} from "recharts";
import { format } from "date-fns";
import { getRandomColorsArray, useTimePickerStore } from "@greedybear/gb-ui";
import {
  FEEDS_STATISTICS_SOURCES_URI,
  FEEDS_STATISTICS_DOWNLOADS_URI,
  FEEDS_STATISTICS_TYPES_URI,
  ENRICHMENT_STATISTICS_SOURCES_URI,
  ENRICHMENT_STATISTICS_REQUESTS_URI,
  IOC_ATTACKER_COUNTRIES_URI,
} from "../../../constants/api";
import { FEED_COLOR_MAP, ENRICHMENT_COLOR_MAP } from "../../../constants";
import useWidgetData from "../../../hooks/useWidgetData";

const COUNTRY_BAR_COLOR = "#e05252";
const CHART_HEIGHT = 250;
const CHART_MARGIN = { top: 0, right: 0, left: 20, bottom: 0 };
const TOOLTIP_STYLE = {
  backgroundColor: "var(--darker)",
  border: 0,
  borderRadius: 5,
};

// constants
const colors = getRandomColorsArray(30, true);

/**
 * Shared chart skeleton: handles loading / empty / error states and renders a
 * ResponsiveContainer
 */
function ChartSkeleton({ data, loading, error, children }) {
  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4 text-muted">
        Loading…
      </div>
    );
  }
  if (error) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4 text-muted">
        {error}
      </div>
    );
  }
  if (!data || data.length === 0) {
    return (
      <h6 className="center text-muted">No data in the selected range.</h6>
    );
  }
  return (
    <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
      <ComposedChart data={data} margin={CHART_MARGIN}>
        <Legend verticalAlign="top" height={40} />
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <CartesianGrid stroke="#25404b" strokeDasharray="1 1" />
        <XAxis dataKey="date" />
        <YAxis allowDecimals={false} />
        {children}
      </ComposedChart>
    </ResponsiveContainer>
  );
}

/**
 * Transforms raw API response for a time-series chart:
 * sorts by date ascending and formats date strings using the current dateFormat.
 */
function useChartData(rawData, dateFormat) {
  return React.useMemo(() => {
    if (!rawData || !Array.isArray(rawData) || rawData.length === 0) return [];
    return [...rawData]
      .sort((a, b) => new Date(a.date) - new Date(b.date))
      .map((o) => ({ ...o, date: format(new Date(o.date), dateFormat) }));
  }, [rawData, dateFormat]);
}

/**
 * Creates an area chart component for a given API endpoint and colorMap slice.
 */
export const AreaChartWidget = React.memo(({ url, colorMap, start, end }) => {
  const { dateFormat } = useTimePickerStore();
  const { data: rawData, loading, error } = useWidgetData(url);
  const data = useChartData(rawData, dateFormat);

  const areas = React.useMemo(
    () =>
      Object.entries(colorMap)
        .slice(start, end)
        .map(([key, color]) => (
          <Area
            key={key}
            type="monotone"
            dataKey={key}
            fill={color}
            stroke={color}
          />
        )),
    [colorMap, start, end],
  );

  return (
    <ChartSkeleton data={data} loading={loading} error={error}>
      {areas}
    </ChartSkeleton>
  );
});
AreaChartWidget.displayName = "AreaChartWidget";

export const createAreaChart = (name, url, colorMap, start, end) => {
  const Component = React.memo(() => {
    console.debug(`${name} rendered!`);
    return (
      <AreaChartWidget url={url} colorMap={colorMap} start={start} end={end} />
    );
  });
  Component.displayName = name;
  return Component;
};

export const FeedsSourcesChart = createAreaChart(
  "FeedsSourcesChart",
  FEEDS_STATISTICS_SOURCES_URI,
  FEED_COLOR_MAP,
  0,
  1,
);

export const FeedsDownloadsChart = createAreaChart(
  "FeedsDownloadsChart",
  FEEDS_STATISTICS_DOWNLOADS_URI,
  FEED_COLOR_MAP,
  1,
  2,
);

export const EnrichmentSourcesChart = createAreaChart(
  "EnrichmentSourcesChart",
  ENRICHMENT_STATISTICS_SOURCES_URI,
  ENRICHMENT_COLOR_MAP,
  0,
  1,
);

export const EnrichmentRequestsChart = createAreaChart(
  "EnrichmentRequestsChart",
  ENRICHMENT_STATISTICS_REQUESTS_URI,
  ENRICHMENT_COLOR_MAP,
  1,
  2,
);

export const FeedsTypesChart = React.memo(() => {
  console.debug("FeedsTypesChart rendered!");

  const { dateFormat } = useTimePickerStore();
  const {
    data: rawData,
    loading,
    error,
  } = useWidgetData(FEEDS_STATISTICS_TYPES_URI);
  const data = useChartData(rawData, dateFormat);

  const bars = React.useMemo(() => {
    if (!data || data.length === 0) return null;
    // Extract feed type keys from first data point (everything except "date")
    const feedsTypes = Object.keys(data[0]).filter((k) => k !== "date");
    return feedsTypes.map((dKey, i) => (
      <Bar stackId="feedtype" key={dKey} dataKey={dKey} fill={colors[i]} />
    ));
  }, [data]);

  return (
    <ChartSkeleton data={data} loading={loading} error={error}>
      {bars}
    </ChartSkeleton>
  );
});
FeedsTypesChart.displayName = "FeedsTypesChart";

export const AttackOriginCountriesChart = React.memo(() => {
  console.debug("AttackOriginCountriesChart rendered!");

  const {
    data: rawData,
    loading,
    error,
  } = useWidgetData(IOC_ATTACKER_COUNTRIES_URI);

  // Normalise: build sorted array of { country, count, code }
  const data = React.useMemo(() => {
    const raw = Array.isArray(rawData) ? rawData : [];
    const countryMap = {};
    const nameMap = {};
    raw.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const code =
        typeof item.code === "string" ? item.code.toUpperCase() : null;
      if (!code) return;
      countryMap[code] = (countryMap[code] || 0) + (Number(item.count) || 0);
      if (!nameMap[code]) nameMap[code] = item.country || code;
    });
    return Object.entries(countryMap)
      .map(([code, count]) => ({ country: nameMap[code], count, code }))
      .sort((a, b) => b.count - a.count);
  }, [rawData]);

  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4 text-muted">
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4 text-muted">
        {error}
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="d-flex justify-content-center align-items-center py-4 text-muted">
        No country data available for the selected time range.
      </div>
    );
  }

  const chartData = data.slice(0, 15);

  return (
    <ResponsiveContainer
      width="100%"
      height={Math.max(180, chartData.length * 28)}
    >
      <BarChart
        layout="vertical"
        data={chartData}
        margin={{ top: 4, right: 48, left: 8, bottom: 4 }}
      >
        <XAxis
          type="number"
          tick={{ fontSize: 11 }}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          type="category"
          dataKey="country"
          width={140}
          interval={0}
          tick={{ fontSize: 12 }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip
          cursor={{ fill: "rgba(255,255,255,0.06)" }}
          formatter={(value) => [value.toLocaleString(), "IOCs"]}
        />
        <Bar dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={20}>
          {chartData.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={COUNTRY_BAR_COLOR}
              fillOpacity={1.0 - 0.45 * (index / (chartData.length - 1 || 1))}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
});
AttackOriginCountriesChart.displayName = "AttackOriginCountriesChart";
