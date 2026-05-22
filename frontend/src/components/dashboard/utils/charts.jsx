import React from "react";
import {
  Bar,
  Area,
  BarChart,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

import {
  AnyChartWidget,
  getRandomColorsArray,
  useTimePickerStore,
} from "@greedybear/gb-ui";
import {
  FEEDS_STATISTICS_SOURCES_URI,
  FEEDS_STATISTICS_DOWNLOADS_URI,
  FEEDS_STATISTICS_TYPES_URI,
  ENRICHMENT_STATISTICS_SOURCES_URI,
  ENRICHMENT_STATISTICS_REQUESTS_URI,
} from "../../../constants/api";
import useAttackerCountriesStore from "../../../stores/useAttackerCountriesStore";

import { FEED_COLOR_MAP, ENRICHMENT_COLOR_MAP } from "../../../constants";

const COUNTRY_BAR_COLOR = "#e05252";

// constants
const colors = getRandomColorsArray(30, true);

/**
 * Creates an area chart component to avoid duplicating chart setup code.
 *
 * @param {string} name - Display name for the generated chart component.
 * @param {string} url - API endpoint used to fetch chart data.
 * @param {Object} colorMap - Map of data keys to color values.
 * @param {number} start - Start index for slicing the color map.
 * @param {number} end - End index for slicing the color map.
 */
export const createAreaChart = (name, url, colorMap, start, end) => {
  const Component = React.memo(() => {
    console.debug(`${name} rendered!`);

    const chartProps = React.useMemo(
      () => ({
        url,
        accessorFnAggregation: (d) => d,
        componentsFn: () =>
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
      }),
      [url, colorMap, start, end],
    );

    return <AnyChartWidget {...chartProps} />;
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

  const chartProps = React.useMemo(
    () => ({
      url: FEEDS_STATISTICS_TYPES_URI,
      accessorFnAggregation: (d) => d,
      componentsFn: (respData) => {
        console.debug("respData", respData);
        if (!respData || !respData?.length) return null;

        // Exctract keys only from respData[0]:
        // feed types are the same for all elements of respData.
        // Slice "date" field: we are only interested in feeds types.
        const feedsTypes = [];
        Object.entries(respData[0])
          .slice(1)
          .map(([dKey], i) => (feedsTypes[i] = dKey));

        // map each feed type to a color
        return feedsTypes.map((dKey, i) => (
          <Bar stackId="feedtype" key={dKey} dataKey={dKey} fill={colors[i]} />
        ));
      },
    }),
    [],
  );

  return <AnyChartWidget {...chartProps} />;
});

export const AttackOriginCountriesChart = React.memo(() => {
  console.debug("AttackOriginCountriesChart rendered!");

  const { range } = useTimePickerStore();
  const {
    normalizedData: data,
    loading,
    error,
    fetchData,
  } = useAttackerCountriesStore();

  React.useEffect(() => {
    fetchData(range);
  }, [range, fetchData]);

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
