import React from "react";
import { format } from "date-fns";

import CustomComposedChart from "./CustomComposedChart";

import { useAxiosComponentLoader } from "../../hooks";
import { useTimePickerStore } from "../../stores";

export default function AnyChartWidget({
  url,
  accessorFnAggregation,
  componentsFn,
  composedChartProps = undefined,
}) {
  // consume zustand store
  const { range, dateFormat } = useTimePickerStore();

  // API
  const [respData, Loader] = useAxiosComponentLoader({
    url,
    params: {
      range,
    },
  });

  // memo
  const chartData = React.useMemo(() => {
    const aggregation = accessorFnAggregation(respData);
    if (!aggregation || !aggregation?.length) return null;
    return aggregation
      .sort((a, b) => new Date(a.date) - new Date(b.date))
      .map((o) => ({
        ...o,
        date: format(new Date(o.date), dateFormat),
      }));
  }, [accessorFnAggregation, dateFormat, respData]);

  const components = React.useMemo(
    () => componentsFn(respData),
    [respData, componentsFn],
  );

  return (
    <Loader
      render={() =>
        chartData?.length ? (
          <CustomComposedChart
            xAxisDataKey="date"
            data={chartData}
            {...composedChartProps}
          >
            {components}
          </CustomComposedChart>
        ) : (
          <h6 className="center text-muted">No data in the selected range.</h6>
        )
      }
    />
  );
}
