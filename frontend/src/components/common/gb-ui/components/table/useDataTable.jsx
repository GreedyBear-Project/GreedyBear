import React from "react";
import useAxios from "axios-hooks";

import LoadingBoundary from "../containers/LoadingBoundary";

import DataTable from "./DataTable";
import useQueryParamsTable from "./useQueryParamsTable";

const defaultPageParams = {
  page_size: 10,
  page: 1,
};
const defaultModifier = (responseData) => responseData?.results || [];

/**
 * Suitable for fetching data from a server. Thus, pagination/filtering/sorting in most cases should be handled by the server too.
 * @param url URL to use to make the request.
 * @param params Query parameters that will be added to the request, which can be overridden by table filters.
 * @param toPassTableProps Table properties (ex. columns, config, initialState, SubComponent) that will be used for creating the table component.
 * @param modifier Function that defines in which field of the response the data that will be used is located.
 */
function useDataTable(
  { url, params: defaultParams },
  toPassTableProps,
  modifier = defaultModifier,
) {
  // hook
  const [params, tableInitialState, tableStateReducer] = useQueryParamsTable();

  // state
  const [initialLoading, setInitialLoading] = React.useState(true);

  // API
  const [{ data, loading, error }, refetch] = useAxios({
    url,
    params: { ...defaultPageParams, ...defaultParams, ...params },
  });

  // side-effects
  // initial table loading (spinner)
  React.useEffect(() => {
    if (!loading) setInitialLoading(false);
  }, [loading]);
  // https://it.reactjs.org/docs/hooks-effect.html#tip-optimizing-performance-by-skipping-effects

  // https://it.reactjs.org/docs/hooks-reference.html#usememo
  const tableNode = React.useMemo(
    () => (
      <LoadingBoundary
        loading={initialLoading}
        error={error}
        render={() => (
          <DataTable
            data={data ? modifier(data) : []}
            pageCount={data?.total_pages || 1}
            stateReducer={tableStateReducer}
            initialState={tableInitialState}
            manualPagination
            manualFilters
            manualSortBy
            customProps={{ refetchTableData: refetch }}
            {...toPassTableProps}
          />
        )}
      />
    ),
    [
      data,
      modifier,
      initialLoading,
      error,
      tableInitialState,
      tableStateReducer,
      refetch,
      toPassTableProps,
    ],
  );

  return [
    data,
    tableNode,
    refetch,
    tableStateReducer,
    loading,
    tableInitialState,
  ];
}

export default useDataTable;
