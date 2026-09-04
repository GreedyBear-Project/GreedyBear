import React from "react";
import { useNavigate, useLocation } from "react-router-dom";

import useAsyncDebounce from "../../hooks/useAsyncDebounce";

import {
  serializeFilterParams,
  deserializeFilterParams,
  serializeSortByParams,
  deserializeSortByParams,
} from "./queryParamsUtils";

/**
  This function automatically defines the params to be used in the request based on the filters set in the table and the URL search parameters.
*/
function useQueryParamsTable() {
  // react-router
  const navigate = useNavigate();
  const location = useLocation();

  // Set the params based on url search params, if no parameter is set in the url it returns an empty dict
  const [params, setParams] = React.useState(() => {
    const urlParams = Object.fromEntries(new URLSearchParams(location.search));
    return Object.keys(urlParams).length ? urlParams : {};
  });

  // The table state changes every time the url params are modified, therefore every time some filters are modified
  const tableInitialState = React.useMemo(() => {
    const { ordering, page, ...filters } = params;
    return {
      pageIndex: page ? parseInt(page - 1, 10) : 0,
      sortBy: ordering ? deserializeSortByParams(ordering) : [],
      filters: filters ? deserializeFilterParams(filters) : [],
    };
  }, [params]);

  // Update query params to match table state and navigate to a page with the new params
  React.useEffect(() => {
    const qs = new URLSearchParams(params).toString();
    const search = qs ? `?${qs}` : "";
    if (search !== location.search) navigate({ search }, { replace: true });
  }, [navigate, params, location.search]);

  // callbacks
  const onTableFilterDebounced = useAsyncDebounce(
    (filters) =>
      setParams(({ ordering }) => ({
        ...(ordering ? { ordering } : {}), // only include 'ordering' key if it defined
        ...serializeFilterParams(filters), // only serialize 'filters' field
      })),
    500,
  ); // Debounce filter call for 500ms

  const onTableSortDebounced = useAsyncDebounce(
    (sortBy) =>
      sortBy?.length
        ? setParams(({ ordering, ...others }) => ({
            ...others,
            ordering: serializeSortByParams(sortBy), // override only 'ordering' key
          }))
        : setParams(({ ordering, ...others }) => others), // if sortBy has been reset remove the 'orgering' key
    500,
  ); // Debounce sortBy call for 500ms

  const tableStateReducer = React.useCallback(
    (newState, action) => {
      const filters = newState?.filters || newState?.columnFilters || [];
      const sortBy = newState?.sortBy || newState?.sorting || [];
      const pageIndex =
        typeof action?.pageIndex === "number"
          ? action.pageIndex
          : newState?.pageIndex || newState?.pagination?.pageIndex || 0;

      switch (action.type) {
        case "gotoPage":
          setParams((currParams) => ({
            ...currParams,
            page: pageIndex + 1,
          }));
          break;
        case "setFilter":
          onTableFilterDebounced(filters);
          break;
        case "toggleSortBy":
          onTableSortDebounced(sortBy);
          break;
        default:
          break;
      }
      return newState;
    },
    [setParams, onTableFilterDebounced, onTableSortDebounced],
  );

  return [params, tableInitialState, tableStateReducer];
}

export default useQueryParamsTable;
