import { rowSelectHooks, rowExpandHooks } from "./hooks";

// gotta maintain the order of these plugins
function makeTableArgs(config) {
  const args = [];
  if (config?.enableExpanded) args.push(...rowExpandHooks);
  if (config?.enableSelection) args.push(...rowSelectHooks);
  return [...args, ...config.customHooks];
}

const defaultConfig = {
  enableFlexLayout: true,
  enableExpanded: false,
  enableSortBy: true,
  enableFilters: true,
  enableSelection: false,
  customHooks: [],
};

const defaultInitialState = {
  pageIndex: 0,
  pageSize: 10,
  sortBy: [],
  selectedRowIds: {},
};

const defaultColumn = {
  // Let's set up our default Filter UI
  Filter: () => null,
};

export { makeTableArgs, defaultConfig, defaultInitialState, defaultColumn };
