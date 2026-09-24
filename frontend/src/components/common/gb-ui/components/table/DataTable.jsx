/* eslint-disable no-nested-ternary */
import React from "react";
import classnames from "classnames";
import { Table } from "reactstrap";
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  getPaginationRowModel,
} from "@tanstack/react-table";
import { FaSort, FaSortUp, FaSortDown } from "react-icons/fa";

import { makeTableArgs, defaultConfig, defaultInitialState } from "./utils";
import Paginator from "./Paginator";

function getColumnId(column) {
  return column.id || column.accessor;
}

function getAccessorFn(column) {
  if (typeof column.accessor === "function") return column.accessor;
  if (typeof column.accessor === "string")
    return (row) => row?.[column.accessor];
  return () => undefined;
}

function normalizeColumn(column, index) {
  const id = getColumnId(column) || `column_${index}`;
  const accessorFn = getAccessorFn(column);

  return {
    ...column,
    id,
    accessorFn,
  };
}

function getLegacyRowValue(row, column) {
  if (!column?.accessorFn) return undefined;
  return column.accessorFn(row);
}

function legacyDefaultFilterFn(row, columnId, filterValue) {
  if (filterValue === undefined || filterValue === null || filterValue === "")
    return true;

  const normalizedFilter = `${filterValue}`.toLowerCase();
  const rowValue = row.getValue(columnId);

  if (Array.isArray(rowValue)) {
    return rowValue.some((value) =>
      `${value ?? ""}`.toLowerCase().includes(normalizedFilter),
    );
  }

  return `${rowValue ?? ""}`.toLowerCase().includes(normalizedFilter);
}

/**
 * Suitable when data is already available client side. Thus, pagination/filtering/sorting can be performed client side too.
 */
function DataTable({
  config: userConfig = defaultConfig,
  onSelectedRowChange = undefined,
  SubComponent = undefined,
  tableProps = undefined,
  tableEmptyNode = "No Data",
  TableBodyComponent = undefined,
  columns = [],
  data = [],
  initialState = defaultInitialState,
  stateReducer = undefined,
  isRowSelectable = () => true,
  customProps = undefined,
  manualPagination = false,
  manualFilters = false,
  manualSortBy = false,
  pageCount = undefined,
}) {
  const config = React.useMemo(
    () => ({ ...defaultConfig, ...userConfig }),
    [userConfig],
  );

  const tableArgs = React.useMemo(() => makeTableArgs(config), [config]);

  const hookRegistry = React.useMemo(() => {
    const registry = { visibleColumns: [], getRowProps: [] };
    tableArgs.forEach((hook) => {
      if (typeof hook === "function") hook(registry);
    });
    return registry;
  }, [tableArgs]);

  const baseColumns = React.useMemo(
    () => columns.map((column, index) => normalizeColumn(column, index)),
    [columns],
  );

  const baseInstance = React.useMemo(
    () => ({ customProps, isRowSelectable }),
    [customProps, isRowSelectable],
  );

  const legacyColumns = React.useMemo(() => {
    let transformedColumns = baseColumns;
    hookRegistry.visibleColumns.forEach((transformer) => {
      transformedColumns = transformer(transformedColumns, {
        instance: baseInstance,
      });
    });
    return transformedColumns;
  }, [baseColumns, hookRegistry, baseInstance]);

  const tanstackColumns = React.useMemo(
    () =>
      legacyColumns.map((column) => ({
        id: column.id,
        accessorFn: column.accessorFn,
        enableSorting: config.enableSortBy && !column.disableSortBy,
        enableColumnFilter: config.enableFilters && !!column.Filter,
        filterFn: column.filterFn || legacyDefaultFilterFn,
        meta: { legacyColumn: column },
      })),
    [legacyColumns, config.enableSortBy, config.enableFilters],
  );

  const legacyInitialState = React.useMemo(
    () => ({ ...defaultInitialState, ...initialState }),
    [initialState],
  );

  const [tableState, setTableState] = React.useState(() => ({
    pagination: {
      pageIndex: legacyInitialState.pageIndex || 0,
      pageSize: legacyInitialState.pageSize || 10,
    },
    sorting: legacyInitialState.sortBy || [],
    columnFilters: legacyInitialState.filters || [],
    rowSelection: legacyInitialState.selectedRowIds || {},
    expanded: {},
  }));

  const reduceState = React.useCallback(
    (nextState, action, prevState) => {
      if (!stateReducer) return nextState;
      return stateReducer(nextState, action, prevState) || nextState;
    },
    [stateReducer],
  );

  const updateState = React.useCallback(
    (producer, action) => {
      setTableState((previousState) => {
        const nextState = producer(previousState);
        return reduceState(nextState, action, previousState);
      });
    },
    [reduceState],
  );

  const toggleRowSelected = React.useCallback(
    (rowId, selected) => {
      updateState(
        (previousState) => ({
          ...previousState,
          rowSelection: {
            ...previousState.rowSelection,
            [rowId]: selected,
          },
        }),
        { type: "toggleRowSelected", id: rowId, value: selected },
      );
    },
    [updateState],
  );

  const table = useReactTable({
    data,
    columns: tanstackColumns,
    state: tableState,
    pageCount,
    manualPagination,
    manualFiltering: manualFilters,
    manualSorting: manualSortBy,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    enableRowSelection: (row) =>
      isRowSelectable({
        id: row.id,
        original: row.original,
      }),
    onPaginationChange: (updater) => {
      updateState(
        (previousState) => {
          const nextPagination =
            typeof updater === "function"
              ? updater(previousState.pagination)
              : updater;

          return {
            ...previousState,
            pagination: nextPagination,
          };
        },
        {
          type:
            typeof updater === "function"
              ? "gotoPage"
              : updater.pageIndex !== tableState.pagination.pageIndex
                ? "gotoPage"
                : "setPageSize",
          pageIndex:
            typeof updater === "function"
              ? updater(tableState.pagination).pageIndex
              : updater.pageIndex,
        },
      );
    },
    onSortingChange: (updater) => {
      updateState(
        (previousState) => ({
          ...previousState,
          sorting:
            typeof updater === "function"
              ? updater(previousState.sorting)
              : updater,
        }),
        { type: "toggleSortBy" },
      );
    },
    onColumnFiltersChange: (updater) => {
      updateState(
        (previousState) => ({
          ...previousState,
          columnFilters:
            typeof updater === "function"
              ? updater(previousState.columnFilters)
              : updater,
        }),
        { type: "setFilter" },
      );
    },
    onRowSelectionChange: (updater) => {
      updateState(
        (previousState) => ({
          ...previousState,
          rowSelection:
            typeof updater === "function"
              ? updater(previousState.rowSelection)
              : updater,
        }),
        { type: "toggleRowSelected" },
      );
    },
    onExpandedChange: (updater) => {
      updateState(
        (previousState) => ({
          ...previousState,
          expanded:
            typeof updater === "function"
              ? updater(previousState.expanded)
              : updater,
        }),
        { type: "toggleRowExpanded" },
      );
    },
  });

  const toLegacyRow = React.useCallback(
    (row) => ({
      id: row.id,
      original: row.original,
      values: Object.fromEntries(
        legacyColumns.map((column) => [
          column.id,
          getLegacyRowValue(row.original, column),
        ]),
      ),
      isSelected: row.getIsSelected(),
      isExpanded: row.getIsExpanded(),
      getToggleRowSelectedProps: () => ({
        checked: row.getIsSelected(),
        onChange: (event) => row.toggleSelected(event.target.checked),
      }),
      getToggleRowExpandedProps: () => ({
        role: "button",
        tabIndex: 0,
        onClick: () => row.toggleExpanded(),
        onKeyDown: (event) => {
          if (event.key === "Enter" || event.key === " ") row.toggleExpanded();
        },
      }),
    }),
    [legacyColumns],
  );

  const pageRows = table.getRowModel().rows;
  const legacyPageRows = React.useMemo(
    () => pageRows.map((row) => toLegacyRow(row)),
    [pageRows, toLegacyRow],
  );

  const selectedFlatRows = React.useMemo(
    () => table.getSelectedRowModel().flatRows.map((row) => toLegacyRow(row)),
    [table, toLegacyRow],
  );

  React.useEffect(() => {
    if (!onSelectedRowChange) return;
    onSelectedRowChange(selectedFlatRows.map((row) => row.original));
  }, [onSelectedRowChange, selectedFlatRows]);

  const tableInstanceContext = React.useMemo(
    () => ({
      ...baseInstance,
      page: legacyPageRows,
      selectedFlatRows,
      toggleRowSelected,
    }),
    [baseInstance, legacyPageRows, selectedFlatRows, toggleRowSelected],
  );

  const renderHeaderContent = React.useCallback(
    (column) => {
      const Header = column?.Header;
      if (typeof Header === "function") {
        return (
          <Header
            selectedFlatRows={selectedFlatRows}
            toggleRowSelected={toggleRowSelected}
            page={legacyPageRows}
          />
        );
      }
      return Header;
    },
    [selectedFlatRows, toggleRowSelected, legacyPageRows],
  );

  const renderFooterContent = React.useCallback((column) => {
    const Footer = column?.Footer;
    if (typeof Footer === "function") return <Footer />;
    return Footer;
  }, []);

  const footerAvailable = legacyColumns.some((column) => !!column.Footer);

  const preFilteredRows = React.useMemo(
    () =>
      data.map((rowObj) => ({
        values: Object.fromEntries(
          legacyColumns.map((column) => [
            column.id,
            getLegacyRowValue(rowObj, column),
          ]),
        ),
      })),
    [data, legacyColumns],
  );

  const getFilterElement = React.useCallback(
    (column) => {
      if (!column?.Filter || !config.enableFilters) return null;

      const filterValue =
        tableState.columnFilters.find((filter) => filter.id === column.id)
          ?.value || "";

      return (
        <column.Filter
          column={{
            ...column,
            id: column.id,
            filterValue,
            preFilteredRows,
            setFilter: (value) => {
              table.getColumn(column.id)?.setFilterValue(value);
            },
          }}
        />
      );
    },
    [config.enableFilters, preFilteredRows, table, tableState.columnFilters],
  );

  const getCellContent = React.useCallback(
    (cell, legacyRow) => {
      const legacyColumn = cell.column.columnDef.meta?.legacyColumn;
      const cellValue = cell.getValue();
      if (typeof legacyColumn?.Cell === "function") {
        return legacyColumn.Cell({
          value: cellValue,
          row: legacyRow,
          column: legacyColumn,
          instance: tableInstanceContext,
        });
      }
      return cellValue;
    },
    [tableInstanceContext],
  );

  const getRowProps = React.useCallback(
    (legacyRow) => {
      let rowProps = { key: legacyRow.id };
      hookRegistry.getRowProps.forEach((getProps) => {
        const output = getProps(rowProps, { row: legacyRow });
        if (Array.isArray(output)) {
          const [, extraProps] = output;
          rowProps = { ...rowProps, ...extraProps };
        }
      });
      return rowProps;
    },
    [hookRegistry],
  );

  const pageOptions = React.useMemo(
    () => Array.from({ length: table.getPageCount() }, (_, index) => index),
    [table],
  );

  const tableBody = TableBodyComponent ? (
    <TableBodyComponent page={legacyPageRows} />
  ) : (
    pageRows.map((row) => {
      const legacyRow = toLegacyRow(row);
      const { key, ...rowProps } = getRowProps(legacyRow);

      return (
        <React.Fragment key={key}>
          <tr
            {...rowProps}
            className={classnames(rowProps.className, {
              "row-selected": legacyRow.isSelected,
            })}
          >
            {row.getVisibleCells().map((cell) => (
              <td key={cell.id} className="text-center">
                {getCellContent(cell, legacyRow)}
              </td>
            ))}
          </tr>
          {SubComponent && config?.enableExpanded && legacyRow?.isExpanded && (
            <tr>
              <td colSpan={table.getVisibleLeafColumns().length}>
                <SubComponent row={legacyRow} />
              </td>
            </tr>
          )}
        </React.Fragment>
      );
    })
  );

  return (
    <div>
      <Table striped hover responsive="xl" {...tableProps}>
        <thead>
          {table.getHeaderGroups().map((headerGroup) => (
            <tr className="head-row" key={headerGroup.id}>
              {headerGroup.headers.map((header) => {
                const legacyColumn = header.column.columnDef.meta?.legacyColumn;
                const sortState = header.column.getIsSorted();
                const canSort =
                  config.enableSortBy && header.column.getCanSort();

                return (
                  <th
                    key={header.id}
                    className={sortState ? "text-primary" : ""}
                    style={{
                      width: legacyColumn?.maxWidth
                        ? `${legacyColumn.maxWidth}px`
                        : undefined,
                      maxWidth: legacyColumn?.maxWidth
                        ? `${legacyColumn.maxWidth}px`
                        : undefined,
                    }}
                  >
                    {/* role, tabIndex, and click handler are applied together only when sortable */}
                    {/* eslint-disable-next-line jsx-a11y/no-static-element-interactions */}
                    <div
                      className="text-center"
                      role={canSort ? "button" : undefined}
                      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
                      tabIndex={canSort ? 0 : undefined}
                      onClick={
                        canSort
                          ? header.column.getToggleSortingHandler()
                          : undefined
                      }
                      onKeyDown={
                        canSort
                          ? (event) => {
                              if (event.key === "Enter" || event.key === " ") {
                                header.column.toggleSorting();
                              }
                            }
                          : undefined
                      }
                    >
                      {renderHeaderContent(legacyColumn)}
                      {canSort &&
                        (sortState ? (
                          sortState === "desc" ? (
                            <FaSortDown />
                          ) : (
                            <FaSortUp />
                          )
                        ) : (
                          <FaSort className="text-muted small" />
                        ))}
                    </div>
                    <div className="d-flex mt-1">
                      {getFilterElement(legacyColumn)}
                    </div>
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {pageRows?.length ? (
            tableBody
          ) : (
            <tr>
              <td
                colSpan={table.getVisibleLeafColumns().length || 1}
                className="text-large fw-bold text-center"
              >
                {tableEmptyNode}
              </td>
            </tr>
          )}
        </tbody>
        {footerAvailable && (
          <tfoot>
            {table.getFooterGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((header) => (
                  <th key={header.id}>
                    {renderFooterContent(
                      header.column.columnDef.meta?.legacyColumn,
                    )}
                  </th>
                ))}
              </tr>
            ))}
          </tfoot>
        )}
      </Table>
      {pageOptions.length > 1 && (
        <Paginator
          pageIndex={table.getState().pagination.pageIndex}
          pageOptions={pageOptions}
          onPaginate={(nextPage) => table.setPageIndex(nextPage)}
          className="table-paginator"
        />
      )}
    </div>
  );
}

export default DataTable;
