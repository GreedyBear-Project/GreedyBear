import React from "react";
import { FormGroup, Input, UncontrolledTooltip, Label } from "reactstrap";

import ArrowToggleIcon from "../icons/ArrowToggleIcon";

// hooks factory

export const createUseRowDisabledHook = (hocProps) => (hooks) => {
  // HoC Props
  const { objectName, onChange } = hocProps;

  hooks.getRowProps.push((props, { row }) => [
    props,
    {
      title: !row.original?.enabled
        ? `This ${objectName} was marked as disabled by it's owner.`
        : "",
      className: !row.original?.enabled ? "row-disabled" : "",
    },
  ]);

  hooks.visibleColumns.push((columns, { instance }) => [
    {
      id: "data-table-disabled_row_action",
      width: 80,
      Cell: ({ row: { original: obj } }) =>
        obj?.permissions?.edit ? (
          <>
            <FormGroup switch id={`toggle-enable-switch__${obj?.id}`}>
              <Input
                type="checkbox"
                name="ruleEnabled"
                className={obj?.enabled ? "row-disabled" : ""}
                defaultChecked={obj?.enabled}
                onChange={async () => {
                  await onChange(obj?.id, !obj?.enabled);
                  instance?.customProps?.refetchTableData();
                }}
              />
            </FormGroup>
            <UncontrolledTooltip target={`toggle-enable-switch__${obj?.id}`}>
              {obj?.enabled ? "Disable" : "Enable"} {objectName}
            </UncontrolledTooltip>
          </>
        ) : null,
    },
    ...columns,
  ]);
};

export const rowSelectHooks = [
  (hooks) => {
    hooks.visibleColumns.push((columns, { instance: { isRowSelectable } }) => [
      {
        id: "data-table_row-selection",
        maxWidth: 80,
        // The header can use the table's getToggleAllRowsSelectedProps method
        // to render a checkbox
        Header: ({ selectedFlatRows, toggleRowSelected, page: pageRows }) => {
          const selectableRows = React.useMemo(
            () => pageRows.filter((r) => isRowSelectable(r)),
            [pageRows],
          );
          const onChange = React.useCallback(
            (e) =>
              e.target.checked
                ? selectableRows.forEach((r) => toggleRowSelected(r.id, true))
                : selectableRows.forEach((r) => toggleRowSelected(r.id, false)),
            [selectableRows, toggleRowSelected],
          );
          return selectableRows.length ? (
            <div
              className="d-flex flex-column"
              title="Toggle selection for all row objects you have ownership for"
            >
              <h6 className="text-muted">{selectedFlatRows.length} selected</h6>
              <IndeterminateCheckbox
                id="data-table-checkbox_header"
                indeterminate={
                  selectedFlatRows.length > 0 &&
                  selectableRows.length !== selectedFlatRows.length
                }
                checked={
                  selectableRows.length > 0 &&
                  selectableRows.length === selectedFlatRows.length
                }
                onChange={onChange}
              />
            </div>
          ) : null;
        },
        Cell: ({ row }) =>
          isRowSelectable(row) ? (
            <IndeterminateCheckbox
              id={`data-table-checkbox_cell_${row.id}`}
              {...row.getToggleRowSelectedProps()}
            />
          ) : null,
      },
      ...columns,
    ]);
  },
];

export const rowExpandHooks = [
  (hooks) => {
    hooks.visibleColumns.push((columns) => [
      {
        Header: () => null,
        id: "data-table-row_expand",
        maxWidth: 60,
        Cell: ({ row }) => (
          // Use Cell to render an expander for each row.
          // We can use the getToggleRowExpandedProps prop-getter
          // to build the expander.
          <span {...row.getToggleRowExpandedProps()}>
            <ArrowToggleIcon isExpanded={!!row?.isExpanded} />
          </span>
        ),
      },
      ...columns,
    ]);
  },
];

// components

const IndeterminateCheckbox = React.forwardRef(
  ({ id, indeterminate, label, ...rest }, ref) => {
    const defaultRef = React.useRef();
    const resolvedRef = ref || defaultRef;

    React.useEffect(() => {
      if (resolvedRef?.current)
        resolvedRef.current.indeterminate = indeterminate;
    }, [resolvedRef, indeterminate]);

    return (
      <FormGroup check className="d-flex justify-content-center mt-2">
        <Input id={id} type="checkbox" innerRef={resolvedRef} {...rest} />
        {label && <Label check>{label}</Label>}
      </FormGroup>
    );
  },
);
