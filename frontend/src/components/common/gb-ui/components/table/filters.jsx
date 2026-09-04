/* eslint-disable */
import React from "react";
import classnames from "classnames";
import { Input } from "reactstrap";

// Define a default UI for filtering
function DefaultColumnFilter({ column: { filterValue, setFilter, id } }) {
  // state
  const [inputValue, setInputValue] = React.useState(
    filterValue !== undefined ? filterValue : "",
  );

  return (
    <Input
      id={`datatable-select-${id}`}
      type="search"
      bsSize="sm"
      className={classnames(
        {
          "bg-body border-secondary": filterValue,
        },
        "input-dark",
      )}
      value={inputValue}
      onChange={(e) => {
        setInputValue(e.target.value);
        // if the user clears the filter
        if (e.target.value.length === 0) {
          // Set undefined to remove the filter entirely
          setFilter(undefined);
        }
      }}
      onKeyDown={(e) => {
        // the request is sent if the user presses 'enter'
        if (e.key === "Enter") {
          setFilter(e.target.value || undefined);
        }
      }}
      onKeyUp={(e) => {
        // if the user presses 'backspace'
        // the request is sent if input value is empty
        if (e.key === "Backspace" && e.target.value.length === 0) {
          // Set undefined to remove the filter entirely
          setFilter(undefined);
        }
      }}
      onPaste={(e) => {
        // if copy-paste is done, the request is sent automatically
        setFilter(e.clipboardData.getData("text/plain") || undefined);
      }}
      placeholder="Search keyword.."
    />
  );
}

// This is a custom filter UI for selecting
// a unique option from a list
function SelectColumnFilter({
  column: {
    filterValue,
    setFilter,
    preFilteredRows,
    id,
    filterValueAccessorFn,
  },
}) {
  // Calculate the options for filtering
  // using the preFilteredRows
  const options = React.useMemo(() => {
    const optionsSet = new Set();
    preFilteredRows.forEach((row) => {
      const value = row.values[id];
      if (value) {
        const optVal = filterValueAccessorFn
          ? filterValueAccessorFn(value)
          : value;
        if (Array.isArray(optVal)) {
          optVal.forEach((v) => optionsSet.add(v));
        } else {
          optionsSet.add(optVal);
        }
      }
    });
    return [...optionsSet.values()];
  }, [id, preFilteredRows, filterValueAccessorFn]);

  // Set undefined to remove the filter entirely
  const onChange = (e) => setFilter(e.target.value || undefined);

  // Render a multi-select box
  return (
    <Input
      id={`datatable-select-${id}`}
      type="select"
      className="custom-select-sm input-dark"
      value={filterValue}
      onChange={onChange}
    >
      <option value="">All</option>
      {options.sort().map((value) => (
        <option key={`datatable-select-${id}-option-${value}`} value={value}>
          {value}
        </option>
      ))}
    </Input>
  );
}

// This is a custom filter UI for selecting
// a unique option from a list
function SelectOptionsFilter({
  column: { filterValue, setFilter, id, selectOptions },
}) {
  const onChange = (e) => setFilter(e.target.value || undefined); // Set undefined to remove the filter entirely

  return (
    <Input
      id={`datatable-select-${id}`}
      type="select"
      className={classnames(
        {
          "bg-body border-secondary": filterValue,
        },
        "custom-select-sm input-dark",
      )}
      value={filterValue}
      onChange={onChange}
    >
      <option value="">All</option>
      {selectOptions.map((value) => (
        <option key={`datatable-select-${id}-option-${value}`} value={value}>
          {value}
        </option>
      ))}
    </Input>
  );
}

// This is a custom filter UI that uses a
// slider to set the filter value between a column's
// min and max values
function SliderColumnFilter({
  column: { filterValue, setFilter, preFilteredRows, id },
}) {
  const [min, max] = [0, 100];
  const value = filterValue || min;

  return (
    <div className="mx-auto text-center">
      <div className="text-info">{`>=${value}`}</div>
      <Input
        id={`datatable-select-${id}`}
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(e) => setFilter(parseInt(e.target.value, 10))}
      />
    </div>
  );
}

export {
  DefaultColumnFilter,
  SelectOptionsFilter,
  SelectColumnFilter,
  SliderColumnFilter,
};
