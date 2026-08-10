import { useMemo, useState } from "react";

import DataTable from "../../src/components/common/gb-ui/components/table/DataTable";
import {
  DefaultColumnFilter,
  SelectOptionsFilter,
} from "../../src/components/common/gb-ui/components/table/filters";
import { createUseRowDisabledHook } from "../../src/components/common/gb-ui/components/table/hooks";
import BooleanIcon from "../../src/components/common/gb-ui/components/icons/BooleanIcon";
import {
  disabledRowFixtureRows,
  tableFixtureRows,
} from "./fixtures/tableFixtures";

const ownerOptions = ["Atlas", "Beacon", "Cypher"];
const initialState = { pageSize: 5 };

const columns = [
  { Header: "#", accessor: "id", Filter: () => null, maxWidth: 20 },
  { Header: "Title", accessor: "title", Filter: DefaultColumnFilter },
  {
    Header: "Owner",
    accessor: "owner",
    Filter: SelectOptionsFilter,
    selectOptions: ownerOptions,
  },
  {
    Header: "Completed",
    accessor: "completed",
    Filter: SelectOptionsFilter,
    selectOptions: ["true", "false"],
    disableSortBy: true,
    Cell: ({ value }) => <BooleanIcon truthy={value} />,
    maxWidth: 40,
  },
];

function TableDetails({ row }) {
  return (
    <div
      className="p-3 text-start"
      data-testid={`expanded-row-${row.original.id}`}
    >
      <strong>{`Details for ${row.original.title}`}</strong>
      <div className="mt-2 text-muted">{`Owned by ${row.original.owner}`}</div>
      <div className="small mt-1">{`Completed: ${row.original.completed}`}</div>
    </div>
  );
}

function InteractiveFixtureTable() {
  const [selectedRows, setSelectedRows] = useState([]);

  return (
    <section data-testid="table-visual-interactive">
      <div className="d-flex align-items-center justify-content-between mb-3">
        <span className="text-muted small">
          Deterministic local fixtures for visual regression coverage.
        </span>
        <small data-testid="table-visual-selected-count">
          {`${selectedRows.length} selected`}
        </small>
      </div>
      <DataTable
        data={tableFixtureRows}
        columns={columns}
        config={{
          enableFilters: true,
          enableSortBy: true,
          enableFlexLayout: true,
          enableSelection: true,
          enableExpanded: true,
        }}
        initialState={initialState}
        onSelectedRowChange={setSelectedRows}
        isRowSelectable={(row) => !row.original.completed}
        SubComponent={TableDetails}
      />
    </section>
  );
}

function DisabledRowFixtureTable() {
  const [rows, setRows] = useState(disabledRowFixtureRows);
  const disabledHook = useMemo(
    () =>
      createUseRowDisabledHook({
        objectName: "rule",
        onChange: async (id, enabled) => {
          setRows((currentRows) =>
            currentRows.map((row) =>
              row.id === id ? { ...row, enabled } : row,
            ),
          );
        },
      }),
    [],
  );

  return (
    <section data-testid="table-visual-disabled">
      <DataTable
        data={rows}
        columns={columns}
        config={{
          enableFilters: true,
          enableSortBy: true,
          enableFlexLayout: true,
          customHooks: [disabledHook],
        }}
        initialState={initialState}
        customProps={{ refetchTableData: () => undefined }}
      />
    </section>
  );
}

function EmptyFixtureTable() {
  return (
    <section data-testid="table-visual-empty">
      <DataTable
        data={[]}
        columns={columns}
        config={{
          enableFilters: true,
          enableSortBy: true,
          enableFlexLayout: true,
        }}
        initialState={initialState}
        tableEmptyNode="No fixture rows available"
      />
    </section>
  );
}

export default function TableVisualFixture() {
  return (
    <main className="container py-4">
      <h1>Table</h1>
      <InteractiveFixtureTable />
      <DisabledRowFixtureTable />
      <EmptyFixtureTable />
    </main>
  );
}
