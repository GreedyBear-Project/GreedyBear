import React from "react";
import { useNavigate } from "react-router-dom";
import {
  Container,
  Button,
  Col,
  Input,
  Label,
  FormGroup,
  Row,
} from "reactstrap";
import { MdFilterAltOff } from "react-icons/md";
import { Form, Formik } from "formik";
import { HONEYPOT_URI, PAYLOADS_BASE_URI } from "../../constants/api";
import {
  ContentSection,
  Select,
  useAxiosComponentLoader,
  useDataTable,
} from "../common/gb-ui/index";
import { payloadsTableColumns } from "./tableColumns";
import { useAuthStore } from "../../stores";

const DEFAULT_VALUES = Object.freeze({
  search: "",
  mime_type: "",
  honeypot: "",
});

const tableEmptyNode = (
  <>
    <h4>No Data</h4>
    <small className="text-muted">Note: Try changing filter.</small>
  </>
);

const buildParams = (values) => {
  const params = {};
  Object.entries(values).forEach(([key, value]) => {
    const trimmed = (value || "").trim();
    if (trimmed) params[key] = trimmed;
  });
  return params;
};

// child component so useDataTable hooks live here; changing `key` remounts it.
function PayloadsTable({ tableParams, canDownload, onDataLoad }) {
  const toPassTableProps = React.useMemo(
    () => ({ columns: payloadsTableColumns(canDownload), tableEmptyNode }),
    [canDownload],
  );

  const [payloadsData, tableNode] = useDataTable(
    {
      url: PAYLOADS_BASE_URI,
      params: tableParams,
      initialParams: { page: "1" },
    },
    toPassTableProps,
    (data) => data.results,
  );

  React.useEffect(() => {
    if (onDataLoad) onDataLoad(payloadsData);
  }, [payloadsData, onDataLoad]);

  return <>{tableNode}</>;
}

function Payloads() {
  const canDownload = useAuthStore(
    React.useCallback((s) => s.canDownloadPayloads, []),
  );

  const navigate = useNavigate();
  const formikRef = React.useRef(null);
  const [tableState, setTableState] = React.useState({
    tableParams: {},
    tableKey: 0,
  });
  const [payloadsData, setPayloadsData] = React.useState(null);

  const [honeypots, Loader] = useAxiosComponentLoader({
    url: `${HONEYPOT_URI}?only_active=true`,
    headers: { "Content-Type": "application/json" },
  });

  const honeypotChoices = React.useMemo(
    () => [
      { label: "All", value: "" },
      ...honeypots.map((honeypot) => ({ label: honeypot, value: honeypot })),
    ],
    [honeypots],
  );

  const onSubmit = React.useCallback((values) => {
    navigate({ search: "" }, { replace: true });
    setTableState((prev) => ({
      tableParams: buildParams(values),
      tableKey: prev.tableKey + 1,
    }));
  }, [navigate]);

  const isDefault = Object.keys(tableState.tableParams).length === 0;

  return (
    <Container>
      <div className="d-flex justify-content-between">
        <h1>
          Payloads&nbsp;
          <small className="text-muted">{payloadsData?.count} total</small>
        </h1>
      </div>
      <ContentSection>
        <Row className="mb-4 mt-2">
          <Col sm={12}>
            <Loader
              render={() => (
                <Formik
                  initialValues={DEFAULT_VALUES}
                  onSubmit={onSubmit}
                  innerRef={formikRef}
                >
                  {(formik) => (
                    <Form>
                      <FormGroup row className="align-items-end">
                        <Col sm={12} md>
                          <Label
                            className="form-control-label"
                            htmlFor="Payloads__search"
                          >
                            Hash:
                          </Label>
                          <Input
                            id="Payloads__search"
                            name="search"
                            value={formik.values.search}
                            placeholder="SHA256, SHA1 or MD5"
                            onChange={formik.handleChange}
                          />
                        </Col>
                        <Col sm={12} md>
                          <Label
                            className="form-control-label"
                            htmlFor="Payloads__mime_type"
                          >
                            MIME type:
                          </Label>
                          <Input
                            id="Payloads__mime_type"
                            name="mime_type"
                            value={formik.values.mime_type}
                            placeholder="e.g. application/x-dosexec"
                            onChange={formik.handleChange}
                          />
                        </Col>
                        <Col sm={12} md>
                          <Label
                            className="form-control-label"
                            htmlFor="Payloads__honeypot"
                          >
                            Honeypot:
                          </Label>
                          <Select
                            id="Payloads__honeypot"
                            name="honeypot"
                            value={formik.values.honeypot}
                            choices={honeypotChoices}
                            onChange={async (e) => {
                              await formik.setFieldValue(
                                "honeypot",
                                e.target.value,
                                true,
                              );
                              await formik.submitForm();
                            }}
                          />
                        </Col>
                        <Col sm={12} md="auto">
                          <Button type="submit" color="primary">
                            Search
                          </Button>
                          &nbsp;
                          <Button
                            color="primary"
                            outline
                            disabled={isDefault}
                            title="Reset filters"
                            aria-label="Reset filters"
                            onClick={() => {
                              formik.resetForm({ values: DEFAULT_VALUES });
                              onSubmit(DEFAULT_VALUES);
                            }}
                          >
                            <MdFilterAltOff />
                          </Button>
                        </Col>
                      </FormGroup>
                    </Form>
                  )}
                </Formik>
              )}
            />
          </Col>
        </Row>
        <PayloadsTable
          key={tableState.tableKey}
          tableParams={tableState.tableParams}
          canDownload={canDownload}
          onDataLoad={setPayloadsData}
        />
      </ContentSection>
    </Container>
  );
}

export default Payloads;
