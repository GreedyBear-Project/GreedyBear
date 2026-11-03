import React from "react";
import {
  Alert,
  Badge,
  Button,
  Container,
  Input,
  Spinner,
  Table,
} from "reactstrap";
import { PAYLOADS_BASE_URI } from "../../constants/api";

const PAGE_SIZE = 10;

function Payloads() {
  const [payloads, setPayloads] = React.useState([]);
  const [search, setSearch] = React.useState("");
  const [mimeType, setMimeType] = React.useState("");
  const [honeypot, setHoneypot] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [count, setCount] = React.useState(0);
  const [totalPages, setTotalPages] = React.useState(1);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    const controller = new AbortController();

    async function loadPayloads() {
      setLoading(true);
      setError("");

      try {
        const params = new URLSearchParams({
          page: String(page),
          page_size: String(PAGE_SIZE),
        });

        if (search.trim()) params.set("search", search.trim());
        if (mimeType.trim()) params.set("mime_type", mimeType.trim());
        if (honeypot.trim()) params.set("honeypot", honeypot.trim());

        const response = await fetch(
          `${PAYLOADS_BASE_URI}?${params.toString()}`,
          {
            credentials: "include",
            signal: controller.signal,
          },
        );

        if (!response.ok) {
          throw new Error(`Failed to load payloads (${response.status})`);
        }

        const data = await response.json();

        setPayloads(data.results || []);
        setCount(data.count ?? 0);
        setTotalPages(data.total_pages ?? 1);
      } catch (err) {
        if (err.name !== "AbortError") {
          setError(err.message || "Unable to load payloads.");
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }

    loadPayloads();
    return () => controller.abort();
  }, [search, mimeType, honeypot, page]);

  function resetFilters() {
    setSearch("");
    setMimeType("");
    setHoneypot("");
    setPage(1);
  }

  return (
    <Container className="mt-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h1>Payloads</h1>
          <small className="text-muted">
            {count.toLocaleString()} payloads found
          </small>
        </div>
      </div>

      <div className="row g-3 mb-4">
        <div className="col-12 col-md-4">
          <label htmlFor="payload-search" className="form-label">
            Search hash
          </label>
          <Input
            id="payload-search"
            value={search}
            placeholder="SHA256, SHA1 or MD5"
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(1);
            }}
          />
        </div>

        <div className="col-12 col-md-3">
          <label htmlFor="payload-mime" className="form-label">
            MIME type
          </label>
          <Input
            id="payload-mime"
            value={mimeType}
            placeholder="e.g. application/octet-stream"
            onChange={(event) => {
              setMimeType(event.target.value);
              setPage(1);
            }}
          />
        </div>

        <div className="col-12 col-md-3">
          <label htmlFor="payload-honeypot" className="form-label">
            Source honeypot
          </label>
          <Input
            id="payload-honeypot"
            value={honeypot}
            placeholder="Exact honeypot name"
            onChange={(event) => {
              setHoneypot(event.target.value);
              setPage(1);
            }}
          />
        </div>

        <div className="col-12 col-md-2 d-flex align-items-end">
          <Button
            color="secondary"
            outline
            className="w-100"
            onClick={resetFilters}
          >
            Reset filters
          </Button>
        </div>
      </div>

      {loading && (
        <div className="text-center my-5">
          <Spinner />
          <div className="mt-2">Loading payloads...</div>
        </div>
      )}

      {error && <Alert color="danger">{error}</Alert>}

      {!loading && !error && (
        <>
          <div className="table-responsive">
            <Table bordered hover responsive={false}>
              <thead>
                <tr>
                  <th>SHA256</th>
                  <th>MIME Type</th>
                  <th>Size</th>
                  <th>Source Honeypot</th>
                  <th>Details</th>
                  <th>Download</th>
                </tr>
              </thead>
              <tbody>
                {payloads.length === 0 ? (
                  <tr>
                    <td colSpan="6" className="text-center py-4">
                      No payloads found.
                    </td>
                  </tr>
                ) : (
                  payloads.map((payload) => (
                    <tr key={payload.id ?? payload.sha256}>
                      <td>
                        <code>{payload.sha256 || "-"}</code>
                      </td>
                      <td>
                        <Badge color="secondary">
                          {payload.mime_type || "-"}
                        </Badge>
                      </td>
                      <td>
                        {payload.size != null
                          ? `${Number(payload.size).toLocaleString()} bytes`
                          : "-"}
                      </td>
                      <td>
                        {payload.source_honeypots?.length
                          ? payload.source_honeypots.join(", ")
                          : "-"}
                      </td>
                      <td>
                        <details>
                          <summary>View details</summary>
                          <div className="small mt-2">
                            <div>
                              <strong>MD5:</strong> {payload.md5 || "-"}
                            </div>
                            <div>
                              <strong>SHA1:</strong> {payload.sha1 || "-"}
                            </div>
                            <div>
                              <strong>IOCs:</strong>{" "}
                              {payload.iocs?.length
                                ? payload.iocs.join(", ")
                                : "-"}
                            </div>
                            <div>
                              <strong>Cowrie sessions:</strong>{" "}
                              {payload.cowrie_sessions?.length
                                ? payload.cowrie_sessions.join(", ")
                                : "-"}
                            </div>
                          </div>
                        </details>
                      </td>
                      <td>
                        <Button
                          color="primary"
                          size="sm"
                          href={`${PAYLOADS_BASE_URI}/${encodeURIComponent(
                            payload.sha256 || "",
                          )}/download`}
                        >
                          Download
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </Table>
          </div>

          <div className="d-flex justify-content-between align-items-center my-3">
            <Button
              color="secondary"
              outline
              disabled={page <= 1}
              onClick={() => setPage((current) => Math.max(1, current - 1))}
            >
              Previous
            </Button>

            <span>
              Page {page}
              {count > 0 ? ` of ${totalPages}` : ""}
            </span>

            <Button
              color="secondary"
              outline
              disabled={page >= totalPages}
              onClick={() => setPage((current) => current + 1)}
            >
              Next
            </Button>
          </div>
        </>
      )}
    </Container>
  );
}

export default Payloads;
