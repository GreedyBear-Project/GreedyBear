import { UncontrolledPopover, PopoverBody, Button } from "reactstrap";
import { FiInfo } from "react-icons/fi";
import { IconButton } from "../common/gb-ui/index";
import { PAYLOADS_BASE_URI } from "../../constants/api";

const joinOrDash = (list) => (list?.length ? list.join(", ") : "-");

const payloadsTableColumns = (canDownload) => [
  {
    Header: "SHA256",
    accessor: "sha256",
    disableSortBy: true,
    Cell: ({ value }) => <code>{value || "-"}</code>,
  },
  {
    Header: "MIME Type",
    accessor: "mime_type",
    disableSortBy: true,
    maxWidth: 160,
  },
  {
    Header: "Size",
    accessor: "size",
    disableSortBy: true,
    maxWidth: 110,
    Cell: ({ value }) =>
      value != null ? `${Number(value).toLocaleString()} B` : "-",
  },
  {
    Header: "Source Honeypots",
    accessor: "source_honeypots",
    disableSortBy: true,
    maxWidth: 160,
    Cell: ({ value }) => joinOrDash(value),
  },
  {
    Header: "Details",
    id: "details",
    disableSortBy: true,
    maxWidth: 75,
    Cell: ({ row }) => {
      const { md5, sha1, iocs, cowrie_sessions } = row.original;
      const popoverId = `payloads-details-${row.id}`;
      return (
        <div className="d-flex justify-content-center">
          <IconButton
            id={popoverId}
            color="light"
            outline
            size="xs"
            Icon={FiInfo}
            aria-label="View details"
          />
          <UncontrolledPopover
            trigger="focus"
            target={popoverId}
            placement="left"
          >
            <PopoverBody className="small">
              <div>MD5: {md5 || "-"}</div>
              <div>SHA1: {sha1 || "-"}</div>
              <div>IOCs: {joinOrDash(iocs)}</div>
              <div>Cowrie sessions: {joinOrDash(cowrie_sessions)}</div>
            </PopoverBody>
          </UncontrolledPopover>
        </div>
      );
    },
  },
  ...(canDownload
    ? [
        {
          Header: "Download",
          id: "download",
          disableSortBy: true,
          maxWidth: 110,
          Cell: ({ row }) => (
            <Button
              color="primary"
              size="sm"
              href={`${PAYLOADS_BASE_URI}/${encodeURIComponent(row.original.sha256 || "")}/download`}
            >
              Download
            </Button>
          ),
        },
      ]
    : []),
];

export { payloadsTableColumns };
