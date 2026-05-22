import { UncontrolledPopover, PopoverBody } from "reactstrap";
import { FiInfo } from "react-icons/fi";
import { BooleanIcon, IconButton } from "@greedybear/gb-ui";
import { INTELOWL_URL, PUBLIC_URL } from "../../constants/environment";

const formatInteger = (value) => {
  if (value === null || value === undefined || Number.isNaN(value)) return "-";
  return Number(value).toLocaleString();
};

// required for recurrence value
const formatPercent = (value) => {
  if (value === null || value === undefined || Number.isNaN(value)) return "-";
  return `${(Number(value) * 100).toFixed(1)}%`;
};

// constants
const feedsTableColumns = [
  {
    Header: "Last Seen",
    accessor: "last_seen",
    maxWidth: 100,
  },
  {
    Header: "First Seen",
    accessor: "first_seen",
    maxWidth: 100,
  },
  {
    Header: "Value",
    accessor: "value",
    maxWidth: 170,
  },
  {
    Header: "Feed type",
    accessor: "feed_type",
    disableSortBy: true,
    maxWidth: 130,
    Cell: ({ value }) =>
      Array.isArray(value) ? (
        <ul className="d-flex flex-column text-left" key={value}>
          {value?.map((val, index) => (
            <li className="mb-1 pb-2" key={index}>
              <div className="d-flex align-items-start">{val}</div>
            </li>
          ))}
        </ul>
      ) : (
        <div>{value}</div>
      ),
  },
  {
    Header: "Scanner",
    accessor: "scanner",
    Cell: ({ value }) => <BooleanIcon truthy={value} withColors />,
    maxWidth: 90,
  },
  {
    Header: "Payload Request",
    accessor: "payload_request",
    Cell: ({ value }) => <BooleanIcon truthy={value} withColors />,
    maxWidth: 130,
  },
  {
    Header: "Attack Count",
    accessor: "attack_count",
    maxWidth: 110,
  },
  {
    Header: "Details",
    accessor: "details",
    disableSortBy: true,
    Cell: ({ row }) => {
      const {
        recurrence_probability,
        expected_interactions,
        interaction_count,
        destination_port_count,
        login_attempts,
        asn,
        ip_reputation,
        attacker_country,
      } = row.original;
      const popoverId = `feeds-details-${row.id}`;
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
            className="feeds-details-popover"
          >
            <PopoverBody className="small">
              <div className="text-muted">Scores</div>
              <div>Recurrence: {formatPercent(recurrence_probability)}</div>
              <div>
                Expected Interactions:{" "}
                {formatInteger(
                  expected_interactions != null
                    ? Math.round(expected_interactions)
                    : null,
                )}
              </div>
              <hr className="my-2" />
              <div className="text-muted">Activity</div>
              <div>Interactions: {formatInteger(interaction_count)}</div>
              <div>Ports: {formatInteger(destination_port_count)}</div>
              <div>Logins: {formatInteger(login_attempts)}</div>
              <hr className="my-2" />
              <div className="text-muted">Enrichment</div>
              <div>ASN: {asn ?? "-"}</div>
              <div>Reputation: {ip_reputation || "-"}</div>
              <div>Country: {attacker_country || "-"}</div>
            </PopoverBody>
          </UncontrolledPopover>
        </div>
      );
    },
    maxWidth: 75,
  },
  ...(INTELOWL_URL
    ? [
        {
          Header: "Analyze",
          id: "intelowl",
          disableSortBy: true,
          maxWidth: 80,
          Cell: ({ row }) => (
            <div className="d-flex justify-content-center">
              <a
                href={`${INTELOWL_URL}/scan?observable_name=${encodeURIComponent(row.original.value)}`}
                target="_blank"
                rel="noopener noreferrer"
                title={`Analyze ${row.original.value} on IntelOwl`}
              >
                <img
                  src={`${PUBLIC_URL}/intelowl.png`}
                  alt="IntelOwl"
                  height="30"
                  style={{ opacity: 0.85 }}
                />
              </a>
            </div>
          ),
        },
      ]
    : []),
];

export { feedsTableColumns };
