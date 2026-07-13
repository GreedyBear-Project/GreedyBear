import React from "react";
import {
  Container,
  Row,
  Col,
  FormGroup,
  Label,
  Button,
  Badge,
} from "reactstrap";

import {
  ContentSection,
  Select,
  useAxiosComponentLoader,
} from "@greedybear/gb-ui";

import { FEEDS_TRENDING_URI, GENERAL_HONEYPOT_URI } from "../../constants/api";
import { MultiSelectDropdown } from "./MultiSelectDropdown";

const DEFAULT_PARAMS = Object.freeze({
  feed_type: "all",
  window_minutes: "60",
  limit: "10",
});

function TrendDeltaBadge({ delta }) {
  if (!Number.isFinite(delta)) {
    return <Badge color="secondary">-</Badge>;
  }

  const color = delta > 0 ? "danger" : delta < 0 ? "success" : "secondary";
  const prefix = delta > 0 ? "+" : "";
  return <Badge color={color}>{`${prefix}${delta}`}</Badge>;
}

const windowChoices = [
  { label: "1 hour", value: "60" },
  { label: "2 hours", value: "120" },
  { label: "4 hours", value: "240" },
  { label: "8 hours", value: "480" },
  { label: "24 hours", value: "1440" },
];

const limitChoices = [
  { label: "10 attackers", value: "10" },
  { label: "25 attackers", value: "25" },
  { label: "50 attackers", value: "50" },
  { label: "100 attackers", value: "100" },
];

function formatWindowDate(value) {
  if (!value) return "";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  return `${new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

function formatGrowthScore(value) {
  const score = Number(value);
  return Number.isFinite(score) ? score.toFixed(2) : "-";
}

export default function FeedsTrending() {
  const [params, setParams] = React.useState(DEFAULT_PARAMS);
  const [draft, setDraft] = React.useState(DEFAULT_PARAMS);
  const draftRef = React.useRef(DEFAULT_PARAMS);

  const [honeypots, HoneypotLoader] = useAxiosComponentLoader({
    url: `${GENERAL_HONEYPOT_URI}?onlyActive=true`,
    headers: { "Content-Type": "application/json" },
  });

  const [payload, Loader, refetchTrending] = useAxiosComponentLoader({
    url: FEEDS_TRENDING_URI,
    params,
    headers: { "Content-Type": "application/json" },
  });

  const onChange = React.useCallback((event) => {
    const { name, value } = event.target;
    setDraft((current) => {
      const nextDraft = { ...current, [name]: value };
      draftRef.current = nextDraft;
      return nextDraft;
    });
  }, []);

  const onSubmit = React.useCallback(
    (event) => {
      event.preventDefault();
      const submittedDraft = draftRef.current;

      if (JSON.stringify(submittedDraft) === JSON.stringify(params)) {
        refetchTrending();
        return;
      }

      setParams({ ...submittedDraft });
    },
    [params, refetchTrending],
  );

  const honeypotFeedType = React.useMemo(
    () =>
      honeypots.map((honeypot) => ({
        label: honeypot,
        value: honeypot.toLowerCase(),
      })),
    [honeypots],
  );

  const selectedFeedTypes = React.useMemo(
    () =>
      draft.feed_type && draft.feed_type !== "all"
        ? draft.feed_type
            .split(",")
            .map((value) =>
              honeypotFeedType.find((option) => option.value === value),
            )
            .filter(Boolean)
        : [],
    [draft.feed_type, honeypotFeedType],
  );

  return (
    <Container>
      <div className="d-flex justify-content-between align-items-end mb-3">
        <div>
          <h1>Trending Feed</h1>
          <small className="text-muted">
            Compare consecutive completed attack windows and highlight rising
            attackers.
          </small>
        </div>
      </div>
      <ContentSection>
        <HoneypotLoader
          render={() => (
            <form onSubmit={onSubmit}>
              <Row className="align-items-end g-3">
                <Col md={5}>
                  <FormGroup>
                    <Label htmlFor="FeedsTrending__feed_type">Feed type</Label>
                    <MultiSelectDropdown
                      id="FeedsTrending__feed_type"
                      options={honeypotFeedType}
                      value={selectedFeedTypes}
                      placeholder="All"
                      onChange={(selected) => {
                        const value =
                          selected.length > 0
                            ? selected.map((option) => option.value).join(",")
                            : "all";

                        setDraft((current) => {
                          const nextDraft = {
                            ...current,
                            feed_type: value,
                          };
                          draftRef.current = nextDraft;
                          return nextDraft;
                        });
                      }}
                    />
                  </FormGroup>
                </Col>
                <Col md={3}>
                  <FormGroup>
                    <Label htmlFor="FeedsTrending__window_minutes">
                      Window size
                    </Label>
                    <Select
                      id="FeedsTrending__window_minutes"
                      name="window_minutes"
                      value={draft.window_minutes}
                      choices={windowChoices}
                      onChange={onChange}
                    />
                  </FormGroup>
                </Col>
                <Col md={2}>
                  <FormGroup>
                    <Label htmlFor="FeedsTrending__limit">Limit</Label>
                    <Select
                      id="FeedsTrending__limit"
                      name="limit"
                      value={draft.limit}
                      choices={limitChoices}
                      onChange={onChange}
                    />
                  </FormGroup>
                </Col>
                <Col md={2} className="d-grid feeds-trending-actions">
                  <FormGroup>
                    <Label
                      className="feeds-trending-action-label"
                      aria-hidden="true"
                    >
                      Actions
                    </Label>
                    <Button
                      color="primary"
                      type="submit"
                      className="w-100 feeds-trending-refresh-button"
                    >
                      Refresh
                    </Button>
                  </FormGroup>
                </Col>
              </Row>
            </form>
          )}
        />
      </ContentSection>
      <Loader
        render={() => (
          <ContentSection>
            <div className="d-flex justify-content-between flex-wrap gap-2 mb-3">
              <div>
                <strong>{payload.count}</strong>
                <span className="text-muted ms-2">attackers</span>
              </div>
              <small className="text-muted">
                {formatWindowDate(payload.current_window?.start)} to{" "}
                {formatWindowDate(payload.current_window?.end)}
              </small>
            </div>
            {payload.attackers?.length ? (
              <div className="table-responsive">
                <table className="table table-dark table-striped align-middle">
                  <thead>
                    <tr>
                      <th>Attacker IP</th>
                      <th>Current</th>
                      <th>Previous</th>
                      <th>Delta</th>
                      <th>Growth Score</th>
                      <th>Rank Delta</th>
                    </tr>
                  </thead>
                  <tbody>
                    {payload.attackers.map((attacker) => (
                      <tr key={attacker.attacker_ip}>
                        <td>{attacker.attacker_ip}</td>
                        <td>{attacker.current_interactions}</td>
                        <td>{attacker.previous_interactions}</td>
                        <td>
                          <TrendDeltaBadge delta={attacker.interaction_delta} />
                        </td>
                        <td>{formatGrowthScore(attacker.growth_score)}</td>
                        <td>{attacker.rank_delta ?? "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-muted">
                No trending attackers found for the selected window.
              </div>
            )}
          </ContentSection>
        )}
      />
    </Container>
  );
}
