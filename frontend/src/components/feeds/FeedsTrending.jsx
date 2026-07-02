import React from "react";
import {
  Container,
  Row,
  Col,
  FormGroup,
  Label,
  Input,
  Button,
  Badge,
} from "reactstrap";

import { ContentSection, useAxiosComponentLoader } from "@greedybear/gb-ui";

import { FEEDS_TRENDING_URI } from "../../constants/api";

const DEFAULT_PARAMS = Object.freeze({
  feed_type: "all",
  window_minutes: "60",
  limit: "10",
});

function TrendDeltaBadge({ delta }) {
  const color = delta > 0 ? "danger" : delta < 0 ? "success" : "secondary";
  const prefix = delta > 0 ? "+" : "";
  return <Badge color={color}>{`${prefix}${delta}`}</Badge>;
}

export default function FeedsTrending() {
  const [params, setParams] = React.useState(DEFAULT_PARAMS);
  const [draft, setDraft] = React.useState(DEFAULT_PARAMS);

  const [payload, Loader] = useAxiosComponentLoader({
    url: FEEDS_TRENDING_URI,
    params,
    headers: { "Content-Type": "application/json" },
  });

  const onChange = React.useCallback((event) => {
    const { name, value } = event.target;
    setDraft((current) => ({ ...current, [name]: value }));
  }, []);

  const onSubmit = React.useCallback(
    (event) => {
      event.preventDefault();
      setParams(draft);
    },
    [draft],
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
        <form onSubmit={onSubmit}>
          <Row className="align-items-end g-3">
            <Col md={4}>
              <FormGroup>
                <Label htmlFor="FeedsTrending__feed_type">Feed type</Label>
                <Input
                  id="FeedsTrending__feed_type"
                  name="feed_type"
                  value={draft.feed_type}
                  onChange={onChange}
                  placeholder="all or cowrie,heralding"
                />
              </FormGroup>
            </Col>
            <Col md={3}>
              <FormGroup>
                <Label htmlFor="FeedsTrending__window_minutes">
                  Window minutes
                </Label>
                <Input
                  id="FeedsTrending__window_minutes"
                  name="window_minutes"
                  type="number"
                  min="60"
                  step="60"
                  value={draft.window_minutes}
                  onChange={onChange}
                />
              </FormGroup>
            </Col>
            <Col md={2}>
              <FormGroup>
                <Label htmlFor="FeedsTrending__limit">Limit</Label>
                <Input
                  id="FeedsTrending__limit"
                  name="limit"
                  type="number"
                  min="1"
                  max="1000"
                  value={draft.limit}
                  onChange={onChange}
                />
              </FormGroup>
            </Col>
            <Col md={3}>
              <Button color="primary" type="submit">
                Refresh
              </Button>
            </Col>
          </Row>
        </form>
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
                {payload.current_window?.start} to {payload.current_window?.end}
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
                        <td>{Number(attacker.growth_score).toFixed(2)}</td>
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
