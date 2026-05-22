import React from "react";
import { Row, Col, Badge } from "reactstrap";
import { VscDebugDisconnect } from "react-icons/vsc";
import { MdOutlineDevicesOther } from "react-icons/md";

import {
  IconButton,
  DateHoverable,
  useAxiosComponentLoader,
  confirm,
} from "@greedybear/gb-ui";

import { deleteOtherSessions, deleteTokenById } from "./api";
import { SESSIONS_BASE_URI } from "../../../constants/api";

export default function SessionsList() {
  console.debug("SessionsList rendered!");

  // API
  const [tokenSessions, Loader, refetch] = useAxiosComponentLoader(
    {
      url: SESSIONS_BASE_URI,
      headers: { "Content-Type": "application/json" },
    },
    (respData) =>
      respData.sort((a, b) => {
        // Sort current session first
        if (a.is_current && !b.is_current) return -1;
        if (!a.is_current && b.is_current) return 1;
        // otherwise sort by most recent first
        return b.created - a.created;
      }),
  );

  // callbacks
  const revokeSessionCb = React.useCallback(
    async (id, clientName) => {
      const answer = await confirm({
        message: (
          <div>
            <p className="text-warning fst-italic">
              Note: This is an irreversible operation.
            </p>
            <p>
              This will revoke the selected session for device:
              <strong> {clientName}</strong>.
            </p>
            Are you sure you wish to proceed?
          </div>
        ),
        confirmText: "Yes",
      });
      if (!answer) return;

      try {
        await deleteTokenById(id, clientName);
        // reload after 500ms
        setTimeout(refetch, 500);
      } catch (e) {
        // handled inside deleteTokenById
      }
    },
    [refetch],
  );

  const revokeOtherSessionsCb = React.useCallback(async () => {
    const answer = await confirm({
      message: (
        <div>
          <p className="text-warning fst-italic">
            Note: This is an irreversible operation.
          </p>
          <p>This will revoke all sessions except the current one.</p>
          Are you sure you wish to proceed?
        </div>
      ),
      confirmText: "Yes",
    });
    if (!answer) return;

    try {
      await deleteOtherSessions();
      // reload after 500ms
      setTimeout(refetch, 500);
    } catch (e) {
      // handled inside deleteOtherSessions
    }
  }, [refetch]);

  return (
    <Loader
      render={() => (
        <>
          <div className="d-flex justify-content-end mb-3">
            <IconButton
              id="sessionslist__revoke-others-btn"
              title="Revoke other sessions"
              aria-label="Revoke other sessions"
              color="warning"
              outline
              size="sm"
              Icon={MdOutlineDevicesOther}
              onClick={revokeOtherSessionsCb}
            />
          </div>
          <ol>
            {tokenSessions.map(
              ({
                id,
                client,
                created,
                expiry,
                has_expired: hasExpired,
                is_current: isCurrent,
              }) => (
                <li key={`sessionslist-${id}`}>
                  <Row className="mb-3 d-flex flex-wrap">
                    <Col sm={6} xl={4}>
                      <small className="text-muted me-1">Device</small>
                      &nbsp;
                      {client}
                    </Col>
                    <Col sm={6} xl={4}>
                      <small className="text-muted me-1">Created</small>
                      <DateHoverable
                        id={`sessionslist-${id}__created`}
                        value={created}
                        format="hh:mm a MMM do, yyyy"
                        title="Session create date"
                        showAgo
                      />
                    </Col>
                    <Col sm={6} xl={3}>
                      <small className="text-muted me-1">Expires</small>
                      <DateHoverable
                        id={`sessionslist-${id}__expires`}
                        value={expiry}
                        title="Session expiry date"
                        format="hh:mm a MMM do, yyyy"
                        showAgo
                      />
                      {hasExpired && (
                        <Badge color="danger" className="ms-2">
                          expired
                        </Badge>
                      )}
                    </Col>
                    {/* Actions */}
                    <Col sm={6} xl={1} className="text-center">
                      {!isCurrent ? (
                        <IconButton
                          id={`sessionslist-${id}__revoke-btn`}
                          title="Revoke Session"
                          aria-label={`Revoke session for ${client}`}
                          color="danger"
                          outline
                          size="xs"
                          Icon={VscDebugDisconnect}
                          onClick={() => revokeSessionCb(id, client)}
                        />
                      ) : (
                        <Badge color="dark">current</Badge>
                      )}
                    </Col>
                  </Row>
                </li>
              ),
            )}
          </ol>
        </>
      )}
    />
  );
}
