import React from "react";
import classnames from "classnames";
import {
  ListGroup,
  ListGroupItem,
  UncontrolledPopover,
  PopoverHeader,
  PopoverBody,
} from "reactstrap";
import { addMinutes, format, formatDistanceToNow } from "date-fns";
import { nanoid } from "nanoid";

function DateHoverable({
  id = undefined,
  value,
  className = undefined,
  noHover = false,
  ago = false,
  showAgo = false,
  format: formatProp = "PPpppp",
  showFormat = "p PP",
  ...rest
}) {
  const [utcVal, userTz, userTzVal] = React.useMemo(() => {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const d = new Date(value || null);
    const dUTC = addMinutes(d, d.getTimezoneOffset());
    return [format(dUTC, showFormat), tz, format(d, showFormat)];
  }, [value, showFormat]);

  const timeId = React.useMemo(() => id || `date-${nanoid(4)}`, [id]);

  return (
    <>
      <time
        id={timeId}
        className={classnames("date-hoverable", className)}
        {...rest}
      >
        {ago
          ? formatDistanceToNow(new Date(value || null), { addSuffix: true })
          : format(new Date(value || null), formatProp)}
      </time>
      {!noHover && (
        <UncontrolledPopover target={timeId} trigger="hover">
          <PopoverHeader className="p-1">
            <small>Time Conversion</small>
          </PopoverHeader>
          <PopoverBody className="bg-body">
            <ListGroup flush>
              {showAgo && (
                <ListGroupItem className="p-1 d-flex justify-content-between align-items-center text-light">
                  <b className="mx-auto text-secondary">
                    {formatDistanceToNow(new Date(value || null), {
                      addSuffix: true,
                    })}
                  </b>
                </ListGroupItem>
              )}
              <ListGroupItem className="p-1 d-flex justify-content-between align-items-center text-light">
                <b>UTC</b>
                <span className="ms-4">{utcVal}</span>
              </ListGroupItem>
              <ListGroupItem className="p-1 d-flex justify-content-between align-items-center text-light">
                <b>{userTz} · Your computer</b>
                <span className="ms-4">{userTzVal}</span>
              </ListGroupItem>
            </ListGroup>
          </PopoverBody>
        </UncontrolledPopover>
      )}
    </>
  );
}

export default React.memo(DateHoverable);
