import React from "react";
import classNames from "classnames";
import { Card, CardBody, CardHeader } from "reactstrap";

function SmallInfoCard({ header, body, className = undefined, ...rest }) {
  return (
    <Card className={classNames("flat border-dark", className)} {...rest}>
      <CardHeader className="bg-dark h5 text-center">{header}</CardHeader>
      <CardBody className="bg-body p-0">{body}</CardBody>
    </Card>
  );
}

export default SmallInfoCard;
