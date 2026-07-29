import React from "react";
import classnames from "classnames";
import { MdCheck, MdCheckCircleOutline } from "react-icons/md";
import { IoMdCloseCircleOutline, IoMdClose } from "react-icons/io";

export default function BooleanIcon({
  truthy,
  withColors = false,
  outline = true,
  ...rest
}) {
  const Check = outline ? MdCheckCircleOutline : MdCheck;
  const Close = outline ? IoMdCloseCircleOutline : IoMdClose;

  return truthy ? (
    <Check
      title="true"
      className={classnames({ "text-success": withColors })}
      size="20px"
      {...rest}
    />
  ) : (
    <Close
      title="false"
      className={classnames({ "text-danger": withColors })}
      size="20px"
      {...rest}
    />
  );
}
