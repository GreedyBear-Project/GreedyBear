import React, { useState, useCallback } from "react";
import { Toast, ToastBody, ToastHeader, Spinner } from "reactstrap";
import { MdError, MdWarning, MdInfo, MdCheckCircle } from "react-icons/md";

function getIcon(color) {
  const iconChoices = {
    danger: MdError,
    warning: MdWarning,
    info: MdInfo,
    success: MdCheckCircle,
    spinner: Spinner,
  };
  return iconChoices[color] ? iconChoices[color] : iconChoices.info;
}

export default function Toaster({
  header,
  body = null,
  color = "info",
  timeout = 4000,
  showToggle = false,
  ...props
}) {
  // state
  const [show, setShow] = useState(true);
  const toggle = useCallback(() => setShow((v) => !v), [setShow]);

  React.useEffect(() => {
    const timer = setTimeout(() => setShow(false), timeout);
    return () => clearTimeout(timer);
  }, [timeout]);

  const Icon = getIcon(color);

  const toastColor = color === "spinner" ? "info" : color;

  return (
    <Toast {...props} className={`mx-auto bg-${toastColor}`} isOpen={show}>
      <ToastHeader
        className={`bg-${toastColor} text-dark`}
        toggle={showToggle ? toggle : undefined}
      >
        <Icon className="text-large me-2" />
        {header}
      </ToastHeader>
      {body && <ToastBody>{body}</ToastBody>}
    </Toast>
  );
}
