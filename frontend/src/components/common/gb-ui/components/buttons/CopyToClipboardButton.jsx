import React from "react";
import { Tooltip, UncontrolledTooltip } from "reactstrap";
import { HiClipboardCopy } from "react-icons/hi";

import useCopyToClipboard from "react-use/lib/useCopyToClipboard";

function CopyToClipboardButton({
  id,
  text,
  children = null,
  tooltip = null,
  showOnHover = false,
  ...rest
}) {
  // props

  // local state
  const [copied, setCopied] = React.useState(false);
  const timeoutRef = React.useRef(null);

  const [, copyToClipboard] = useCopyToClipboard();

  React.useEffect(
    () => () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    },
    [],
  );

  // callbacks
  const onCopy = () => {
    copyToClipboard(text);
    setCopied(true);
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = setTimeout(
      () => setCopied(false),
      tooltip?.timeout || 1000,
    );
  };

  return (
    <>
      <span
        id={`copyBtn-${id}`}
        role="button"
        tabIndex={0}
        className="pointer"
        onClick={onCopy}
        onKeyPress={onCopy}
        {...rest}
      >
        {children || <HiClipboardCopy size="1.5em" />}
      </span>
      <Tooltip
        isOpen={copied}
        placement="top"
        target={`copyBtn-${id}`}
        trigger="click"
        innerClassName="bg-info text-darker"
        delay={{ show: 0, hide: 0 }}
      >
        {tooltip?.text || "Copied!"}
      </Tooltip>
      {showOnHover && (
        <UncontrolledTooltip target={`copyBtn-${id}`} trigger="hover">
          Click to copy
        </UncontrolledTooltip>
      )}
    </>
  );
}

export default CopyToClipboardButton;
