import React from "react";
import { Button, Popover, UncontrolledTooltip, PopoverBody } from "reactstrap";
import { nanoid } from "nanoid";
import { IoMdClose } from "react-icons/io";

export default function PopupFormButton({
  id = undefined,
  title = null,
  titlePlacement = "right-start",
  popOverPlacement = "right-start",
  Icon,
  Form,
  onFormSuccess = () => null,
  ...rest
}) {
  // props

  // state
  const [popoverOpen, setPopoverOpen] = React.useState(false);
  const closeTimeoutRef = React.useRef(null);

  React.useEffect(
    () => () => {
      if (closeTimeoutRef.current) clearTimeout(closeTimeoutRef.current);
    },
    [],
  );

  // callbacks
  const onFormSubmit = React.useCallback(() => {
    if (closeTimeoutRef.current) clearTimeout(closeTimeoutRef.current);
    closeTimeoutRef.current = setTimeout(() => setPopoverOpen(false), 400);
    onFormSuccess();
  }, [onFormSuccess]);

  // vars
  const btnId = React.useMemo(() => id || `popover-btn-${nanoid(4)}`, [id]);

  return (
    <>
      <Button
        id={btnId}
        type="button"
        className="btn-sm"
        color="info"
        {...rest}
      >
        {popoverOpen ? <IoMdClose /> : <Icon />}
      </Button>
      {title && (
        <UncontrolledTooltip
          target={btnId}
          placement={titlePlacement}
          delay={{ show: 0 }}
        >
          {title}
        </UncontrolledTooltip>
      )}
      <Popover
        placement={popOverPlacement}
        isOpen={popoverOpen}
        target={btnId}
        toggle={() => setPopoverOpen(!popoverOpen)}
      >
        <PopoverBody className="bg-dark">
          <Form onFormSubmit={onFormSubmit} />
        </PopoverBody>
      </Popover>
    </>
  );
}
