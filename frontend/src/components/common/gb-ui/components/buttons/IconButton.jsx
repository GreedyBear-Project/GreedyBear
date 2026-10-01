import React from "react";
import { Button, UncontrolledTooltip } from "reactstrap";
import { nanoid } from "nanoid";

function IconButton({
  id = undefined,
  title = undefined,
  titlePlacement = "right-start",
  Icon,
  ...rest
}) {
  // props

  // vars
  const btnId = React.useMemo(() => id || `iconbtn-${nanoid(4)}`, [id]);

  return (
    <Button id={btnId} type="button" {...rest}>
      <Icon />
      {title && (
        <UncontrolledTooltip
          target={btnId}
          placement={titlePlacement}
          delay={{ show: 0 }}
        >
          {title}
        </UncontrolledTooltip>
      )}
    </Button>
  );
}

export default IconButton;
