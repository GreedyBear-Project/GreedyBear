import React, { Fragment } from "react";
import { createRoot } from "react-dom/client";
import { Modal, ModalHeader, ModalBody, ModalFooter, Button } from "reactstrap";

function ConfirmModal({
  onClose,
  message = "Are you sure?",
  title = "Warning!",
  confirmText = "Ok",
  cancelText = "Cancel",
  confirmColor = "primary",
  cancelColor = "",
  className = "",
  buttonsComponent = null,
  size = null,
  bodyComponent = null,
  modalProps = {},
}) {
  let buttonsContent = (
    <Fragment>
      {cancelText && (
        <Button color={cancelColor} onClick={() => onClose(false)}>
          {cancelText}
        </Button>
      )}{" "}
      <Button color={confirmColor} onClick={() => onClose(true)}>
        {confirmText}
      </Button>
    </Fragment>
  );

  if (buttonsComponent) {
    const CustomComponent = buttonsComponent;
    buttonsContent = <CustomComponent onClose={onClose} />;
  }

  const BodyComponent = bodyComponent;

  return (
    <Modal
      size={size}
      isOpen
      toggle={() => onClose(false)}
      className={`reactstrap-confirm ${className}`}
      {...modalProps}
    >
      {title && (
        <ModalHeader toggle={() => onClose(false)}>{title || null}</ModalHeader>
      )}
      <ModalBody>{bodyComponent ? <BodyComponent /> : message}</ModalBody>
      <ModalFooter>{buttonsContent}</ModalFooter>
    </Modal>
  );
}

export const confirm = (props) =>
  new Promise((resolve) => {
    const el = document.createElement("div");
    document.body.appendChild(el);
    const root = createRoot(el);
    const handleResolve = (result) => {
      root.unmount();
      el.remove();
      resolve(result);
    };
    root.render(<ConfirmModal {...props} onClose={handleResolve} />);
  });

export default ConfirmModal;
