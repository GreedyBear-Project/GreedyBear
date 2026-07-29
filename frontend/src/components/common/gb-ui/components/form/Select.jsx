import React from "react";
import { Input } from "reactstrap";

export default function Select({
  choices,
  allowEmpty = false,
  emptyLabel = "",
  ...rest
}) {
  return (
    <Input type="select" id={`select-${rest.name}`} {...rest}>
      {allowEmpty && <option value="">{emptyLabel}</option>}
      {choices.map(({ label: text, value }) => (
        <option key={value} value={value}>
          {text}
        </option>
      ))}
    </Input>
  );
}
