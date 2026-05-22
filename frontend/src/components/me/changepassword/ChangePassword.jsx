import React from "react";
import {
  FormGroup,
  Label,
  Container,
  Input,
  Spinner,
  Button,
} from "reactstrap";
import { Form, Formik } from "formik";
import { useTitle } from "react-use";

import { ContentSection } from "@greedybear/gb-ui";

import { useAuthStore } from "../../../stores";
import {
  PasswordValidator,
  ComparePassword,
  OldNewPasswordValidator,
} from "../../auth/utils/validator";
import {
  usePasswordVisibility,
  ShowPasswordToggle,
} from "../../common/ShowPasswordToggle";

const initialValues = {
  old_password: "",
  new_password: "",
  confirmNewPassword: "",
};

const validateForm = (values) => {
  const errors = {};

  if (!values.old_password) {
    errors.old_password = "Required";
  }

  // new password — reuse shared validator (required + length + regex)
  const newPwErrors = PasswordValidator(values.new_password);
  if (newPwErrors.password) {
    errors.new_password = newPwErrors.password;
  }

  // confirm password
  const confirmPwErrors = PasswordValidator(values.confirmNewPassword);
  if (confirmPwErrors.password) {
    errors.confirmNewPassword = confirmPwErrors.password;
  }

  // passwords must match
  const compareErrors = ComparePassword(
    values.new_password,
    values.confirmNewPassword,
  );
  if (compareErrors.password) {
    errors.new_password = compareErrors.password;
  }
  if (compareErrors.confirmPassword) {
    errors.confirmNewPassword = compareErrors.confirmPassword;
  }

  // new password must differ from old
  const oldNewErrors = OldNewPasswordValidator(
    values.old_password,
    values.new_password,
  );
  if (oldNewErrors.new_password) {
    errors.new_password = oldNewErrors.new_password;
  }

  return errors;
};

// Component
export default function ChangePassword() {
  // page title
  useTitle("GreedyBear | Change Password", { restoreOnUnmount: true });

  const { passwordShown, toggleVisibility, inputType } =
    usePasswordVisibility();

  const changePassword = useAuthStore(
    React.useCallback((s) => s.service.changePassword, []),
  );

  // callback
  const onSubmit = React.useCallback(
    async (values, { setSubmitting, resetForm }) => {
      await changePassword(values);
      setSubmitting(false);
      resetForm();
    },
    [changePassword],
  );

  return (
    <ContentSection className="bg-body">
      <Container className="col-12 col-lg-8 col-xl-4 mt-5 mb-5">
        <h3 className="fw-bold">Change Password</h3>
        <hr />
        <Formik
          initialValues={initialValues}
          validate={validateForm}
          onSubmit={onSubmit}
          validateOnMount
        >
          {(formik) => (
            <Form>
              <FormGroup>
                <Label for="oldPassword">Old Password</Label>
                <Input
                  id="oldPassword"
                  type={inputType}
                  name="old_password"
                  onChange={formik.handleChange}
                  onBlur={formik.handleBlur}
                  value={formik.values.old_password}
                  valid={
                    !formik.errors.old_password && !!formik.touched.old_password
                  }
                  invalid={
                    !!formik.touched.old_password &&
                    !!formik.errors.old_password
                  }
                />
                {formik.touched.old_password && (
                  <small>{formik.errors.old_password}</small>
                )}
              </FormGroup>
              <FormGroup>
                <Label for="newPassword">New Password</Label>
                <Input
                  id="newPassword"
                  type={inputType}
                  name="new_password"
                  onChange={formik.handleChange}
                  onBlur={formik.handleBlur}
                  value={formik.values.new_password}
                  valid={
                    !formik.errors.new_password && !!formik.touched.new_password
                  }
                  invalid={
                    !!formik.touched.new_password &&
                    !!formik.errors.new_password
                  }
                />
                {formik.touched.new_password && (
                  <small>{formik.errors.new_password}</small>
                )}
              </FormGroup>
              <FormGroup>
                <Label for="confirmNewPassword">Confirm New Password</Label>
                <Input
                  id="confirmNewPassword"
                  type={inputType}
                  name="confirmNewPassword"
                  onChange={formik.handleChange}
                  onBlur={formik.handleBlur}
                  value={formik.values.confirmNewPassword}
                  valid={
                    !formik.errors.confirmNewPassword &&
                    !!formik.touched.confirmNewPassword
                  }
                  invalid={
                    !!formik.touched.confirmNewPassword &&
                    !!formik.errors.confirmNewPassword
                  }
                />
                {formik.touched.confirmNewPassword && (
                  <small>{formik.errors.confirmNewPassword}</small>
                )}
              </FormGroup>
              <ShowPasswordToggle
                id="ChangePassword__showPassword"
                passwordShown={passwordShown}
                onChange={toggleVisibility}
              />
              <FormGroup className="mt-3">
                <Button
                  type="submit"
                  color="primary"
                  disabled={formik.isSubmitting || !formik.isValid}
                >
                  {formik.isSubmitting && <Spinner size="sm" />} Change Password
                </Button>
              </FormGroup>
            </Form>
          )}
        </Formik>
      </Container>
    </ContentSection>
  );
}
