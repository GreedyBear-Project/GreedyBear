import React from "react";
import {
  FormGroup,
  Label,
  Container,
  Input,
  Spinner,
  Button,
  Row,
  Alert,
} from "reactstrap";
import { MdInfoOutline } from "react-icons/md";
import { Form, Formik } from "formik";

import { ContentSection } from "@greedybear/gb-ui";

import { useAuthStore } from "../../stores";
import {
  // ResendVerificationEmailButton,
  ForgotPasswordButton,
} from "./utils/registration-buttons";
import {
  usePasswordVisibility,
  ShowPasswordToggle,
} from "../common/ShowPasswordToggle";

// constants
const initialValues = {
  username: "",
  password: "",
};

// methods
const onValidate = (values) => {
  const errors = {};
  if (!values.username) {
    errors.username = "Required";
  }
  if (!values.password) {
    errors.password = "Required";
  }
  return errors;
};

// Component
function Login() {
  console.debug("Login rendered!");

  // local state
  const { passwordShown, toggleVisibility, inputType } =
    usePasswordVisibility();

  // auth store
  const loginUser = useAuthStore(
    React.useCallback((s) => s.service.loginUser, []),
  );

  // callbacks
  const onSubmit = React.useCallback(
    async (values, _formik) => {
      try {
        await loginUser(values);
      } catch (e) {
        // handled inside loginUser
      }
    },
    [loginUser],
  );

  return (
    <ContentSection className="bg-body">
      <Container className="col-12 col-lg-8 col-xl-4">
        <ContentSection>
          <h3 className="fw-bold">Log In</h3>
          <hr />
          <Alert
            color="accent-2"
            id="access-info"
            className="col-12 px-1 text-center"
          >
            <h5 className="text-white">
              <MdInfoOutline size="1.15rem" />
              &nbsp;New users
            </h5>
            <p>
              If you do not have an account please contact a member of The
              Honeynet Project who will provide you with credentials to log in
            </p>
          </Alert>
          {/* Form */}
          <Formik
            initialValues={initialValues}
            validate={onValidate}
            onSubmit={onSubmit}
            validateOnChange
          >
            {(formik) => (
              <Form>
                {/* username */}
                <FormGroup>
                  <Label for="LoginForm__username">Username</Label>
                  <Input
                    id="LoginForm__username"
                    type="text"
                    name="username"
                    placeholder="Enter username"
                    autoComplete="username"
                    value={formik.values.username}
                    onChange={formik.handleChange}
                  />
                </FormGroup>
                {/* password */}
                <FormGroup>
                  <Label for="LoginForm__password">Password</Label>
                  <Input
                    id="LoginForm__password"
                    type={inputType}
                    name="password"
                    placeholder="Enter password"
                    autoComplete="current-password"
                    value={formik.values.password}
                    onChange={formik.handleChange}
                  />
                </FormGroup>
                <ShowPasswordToggle
                  id="LoginForm__showPassword"
                  passwordShown={passwordShown}
                  onChange={toggleVisibility}
                />
                {/* Submit */}
                <FormGroup className="d-flex-center">
                  <Button
                    type="submit"
                    disabled={!formik.isValid || formik.isSubmitting}
                    color="primary"
                    outline
                  >
                    {formik.isSubmitting && <Spinner size="sm" />} Login
                  </Button>
                </FormGroup>
              </Form>
            )}
          </Formik>
        </ContentSection>
        {/* popover buttons */}
        <Row className="d-flex flex-column align-items-end g-0">
          <ForgotPasswordButton />
          {/*  Registration operations have been temporarily disabled due to not proper Terms of Service */}
          {/* <ResendVerificationEmailButton /> */}
        </Row>
      </Container>
    </ContentSection>
  );
}

export default Login;
