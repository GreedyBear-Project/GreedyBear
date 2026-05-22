import React from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { Spinner } from "reactstrap";
import { ContentSection } from "@greedybear/gb-ui";

import { verifyEmail } from "./api";

// Component
export default function EmailVerification() {
  console.debug("EmailVerification rendered!");

  // search param
  const [searchParams] = useSearchParams();
  const key = searchParams.get("key") || null;
  console.debug("key:", key);

  // local state
  const [isKeyValid, setIsKeyValid] = React.useState(true);
  const [isVerified, setIsVerified] = React.useState(false);

  // side-effects
  React.useEffect(() => {
    if (key) {
      const timeoutId = setTimeout(
        () =>
          verifyEmail({ key })
            .then(() => setIsVerified(true))
            .catch(() => setIsKeyValid(false)),
        500,
      );

      return () => clearTimeout(timeoutId);
    } else {
      setIsKeyValid(false);
    }
  }, [key]);
  return isVerified ? (
    <Navigate push to="/login" />
  ) : (
    <ContentSection className="col-lg-4 mx-auto">
      {isKeyValid ? (
        <h5 className="text-center">
          <Spinner type="border" />
          <p>Verifying...</p>
        </h5>
      ) : (
        <h5 className="text-center">Error: Invalid key.</h5>
      )}
    </ContentSection>
  );
}
