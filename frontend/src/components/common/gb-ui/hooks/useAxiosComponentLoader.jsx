import React from "react";
import axios from "axios";

import Loader from "../components/containers/Loader";

const noop = (x) => x;

function useAxiosComponentLoader(axiosOptions, modifier = noop) {
  // Depend on primitive keys, not axiosOptions itself: callers commonly pass a
  // fresh object literal every render, which would otherwise retrigger the
  // effect unboundedly.
  const isUrlString = typeof axiosOptions === "string";
  const url = isUrlString ? axiosOptions : axiosOptions?.url;
  const method = isUrlString ? undefined : axiosOptions?.method;
  const paramsKey = isUrlString
    ? ""
    : JSON.stringify(axiosOptions?.params ?? null);

  // Ref lets the effect read the full, latest options (headers, data, etc.)
  // without pulling the unstable object reference into the dep list.
  const axiosOptionsRef = React.useRef(axiosOptions);
  axiosOptionsRef.current = axiosOptions;

  const [requestKey, setRequestKey] = React.useState(0);
  const [data, setData] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState(null);

  React.useEffect(() => {
    const controller = new AbortController();
    let isMounted = true;

    setLoading(true);
    setError(null);

    const latestOptions = axiosOptionsRef.current;
    const requestConfig =
      typeof latestOptions === "string"
        ? { url: latestOptions }
        : latestOptions;

    axios({
      ...requestConfig,
      signal: controller.signal,
    })
      .then((response) => {
        if (!isMounted) return;

        setData(response.data);
      })
      .catch((requestError) => {
        if (!isMounted || requestError?.code === "ERR_CANCELED") return;

        setError(requestError);
      })
      .finally(() => {
        if (isMounted) setLoading(false);
      });

    return () => {
      isMounted = false;
      controller.abort();
    };
  }, [isUrlString, url, method, paramsKey, requestKey]);

  const refetch = React.useCallback(() => {
    setRequestKey((currentKey) => currentKey + 1);
  }, []);

  // memo
  const MyLoader = React.useMemo(
    // eslint-disable-next-line func-names
    () =>
      function (props) {
        return <Loader loading={loading} error={error} {...props} />;
      },
    [loading, error],
  );

  const modifiedData = React.useMemo(
    () => (data ? modifier(data) : []),
    [data, modifier],
  );

  return [modifiedData, MyLoader, refetch];
}

export default useAxiosComponentLoader;
