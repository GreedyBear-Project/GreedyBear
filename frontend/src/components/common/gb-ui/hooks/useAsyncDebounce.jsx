import React from "react";

/**
 * Debounces a callback and returns a promise that resolves with the latest call result.
 * This mirrors the behavior commonly relied on from react-table's useAsyncDebounce helper.
 */
export default function useAsyncDebounce(defaultFn, defaultWait = 0) {
  const fnRef = React.useRef(defaultFn);
  const waitRef = React.useRef(defaultWait);
  const debounceRef = React.useRef({});

  React.useEffect(() => {
    fnRef.current = defaultFn;
  }, [defaultFn]);

  React.useEffect(() => {
    waitRef.current = defaultWait;
  }, [defaultWait]);

  React.useEffect(
    () => () => {
      if (debounceRef.current.timeout) {
        clearTimeout(debounceRef.current.timeout);
      }
    },
    [],
  );

  return React.useCallback((...args) => {
    if (!debounceRef.current.promise) {
      debounceRef.current.promise = new Promise((resolve, reject) => {
        debounceRef.current.resolve = resolve;
        debounceRef.current.reject = reject;
      });
    }

    if (debounceRef.current.timeout) {
      clearTimeout(debounceRef.current.timeout);
    }

    debounceRef.current.timeout = setTimeout(async () => {
      delete debounceRef.current.timeout;

      try {
        debounceRef.current.resolve(await fnRef.current(...args));
      } catch (error) {
        debounceRef.current.reject(error);
      } finally {
        delete debounceRef.current.promise;
        delete debounceRef.current.resolve;
        delete debounceRef.current.reject;
      }
    }, waitRef.current);

    return debounceRef.current.promise;
  }, []);
}
