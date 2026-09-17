export const GREEDYBEAR_DOCS_URL =
  "https://github.com/GreedyBear-Project/GreedyBear/wiki";
export const GREEDYBEAR_API_SWAGGER_URL = "/api/schema/swagger-ui/";
export const GREEDYBEAR_API_REDOC_URL = "/api/schema/redoc/";

// env variables
// Vite uses import.meta.env, Jest uses process.env
const isTest =
  typeof process !== "undefined" && process.env.NODE_ENV === "test";

export const VERSION = isTest
  ? process.env.VITE_GREEDYBEAR_VERSION || "3.0.1"
  : import.meta.env.VITE_GREEDYBEAR_VERSION;

export const PUBLIC_URL = isTest
  ? (process.env.PUBLIC_URL || "/").replace(/\/$/, "")
  : import.meta.env.BASE_URL.replace(/\/$/, "");

export const INTELOWL_URL = isTest
  ? (process.env.VITE_INTELOWL_URL || "").replace(/\/$/, "")
  : (import.meta.env.VITE_INTELOWL_URL || "").replace(/\/$/, "");
