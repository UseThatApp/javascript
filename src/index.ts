export {
  beginLogin,
  completeLogin,
  getEntitlement,
  logoutUrl,
  refresh,
  userinfo,
  type BeginLoginOptions,
  type CompleteLoginArgs,
  type GetEntitlementOptions,
  type LogoutUrlOptions,
} from "./client.js";

export {
  configure,
  loadConfig,
  resetConfig,
  DEFAULT_API_URL,
  DEFAULT_ISSUER,
  DEFAULT_SCOPES,
  type UtaConfig,
  type UtaConfigOverrides,
} from "./config.js";

export { resetDiscoveryCache, type OidcMetadata } from "./discovery.js";

export {
  UtaAuthError,
  UtaConfigError,
  UtaDiscoveryError,
  UtaError,
  UtaPermissionError,
  UtaServerError,
  UtaTokenError,
} from "./errors.js";

export type { Entitlement, UtaFlowState, UtaSession } from "./types.js";
