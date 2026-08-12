export {
  beginLogin,
  completeLogin,
  getAppInfo,
  getEntitlement,
  getPrices,
  logoutUrl,
  manageUrl,
  purchaseUrl,
  refresh,
  userinfo,
  type BeginLoginOptions,
  type CompleteLoginArgs,
  type GetAppInfoOptions,
  type GetEntitlementOptions,
  type GetPricesOptions,
  type LogoutUrlOptions,
  type ManageUrlOptions,
  type PurchaseUrlOptions,
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

export type { AppInfo, AppPrices, Entitlement, UtaFlowState, UtaPrice, UtaSession } from "./types.js";
