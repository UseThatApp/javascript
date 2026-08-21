export {
  beginLogin,
  completeLogin,
  getAppInfo,
  getEntitlement,
  getOrder,
  getPrices,
  logoutUrl,
  manageUrl,
  purchaseUrl,
  refresh,
  regenerateLicenseKey,
  userinfo,
  validateLicenseKey,
  type BeginLoginOptions,
  type CompleteLoginArgs,
  type GetAppInfoOptions,
  type GetEntitlementOptions,
  type GetPricesOptions,
  type LicenseApiOptions,
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
  UtaLicenseCanceledError,
  UtaNotFoundError,
  UtaOrderProcessingError,
  UtaPermissionError,
  UtaServiceNotEnabledError,
  UtaServerError,
  UtaTokenError,
} from "./errors.js";

export type { AppInfo, AppPrices, Entitlement, LicenseState, UtaFlowState, UtaPrice, UtaSession } from "./types.js";
