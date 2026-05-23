export interface UtaUser {
  /** Opaque identifier for the user/license. Persist; pass to `getVersion()`. */
  readonly user_key: string;
  /** Echoed app id; equals `UTA_APP_ID`. */
  readonly app_id: string;
  /** Unix seconds — `iat` from the envelope. */
  readonly issued_at: number;
  /** Unix seconds — `exp` from the envelope. */
  readonly expires_at: number;
  /**
   * Non-authoritative product name; for first paint only.
   *
   * The contract is: developers MAY use this for first paint but MUST
   * call `getVersion(user_key)` for the real, current value.
   */
  readonly version_hint: string | null;
}
