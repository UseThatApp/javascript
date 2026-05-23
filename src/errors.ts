export class UtaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class UtaConfigError extends UtaError {}

export class UtaSignatureError extends UtaError {}

export class UtaPayloadExpiredError extends UtaError {}

export class UtaAppMismatchError extends UtaError {}

export class UtaBadRequestError extends UtaError {}

export class UtaSessionRevokedError extends UtaError {}

export class UtaUnknownSessionError extends UtaError {}

export class UtaServerError extends UtaError {}
