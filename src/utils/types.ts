export type JwkKeyFormat = {
  kty: string;
  crv: string;
  x: string;
  y: string;
  kid?: string;
  d?: string;
};

export type AuthenticationPayload = {
  did: string;
  nonce: unknown;
  redirectUri: string;
  response_mode: string;
  claims?: unknown;
};

export type AuthResponsePayload = {
  iss: string;
  sub: string;
  aud: string;
  nonce: string;
  sub_jwk: JwkKeyFormat;
  claims: unknown;
};

export type DidRegistrationResponse = {
  jobId?: any;
  didState: {
    state: string;
    action?: string;
    signingRequest?: {
      request1: SigningPayload;
      request2?: SigningPayload;
      request3?: SigningPayload;
    };
    identifier?: string;
    secret?: object;
    didDocument?: object;
  };
};

type SigningPayload = {
  payload: unknown;
  did?:string,
  kid?: string;
  alg?: string;
  typ?: string;
  issuer?: string;
};
