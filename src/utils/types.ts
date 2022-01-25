import { BigNumberish } from "@ethersproject/bignumber";
import { BytesLike } from "@ethersproject/bytes";

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
  nonce: string;
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

export type SiopResponse = {
  alg: string;
  nonce: string;
  response: any;
};

type SigningPayload = {
  payload: unknown;
  did?: string;
  kid?: string;
  alg?: string;
  typ?: string;
  issuer?: string;
  serializedPayload?: any;
};

export interface buildParamsObject {
  did: string;
  didDoc?: DIDDocument;
  publicKey: Array<JwkKeyFormat>;
}

export type UnsignedTX = {
  to: string;
  data: string;
  value: string;
  nonce: Number;
  chainId: Number;
  gasLimit: string;
  gasPrice: string;
  from?: string;
};

export type UnsignedTransaction = {
  to?: string;
  nonce?: number;

  gasLimit?: BigNumberish;
  gasPrice?: BigNumberish;

  data?: BytesLike;
  value?: BigNumberish;
  chainId?: number;

  // Typed-Transaction features
  type?: number | null;

  // EIP-2930; Type 1 & EIP-1559; Type 2
  accessList?: AccessListish;

  // EIP-1559; Type 2
  maxPriorityFeePerGas?: BigNumberish;
  maxFeePerGas?: BigNumberish;
};
export type AccessList = Array<{ address: string; storageKeys: Array<string> }>;

// Input allows flexibility in describing an access list
export type AccessListish =
  | AccessList
  | Array<[string, Array<string>]>
  | Record<string, Array<string>>;

export interface JWTOptions {
  issuer: string;
  signer?: Signer;
  /**
   * @deprecated Please use `header.alg` to specify the JWT algorithm.
   */
  alg?: string;
  expiresIn?: number;
  canonicalize?: boolean;
}

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  iat?: number;
  nbf?: number;
  exp?: number;
  rexp?: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
}

export interface JWTHeader {
  typ: "JWT";
  alg: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
}

export type Extensible = Record<string, any>;

export type KeyCapabilitySection =
  | "authentication"
  | "assertionMethod"
  | "keyAgreement"
  | "capabilityInvocation"
  | "capabilityDelegation";

export type DIDDocument = {
  "@context"?: "https://www.w3.org/ns/did/v1" | string | string[];
  id: string;
  alsoKnownAs?: string[];
  controller?: string | string[];
  verificationMethod?: VerificationMethod[];
  service?: ServiceEndpoint[];
} & {
  [x in KeyCapabilitySection]?: (string | VerificationMethod)[];
};

export interface VerificationMethod {
  type: string;
  id?: string;
  controller?: string;
  publicKeyBase58?: string;
  publicKeyBase64?: string;
  publicKeyJwk?: JsonWebKey;
  publicKeyHex?: string;
  publicKeyMultibase?: string;
  blockchainAccountId?: string;
  ethereumAddress?: string;
}

export interface JsonWebKey extends Extensible {
  alg?: string;
  crv?: string;
  e?: string;
  ext?: boolean;
  key_ops?: string[];
  kid?: string;
  kty?: string;
  n?: string;
  use?: string;
  x?: string;
  y?: string;
}

export type ServiceEndpoint ={
  id: string;
  type: string;
  serviceEndpoint: string;
  description?: string;
}

export type SignerAlgorithm = (payload: string, signer: Signer) => Promise<string>;

export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>;
export type EcdsaSignature = {
  r: string;
  s: string;
  recoveryParam?: number | null;
}
