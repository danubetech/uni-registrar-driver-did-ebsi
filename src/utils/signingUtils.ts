import * as u8a from "uint8arrays";
import canonicalizeData from "canonicalize";
import { resolveProperties } from "@ethersproject/properties";
import { keccak256 } from "@ethersproject/keccak256";
import { serialize } from "@ethersproject/transactions";
import {  splitSignature } from "@ethersproject/bytes";
import { createHash } from "crypto";
import { JWTPayload,JWTHeader,JWTOptions,Signer,SignerAlgorithm,EcdsaSignature,UnsignedTransaction, } from "./types";


export const prepareJWSPayload = async (
  payload: Partial<JWTPayload>,
  { issuer, alg, expiresIn, canonicalize }: JWTOptions,
  header: Partial<JWTHeader> = {}
): Promise<string> => {
  if (!header.typ) header.typ = "JWT";
  if (!header.alg) header.alg = alg;
  let timestamps: Partial<JWTPayload> = {
    iat: Math.floor(Date.now() / 1000),
    exp: undefined,
  };
  timestamps.exp = <number>(payload.nbf || timestamps.iat) + Math.floor(expiresIn);
  const fullPayload = { ...timestamps, ...payload, iss: issuer };
  const encodedPayload =
    typeof fullPayload === "string" ? fullPayload : encodeSection(fullPayload, canonicalize);
  return [encodeSection(header, canonicalize), encodedPayload].join(".");
};

export const signJWS = async (
  signingInput: string,
  alg: string,
  signer: Signer
): Promise<string> => {
  const jwtSigner: SignerAlgorithm = ES256KSignerAlg();
  return await jwtSigner(signingInput, signer);
};


export const encodeSection= (data: any, shouldCanonicalize = false): string=> {
  if (shouldCanonicalize) {
    return encodeBase64url(<string>canonicalizeData(data));
  } else {
    return encodeBase64url(JSON.stringify(data));
  }
}



export const ES256KSignerAlg = (recoverable?: boolean): SignerAlgorithm =>{
  return async function sign(payload: string, signer: Signer): Promise<string> {
    const signature: EcdsaSignature | string = await signer(payload);
    if (instanceOfEcdsaSignature(signature)) {
      return toJose(signature, recoverable);
    } else {
      if (recoverable && typeof fromJose(signature).recoveryParam === "undefined") {
        throw new Error(
          `not_supported: ES256K-R not supported when signer doesn't provide a recovery param`
        );
      }
      console.log(signature)
      return signature;
    }
  };
}

export const instanceOfEcdsaSignature= (object: any): object is EcdsaSignature =>{
  return typeof object === "object" && "r" in object && "s" in object;
}

export const toJose = ({ r, s, recoveryParam }: EcdsaSignature, recoverable?: boolean): string => {
  const jose = new Uint8Array(recoverable ? 65 : 64);
  jose.set(u8a.fromString(r, "base16"), 0);
  jose.set(u8a.fromString(s, "base16"), 32);
  if (recoverable) {
    if (typeof recoveryParam === "undefined") {
      throw new Error("Signer did not return a recoveryParam");
    }
    jose[64] = <number>recoveryParam;
  }
  return bytesToBase64url(jose);
}

export function bytesToBase64url(b: Uint8Array): string {
  return u8a.toString(b, "base64url");
}

export const fromJose = (signature: string): { r: string; s: string; recoveryParam?: number } =>{
  const signatureBytes: Uint8Array = base64ToBytes(signature);
  if (signatureBytes.length < 64 || signatureBytes.length > 65) {
    throw new TypeError(
      `Wrong size for signature. Expected 64 or 65 bytes, but got ${signatureBytes.length}`
    );
  }
  const r = bytesToHex(signatureBytes.slice(0, 32));
  const s = bytesToHex(signatureBytes.slice(32, 64));
  const recoveryParam = signatureBytes.length === 65 ? signatureBytes[64] : undefined;
  return { r, s, recoveryParam };
}

export const bytesToHex= (b: Uint8Array): string => {
  return u8a.toString(b, "base16");
}
export const base64ToBytes= (s: string): Uint8Array => {
  const inputBase64Url = s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  return u8a.fromString(inputBase64Url, "base64url");
}
export const encodeBase64url=(s: string): string => {
  return bytesToBase64url(u8a.fromString(s));
}

export const serializeTx = async (transaction: any): Promise<string> => {
  return resolveProperties(transaction).then((tx) => {
    return keccak256(serialize(<UnsignedTransaction>tx));
  });
};

export const signedTransactionSignature = async (transaction: any, signature: any): Promise<string> => {
  let sign = fromJose(signature);
  sign.r = '0x' + sign.r;
  sign.s = "0x" + sign.s;
  console.log(sign);
  const sig = splitSignature({
    recoveryParam: 0,
    r: sign.r,
    s: sign.s,
  });
  return resolveProperties(transaction).then((tx) => {
    return serialize(<UnsignedTransaction>tx, sig);
  });
};
export const  sha256 = (payload: string | Uint8Array): any=> {
  const data = typeof payload === "string" ? u8a.fromString(payload) : payload;
  const h = createHash("sha256");
  h.update(data);
  const a = h.digest();
  return '0x'+a.toString('hex');
}

