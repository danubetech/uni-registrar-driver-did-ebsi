import { decodeJWT, verifyEbsiJWT } from "@cef-ebsi/did-jwt";
import axios from "axios";
import { OIDC_ISSUE, ES256K } from "../types";
import { v4 as uuidv4 } from "uuid";
import { signDidAuthInternal, prefixWith0x } from "./utils";
import { calculateThumbprint } from "jose/jwk/thumbprint";
import { ec } from "elliptic";
import { Base64 } from "js-base64";

export const createAuthenticationResponse = async (didAuthResponseCall) => {
  if (
    !didAuthResponseCall ||
    !didAuthResponseCall.hexPrivatekey ||
    !didAuthResponseCall.did ||
    !didAuthResponseCall.redirectUri
  )
    throw new Error("Invalid parmas");

  const payload = await createAuthenticationResponsePayload(
    didAuthResponseCall
  );
  // signs payload using internal libraries
  const jwt = await signDidAuthInternal(
    didAuthResponseCall.did,
    payload,
    didAuthResponseCall.hexPrivatekey
  );
  const params = `id_token=${jwt}`;
  let uriResponse = {
    urlEncoded: "",
    bodyEncoded: "",
    encoding: "application/x-www-form-urlencoded",
    response_mode: didAuthResponseCall.response_mode
      ? didAuthResponseCall.response_mode
      : "fragment", // FRAGMENT is the default
  };

  if (didAuthResponseCall.response_mode === "form_post") {
    uriResponse.urlEncoded = encodeURI(didAuthResponseCall.redirectUri);
    uriResponse.bodyEncoded = encodeURI(params);
    return uriResponse;
  }

  if (didAuthResponseCall.response_mode === "query") {
    uriResponse.urlEncoded = encodeURI(
      `${didAuthResponseCall.redirectUri}?${params}`
    );
    return uriResponse;
  }
  uriResponse.response_mode = "fragment";
  uriResponse.urlEncoded = encodeURI(
    `${didAuthResponseCall.redirectUri}#${params}`
  );
  return uriResponse;
};

const createAuthenticationResponsePayload = async (input) => {
  const responsePayload = {
    iss: OIDC_ISSUE,
    sub: await getThumbprint(input.hexPrivatekey, null),
    aud: input.redirectUri,
    nonce: input.nonce,
    sub_jwk: getJWK(input.hexPrivatekey, `${input.did}#key-1`),
    claims: input.claims,
  };
  return responsePayload;
};

export const verifyAuthenticationRequest = async (didAuthJwt, didRegistry) => {
  // as audience is set in payload as a DID, it is required to be set as options
  const options = {
    audience: getAudience(didAuthJwt),
    didRegistry,
  };
  const verifiedJWT = await verifyEbsiJWT(didAuthJwt, options);
  if (!verifiedJWT || !verifiedJWT.payload)
    throw Error("Signature Verification Error");
  return verifiedJWT.payload;
};

const getAudience = (jwt) => {
  const { payload } = decodeJWT(jwt);
  if (!payload) throw new Error("Null Payload");
  if (!payload.aud) return undefined;
  if (Array.isArray(payload.aud)) throw new Error("Invalid Payload");
  return payload.aud;
};

export const siopSession = async (
  client: any,
  publicKey: object,
  callbackUrl: string,
  verifiedClaims?: string
): Promise<{
  alg: string;
  nonce: string;
  response: any;
}> => {
  const nonce = uuidv4();
  let body: unknown;
  let alg: string;

  // using client from ethuser
  alg = ES256K;
  const didAuthJwt = await createAuthenticationResponse({
    hexPrivatekey: prefixWith0x(client.privateKey),
    did: client.did,
    nonce,
    redirectUri: callbackUrl,
    response_mode: "form_post",
    ...(verifiedClaims && {
      claims: {
        verified_claims: verifiedClaims,
        encryption_key: publicKey,
      },
    }),
  });
  console.log(didAuthJwt);
  body = didAuthJwt.bodyEncoded;
  const responseSession = await axios.post(callbackUrl, body);
  console.log(responseSession);
  return {
    alg,
    nonce,
    response: responseSession.data,
  };
};

const getJWK = (hexPrivateKey, kid) => {
  const { x, y } = getECKeyfromHexPrivateKey(hexPrivateKey);
  return {
    kid,
    kty: "EC",
    crv: "secp256k1",
    x,
    y,
  };
};

const getThumbprint = async (hexPrivateKey, kid) => {
  const jwk = getJWK(hexPrivateKey, kid);
  const thumbprint = await calculateThumbprint(jwk, "sha256");
  return thumbprint;
};

const getECKeyfromHexPrivateKey = (hexPrivateKey) => {
  const secp256 = new ec("secp256k1");
  const privKey = secp256.keyFromPrivate(
    hexPrivateKey.replace("0x", ""),
    "hex"
  );
  const pubPoint = privKey.getPublic();
  return {
    x: Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
    y: Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
  };
};
