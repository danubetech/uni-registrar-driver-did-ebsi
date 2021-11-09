import { decodeJWT, verifyEbsiJWT } from "@cef-ebsi/did-jwt";
import axios from "axios";
import { OIDC_ISSUE, ES256K } from "../types";
import { v4 as uuidv4 } from "uuid";
import { signDidAuthInternal } from "./utils";
import { calculateThumbprint } from "jose/jwk/thumbprint";
import { JwkKeyFormat } from "./types";

export const createAuthenticationResponse = async (
  didAuthResponseCall,
  publicKeyJWK: JwkKeyFormat
) => {
  if (
    !didAuthResponseCall ||
    !didAuthResponseCall.did ||
    !didAuthResponseCall.redirectUri
  )
    throw new Error("Invalid parmas");

  const payload = await createAuthenticationResponsePayload(didAuthResponseCall, publicKeyJWK);
  console.log("payload");
  // signs payload using internal libraries
  console.log(payload);
  const jwt = await signDidAuthInternal(
    didAuthResponseCall.did,
    payload,
    didAuthResponseCall.hexPrivatekey
  );
  console.log(jwt);
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
    uriResponse.urlEncoded = encodeURI(`${didAuthResponseCall.redirectUri}?${params}`);
    return uriResponse;
  }
  uriResponse.response_mode = "fragment";
  uriResponse.urlEncoded = encodeURI(`${didAuthResponseCall.redirectUri}#${params}`);
  return uriResponse;
};

export const createAuthenticationResponsePayload = async (input, publicKeyJWK: JwkKeyFormat) => {
  const responsePayload = {
    iss: OIDC_ISSUE,
    sub: await getThumbprint(publicKeyJWK),
    aud: input.redirectUri,
    nonce: input.nonce,
    sub_jwk: publicKeyJWK,
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
  if (!verifiedJWT || !verifiedJWT.payload) throw Error("Signature Verification Error");
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
  publicKeyJWK: JwkKeyFormat,
  callbackUrl: string,
  nonce: string,
  verifiedClaims?: string,
): Promise<{
  alg: string;
  nonce: string;
  response: any;
}> => {
  let body: unknown;
  let alg: string;

  // using client from ethuser
  alg = ES256K;
  
  if (publicKeyJWK == null) throw new Error("Public Key JWK null");
  console.log(publicKeyJWK)
  const didAuthJwt = await createAuthenticationResponse(
    {
      did: client.did,
      hexPrivatekey:client.privateKey,
      nonce,
      redirectUri: callbackUrl,
      response_mode: "form_post",
      ...(verifiedClaims && {
        claims: {
          verified_claims: verifiedClaims,
          encryption_key: publicKeyJWK,
        },
      }),
    },
    publicKeyJWK
  );
  console.log(didAuthJwt);
  body = didAuthJwt.bodyEncoded;
  const responseSession = await axios.post(callbackUrl, body);
  console.log(responseSession.data);
  return {
    alg,
    nonce,
    response: responseSession.data,
  };
};

const getThumbprint = async (jwk) => {
  const thumbprint = await calculateThumbprint(jwk, "sha256");
  return thumbprint;
};
