import { decodeJWT, verifyEbsiJWT } from "@cef-ebsi/did-jwt";
import { OIDC_ISSUE } from "../constants";
import { signDidAuthInternal } from "../utils";
//import { calculateThumbprint,JWK } from "jose/jwk/thumbprint";
import { calculateJwkThumbprint, JWK,} from "jose";
import { JwkKeyFormat } from "../types";

export const createAuthenticationResponse = async (
  didAuthResponseCall:any,
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
    response_mode: didAuthResponseCall.response_mode ? didAuthResponseCall.response_mode : "fragment", // FRAGMENT is the default
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

export const createAuthenticationResponsePayload = async (input:any, publicKeyJWK: JwkKeyFormat) => {
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

export const verifyAuthenticationRequest = async (didAuthJwt:string, didRegistry:string) => {
  // as audience is set in payload as a DID, it is required to be set as options
  const options = {
    audience: getAudience(didAuthJwt),
    didRegistry,
  };
  const verifiedJWT = await verifyEbsiJWT(didAuthJwt, options);
  if (!verifiedJWT || !verifiedJWT.payload) throw Error("Signature Verification Error");
  return verifiedJWT.payload;
};

const getAudience = (jwt:string) => {
  const { payload } = decodeJWT(jwt);
  if (!payload) throw new Error("Null Payload");
  if (!payload.aud) return undefined;
  if (Array.isArray(payload.aud)) throw new Error("Invalid Payload");
  return payload.aud;
};


const getThumbprint = async (jwk: JWK):Promise<string> => {
  const thumbprint = await calculateJwkThumbprint(jwk, "sha256");
  return thumbprint;
};
