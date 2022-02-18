import axios from "axios";
import {
  createAuthenticationResponsePayload,
  verifyAuthenticationRequest,
} from "./onboardingUtils";
import querystring from "querystring";
import base64url from "base64url";
const canonicalize = require("canonicalize");
import { JwkKeyFormat } from "../types";
import { ES256K, OIDC_ISSUE } from "../constants";
import {
  VerifiablePresentation,
  createVerifiablePresentation,
} from "@cef-ebsi/verifiable-presentation";
import { VerifiableCredential } from "@cef-ebsi/verifiable-credential";
import { AuthenticationPayload, AuthResponsePayload, SiopResponse } from "../types";
import { Agent } from "@cef-ebsi/siop-auth";
import { prepareJWSPayload, signJWS } from "../signingUtils"
import { ES256KSigner } from "@cef-ebsi/did-jwt";
import { extractIatFromJwt } from "../utils";

export const userOnBoardAuthReq = async (
  token: string,
  did: string,
  publicKeyJwk: JwkKeyFormat,
  privateKey:any,
): Promise<{ id_token: string }> => {

  console.log("User onboarding initiated");
  
  const authReq = await createAuthenticationRequest(did, publicKeyJwk);
  const authReqObject = authReq.authRequestObject;
  // signs payload using internal libraries
  //const jwt = await signDidAuthInternal(did, authReq.payload, privateKey);
  let signingPayload = await prepareJWSPayload(
    { ...authReq.payload },
    {
      issuer: OIDC_ISSUE,
      alg: ES256K,
      expiresIn: 5 * 60,
    },
    {
      alg: ES256K,
      typ: "JWT",
      kid:  `${did}#key-1`,
    }
  );
  const signature = await signJWS(signingPayload, ES256K, ES256KSigner(privateKey.replace("0x", "")));
  const jwt = [signingPayload, signature].join(".");

  const verifiableCredntial = (await getVerifiableCredential(authReqObject, jwt, token)).verifiableCredential;

  console.log(verifiableCredntial);

  //const verifiablePresentation = await createVP(did, privateKey, verifiableCredntial);

  const options = {
    resolver: `https://api.preprod.ebsi.eu/did-registry/v2/identifiers`,
    tirUrl: `https://api.preprod.ebsi.eu/trusted-issuers-registry/v2/issuers`,
  };
  const requiredProof = {
    type: "EcdsaSecp256k1Signature2019",
    proofPurpose: "assertionMethod",
    verificationMethod: `${did}#keys-1`,
  };
  const presentation = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: "VerifiablePresentation",
    verifiableCredential: [verifiableCredntial],
    holder: did,
  };
  // this payload goes to client

  const vpPayload = await prepareJWSPayload(
    presentation,
    {
      alg: "ES256K",
      issuer: did,
      canonicalize: true,
    },
    {
      alg: "ES256K",
      typ: "JWT",
      kid: `${options.resolver}/${did}#keys-1`,
    }
  );

  const signatureVP = await signJWS(vpPayload, ES256K, ES256KSigner(privateKey.replace("0x", "")));

  // signature is response from driver
  const jwtVP = [vpPayload, signatureVP].join(".");
  //const vpToken = jwtVP.split(".");

  const signatureValue = {
    proofValue: `${jwtVP}`,
    proofValueName: "jws",
    iat: extractIatFromJwt(jwtVP),
  };

  const verifiablePresentation = await createVerifiablePresentation(presentation, requiredProof, signatureValue, options);


  console.log(verifiablePresentation);

  const siopPayloadRequest = await siopPayload(verifiablePresentation, publicKeyJwk, did);
  const payloadSIOP = siopPayloadRequest.payload;
  // signs payload using internal libraries
  //const jwtSIOP = await signDidAuthInternal(did, payloadSIOP, privateKey);
  const requestObject = siopPayloadRequest.authRequestObject;

  let signingPayloadSIOP = await prepareJWSPayload(
    { ...payloadSIOP },
    {
      issuer: OIDC_ISSUE,
      alg: ES256K,
      expiresIn: 5 * 60,
    },
    {
      alg: ES256K,
      typ: "JWT",
      kid: `${did}#key-1`,
    }
  );
  const signatureSIOP = await signJWS(
    signingPayloadSIOP,
    ES256K,
    ES256KSigner(privateKey.replace("0x", ""))
  );
  const jwtSIOP = [signingPayloadSIOP, signatureSIOP].join(".");

  const encryptedToken = await getEncryptedToken(requestObject,jwtSIOP);

  const siopAgent = new Agent({
    privateKey: privateKey.slice(2),
    didRegistry: "https://api.preprod.ebsi.eu/did-registry/v2/identifiers",
  });
  const accessToken = await siopAgent.verifyAuthenticationResponse(
    encryptedToken.siopResponse.response,
    encryptedToken.siopResponse.nonce,
  );

  return { id_token: accessToken.toString() };
};



const createAuthenticationResponse = async (didAuthResponseCall:any, signedJWT: string) => {
  if (!didAuthResponseCall || !didAuthResponseCall.did || !didAuthResponseCall.redirectUri)
    throw new Error("Invalid parmas");
  const params = `id_token=${signedJWT}`;
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

export const getEncryptedToken = async (
  requestObject: AuthenticationPayload,
  signedJwt: string
): Promise<{ siopResponse: SiopResponse }> => {
  const alg = ES256K;
  const didAuthJwt = await createAuthenticationResponse(requestObject, signedJwt);
  const body = didAuthJwt.bodyEncoded;
  const responseSession = await axios.post(requestObject.redirectUri, body);
  console.log(responseSession.data);
  const siopSessionResponse = {
    alg,
    nonce: requestObject.nonce,
    response: responseSession.data,
  };
  return { siopResponse: siopSessionResponse };
};

export const siopPayload = async (
  verifiablePresentation: VerifiablePresentation,
  publicKeyJwk: JwkKeyFormat,
  did: string
): Promise<{ payload: AuthResponsePayload; authRequestObject: AuthenticationPayload }> => {
  const canonicalizedVP = base64url.encode(canonicalize(verifiablePresentation));
  const siopResponse = await axios.post(
    "https://api.preprod.ebsi.eu/authorisation/v1/authentication-requests",
    {
      scope: "openid did_authn",
    }
  );
  console.log(siopResponse.data);
  const uriDecoded = querystring.decode(siopResponse.data.uri.replace("openid://?", "")) as {
    client_id: string;
    request: string;
    nonce: string;
  };
  console.log(uriDecoded);
  const awa = await verifyAuthenticationRequest(
    uriDecoded.request,
    "https://api.preprod.ebsi.eu/did-registry/v2/identifiers"
  );

  if (publicKeyJwk == null) throw new Error("Public Key JWK null");

  const reqObj = {
    did: did,
    nonce: uriDecoded.nonce,
    redirectUri: uriDecoded.client_id,
    response_mode: "form_post",
    ...(canonicalizedVP && {
      claims: {
        verified_claims: canonicalizedVP,
        encryption_key: publicKeyJwk,
      },
    }),
  };
  return {
    payload: await createAuthenticationResponsePayload(reqObj, publicKeyJwk),
    authRequestObject: reqObj,
  };
};

export const getVerifiableCredential = async (
  authReqObject: AuthenticationPayload,
  signedJwt: string,
  token: string
): Promise<{ verifiableCredential: VerifiableCredential }> => {
  const didAuthResponseJwt = await createAuthenticationResponse(authReqObject, signedJwt);

  const [url, data] = didAuthResponseJwt.urlEncoded.split("#");
  const response = await axios
    .post(url, data, {
      headers: {
        Authorization: `Bearer ${token}`,
        "content-type": "application/x-www-form-urlencoded",
      },
    })
    .catch((error) => {
      // Handle Error Here
      console.log("User Onboarding error");
      console.error(error.message);
      throw Error("Invalid onboarding token");
    });
  const verifiableCredential: VerifiableCredential = response.data.verifiableCredential;
  console.log(verifiableCredential);
  return { verifiableCredential: verifiableCredential };
};

export const createAuthenticationRequest = async (
  did: string,
  publicKeyJwk: JwkKeyFormat
): Promise<{ payload: AuthResponsePayload; authRequestObject: AuthenticationPayload }> => {
  const onboardRequestUrl =
    "https://api.preprod.ebsi.eu/users-onboarding/v1/authentication-requests";
  console.log("Request to user-onboarding-request");
  console.log("request url " + onboardRequestUrl);
  const authReq = await axios
    .post(onboardRequestUrl, {
      scope: "ebsi users onboarding",
    })
    .catch((error) => {
      console.log("request url failed to " + onboardRequestUrl);
      console.log(error.message);
      throw Error("SIOP request failed");
    });
  const uriAuthDecoded = querystring.decode(
    authReq.data.session_token.replace("openid://?", "")
  ) as {
    client_id: string;
    request: string;
    nonce: string;
  };

  console.log(uriAuthDecoded);
  await verifyAuthenticationRequest(
    uriAuthDecoded.request,
    "https://api.preprod.ebsi.eu/did-registry/v2/identifiers"
  );

  const authReqObject: AuthenticationPayload = {
    did: did,
    nonce: uriAuthDecoded.nonce,
    redirectUri: uriAuthDecoded.client_id,
    response_mode: "fragment",
  };

  return {
    payload: await createAuthenticationResponsePayload(authReqObject, publicKeyJwk),
    authRequestObject: authReqObject,
  };
};
