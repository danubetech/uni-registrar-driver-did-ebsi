import { decodeJWT, verifyEbsiJWT } from "@cef-ebsi/did-jwt";
import { OIDC_ISSUE, ES256K, CONTEXT_W3C_VC,VERIFIABLE_PRESENTATION } from "../constants";
import { calculateJwkThumbprint, JWK,} from "jose";
import { JwkKeyFormat, JWTPayload} from "../types";
import axios from "axios";
import querystring from "querystring";
import { SiopResponse } from "../types";
import {config} from '../../config';
import {prepareJWSPayload,encodeSection} from '../signingUtils'
import { v4 as uuidv4 } from "uuid";
import base64url from "base64url";


export const verifyAuthenticationRequest = async (didAuthJwt: string, didRegistry: string) => {
  // as audience is set in payload as a DID, it is required to be set as options
  const options = {
    audience: getAudience(didAuthJwt),
    didRegistry,
  };
  const verifiedJWT = await verifyEbsiJWT(didAuthJwt, options);
  if (!verifiedJWT || !verifiedJWT.payload) throw Error("Signature Verification Error");
  return verifiedJWT.payload;
};

const getAudience = (jwt: string) => {
  const { payload } = decodeJWT(jwt);
  if (!payload) throw new Error("Null Payload");
  if (!payload.aud) return undefined;
  if (Array.isArray(payload.aud)) throw new Error("Invalid Payload");
  return payload.aud;
};

export const getThumbprint = async (jwk: JWK): Promise<string> => {
  const thumbprint = await calculateJwkThumbprint(jwk, "sha256");
  return thumbprint;
};

export const getEncryptedToken = async (
  requestObject: any,
  signedJwt: string
): Promise<{ siopResponse: SiopResponse }> => {

  const body = {
    id_token: signedJwt,
    vp_token: requestObject.vp ,
  };
  console.log(body)
  const responseSession = await axios
      .post(requestObject.aud, body)
      .catch((error) => {
        throw Error("Cannot get encrypted token: " + JSON.stringify(error.response.data));
      });
  console.log(responseSession.data);
  const siopSessionResponse = {
    alg:ES256K,
    nonce: requestObject.nonce,
    response: responseSession.data,
  };
  console.log(siopSessionResponse);
  return { siopResponse: siopSessionResponse };
};

export const siopPayload = async (
  verifiablePresentation: string,
  publicKeyJwk: JwkKeyFormat,
  did: string,
  keyId:string,
  baseUrl:string
): Promise<{ payload: any, siopJwtPayload:string }> => {
  const authenticationRequestUrl = `${baseUrl}/authorisation/${config.authorizationApiVersion}/authentication-requests`;
  const siopResponse = await axios
      .post(
        authenticationRequestUrl,
          {
            scope: "openid did_authn",
          }
      )
      .catch((error) => {
        console.log("siopPayload: Error from endpoint " + authenticationRequestUrl);
        throw Error("Cannot get SIOP payload: " + JSON.stringify(error.response.data));
      });
  console.log(siopResponse.data);
  const uriDecoded = querystring.decode(siopResponse.data.replace("openid://?", "")) as {
    client_id: string;
    request: string;
    nonce: string;
  };
  console.log(uriDecoded);
  // Verify auth response
  if (publicKeyJwk == null) throw new Error("Public Key JWK null");

  const payload ={
    nonce:uriDecoded.nonce,
    aud: uriDecoded.client_id,
    claims: {
      encryption_key: publicKeyJwk,
    },
    responseMode: "form_post",
    _vp_token: {
      presentation_submission: {
        id: uuidv4(),
        definition_id: uuidv4(),
        descriptor_map: [
          {
            id: uuidv4(),
            format: "jwt_vp",
            path: "$",
            path_nested: {
              id: "onboarding-input-id",
              format: "jwt_vc",
              path: "$.vp.verifiableCredential[0]",
            },
          },
        ],
      },
    }
  }
  let siopJwtPayload = await  constructJwtPayload(payload,`${did}${keyId}`);

  return {payload: payload, siopJwtPayload: siopJwtPayload };
};

export const getVerifiableCredential = async (
  redirectUri: string,
  signedJwt: string,
  token: string
): Promise<{ verifiableCredential: string }> => {

  const body=`id_token=${signedJwt}`;

  const response = await axios
    .post(redirectUri, body, {
      headers: {
        Authorization: `Bearer ${token}`,
        "content-type": "application/x-www-form-urlencoded",
      },
    })
      .catch((error) => {
        throw Error("Cannot get verifiable credential: " + JSON.stringify(error.response.data));
      });
  const verifiableCredential: string = response.data.verifiableCredential;
  console.log(verifiableCredential);
  return { verifiableCredential: verifiableCredential };
};

export const createAuthenticationRequest = async (
  did: string,
  publicKeyJwk: JwkKeyFormat,
  onboardRequestUrl:string,
  keyId:string
): Promise<{ payload: any,jwtPayload:string }> => {
  console.log("Request to user-onboarding-request");
  console.log("request url " + onboardRequestUrl);
  const authReq = await axios
      .post(onboardRequestUrl, {
        scope: "ebsi users onboarding",
      })
      .catch((error) => {
        console.log("createAuthenticationRequest: Error from endpoint " + onboardRequestUrl);
        throw Error("Cannot create authentication request: " + JSON.stringify(error.response.data));
      });
  const uriAuthDecoded = querystring.decode(
    authReq.data.session_token.replace("openid://?", "")
  ) as {
    client_id: string;
    request: string;
    nonce: string;
  };
  
  const payload:JWTPayload = {
    aud: uriAuthDecoded.client_id,
    sub: await getThumbprint(publicKeyJwk),
    sub_jwk: publicKeyJwk,
    nonce:uriAuthDecoded.nonce,
    claims: {
      encryption_key: publicKeyJwk,
    },
    responseMode: "form_post",
  };

  let signingPayload = await  constructJwtPayload(payload,`${did}${keyId}`);

  return {payload: payload, jwtPayload:signingPayload};
};

export const buildVPJwtPayload=async(issuerDID:string, vcJWT:string,keyId:string):Promise<string>=>{

  const payload = decodeJWT(vcJWT).payload;
  const presentation = {
    "@context": [CONTEXT_W3C_VC],
    type: [VERIFIABLE_PRESENTATION],
    verifiableCredential: [vcJWT],
    holder: issuerDID,
  }
  const vpPayload:JWTPayload ={
    vp:presentation,
    sub: issuerDID,
    iss: issuerDID,
    aud: payload.iss,
    exp: Math.floor(Date.now() / 1000) + 900,

  }
  return await  constructJwtPayload(vpPayload,`${issuerDID}${keyId}`) ;
}

export const createJwtVP= async (issuerDID:string,signature:string,jwtPayload:string,keyId:string):Promise<string>=>{
  const payload = extractIatFromJwt(jwtPayload);
  const proof = {
    type: "JsonWebSignature2020",
    created: payload.iat,
    jws: signature,
    proofPurpose: "assertionMethod",
    verificationMethod: `${issuerDID}${keyId}`
   }
   return `${jwtPayload}.${encodeSection(proof)}`;
}

const extractIatFromJwt = (jwt: string) => {
  const token = jwt.split(".");
  const payload = base64url.decode(token[1]);
  return JSON.parse(payload).iat;
};

const constructJwtPayload =async(payload:JWTPayload,kid:string):Promise<string>=>{

  return await prepareJWSPayload(
    {...payload},
    {
      alg: "ES256K",
      issuer: OIDC_ISSUE,
      canonicalize: true,
      expiresIn:Math.floor(Date.now() / 1000) + 900,
    },
    {
      alg: "ES256K",
      typ: "JWT",
      kid,
    }
  )
}