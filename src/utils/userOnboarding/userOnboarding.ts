import axios from "axios";
import { createVP } from "../utils";
import {
  createAuthenticationResponse,
  verifyAuthenticationRequest,
  siopSession,
} from "./onboardingUtils";

import { v4 as uuidv4 } from "uuid";
import querystring from "querystring";
import { Agent } from "@cef-ebsi/siop-auth";
import base64url from "base64url";
import { Header} from "../types"
const canonicalize = require("canonicalize");

export const userOnBoardAuthReq = async (
  token: string,
  client: any,
  publicKeyJwk: any
): Promise<{ id_token: string; headers: Header }> => {
  let response;

  console.log("User onboarding initialted");

  const conformanceTestHeaderNonce = uuidv4();

  let header = headerObject(conformanceTestHeaderNonce);
  console.log(conformanceTestHeaderNonce);
  const onboardRequestUrl =
    "https://api.preprod.ebsi.eu/users-onboarding/v1/authentication-requests";
  console.log("Request to user-onboarding-request");
  console.log("request url " + onboardRequestUrl);
  const authReq = await axios.post(
    onboardRequestUrl,
    {
      scope: "ebsi users onboarding",
    },
    {
      headers: header,
    }
  );
  console.log(authReq.status)
  console.log(authReq.data);
  const uriAuthDecoded = querystring.decode(
    authReq.data.session_token.replace("openid://?", "")
  ) as {
    client_id: string;
    request: string;
    nonce: any;
  };

  console.log(uriAuthDecoded);
  const authRequestResponse = await verifyAuthenticationRequest(
    uriAuthDecoded.request,
    "https://api.preprod.ebsi.eu/did-registry/v2/identifiers"
  );

  console.log(authRequestResponse);

  const didAuthResponseJwt = await createAuthenticationResponse({
    hexPrivatekey: client.privateKey,
    did: client.did,
    nonce: uriAuthDecoded.nonce,
    redirectUri: uriAuthDecoded.client_id,
  });
  const [url, data] = didAuthResponseJwt.urlEncoded.split("#");
  console.log(didAuthResponseJwt);
  console.log("Request to user-onboarding-response");
  console.log("request url " + url);
  response = await axios
    .post(url, data, {
      headers: {
        Authorization: `Bearer ${token}`,
        "content-type": "application/x-www-form-urlencoded",
        Conformance: header.Conformance,
      },
    })
    .catch((error) => {
      console.log("User Onboarding error");
      console.error(error.message);
      throw new Error("Invalid on-boarding token");
    });
  const verifiableCredntial = response.data.verifiableCredential;
  console.log(response.status);
  console.log(response.data);

  const verifiablePresentation = await createVP(client.did, client.privateKey, verifiableCredntial);
  console.log(verifiablePresentation);
  const canonicalizedVP = base64url.encode(canonicalize(verifiablePresentation));

  console.log("Request to authorization-request");
  const authRequestUrl = "https://api.preprod.ebsi.eu/authorisation/v1/authentication-requests";
  console.log("request url " + authRequestUrl);
  const siopResponse = await axios.post(
    authRequestUrl,
    {
      scope: "openid did_authn",
    },
    {
      headers: header,
    }
  );
  console.log(siopResponse.status);
  console.log(siopResponse.data);
  const uriDecoded = querystring.decode(siopResponse.data.uri.replace("openid://?", "")) as {
    client_id: string;
    request: string;
  };
  console.log(uriDecoded);
  await verifyAuthenticationRequest(
    uriDecoded.request,
    "https://api.preprod.ebsi.eu/did-registry/v2/identifiers"
  );

  const siopSessionRequestObject = await siopSession(
    client,
    publicKeyJwk,
    uriDecoded.client_id,
    canonicalizedVP
  );
  console.log("Request to authorization-siop");
  console.log("request url " + uriDecoded.client_id);
  const siopSessionResponse = await axios.post(
    uriDecoded.client_id,
    siopSessionRequestObject.request
  );
  console.log(siopSessionResponse.status);
  console.log(siopSessionResponse.data);

  let accessToken: string;

  const siopAgent = new Agent({
    privateKey: client.privateKey.slice(2),
    didRegistry: "https://api.preprod.ebsi.eu/did-registry/v2/identifiers",
  });
  accessToken = await siopAgent.verifyAuthenticationResponse(
    siopSessionResponse.data,
    siopSessionRequestObject.nonce
  );
  console.log(accessToken);
  return { id_token: accessToken.toString(), headers: header };
};


const headerObject = (uuid:unknown): Header => {
  return {
    accept: "application/json",
    "Content-Type": "application/json",
    Conformance: uuid,
  };
};
