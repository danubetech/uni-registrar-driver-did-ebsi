import axios from "axios";
import { createVP } from "./utils/utils";
import {
  createAuthenticationResponse,
  verifyAuthenticationRequest,
  siopSession,
} from "./utils/onboardingUtils";

import querystring from "querystring";
import { Agent } from "@cef-ebsi/siop-auth";
import base64url from "base64url";
const canonicalize = require("canonicalize");
import { JwkKeyFormat } from "./utils/types";

export const userOnBoardAuthReq = async (
  token: string,
  client: any,
  publicKeyJwk: JwkKeyFormat
): Promise<{ id_token: string }> => {
  let response;

  console.log("User onboarding initialted");
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
  console.log(authReq.status);
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

  const didAuthResponseJwt = await createAuthenticationResponse(
    {
      hexPrivatekey: client.privateKey,
      did: client.did,
      nonce: uriAuthDecoded.nonce,
      redirectUri: uriAuthDecoded.client_id,
    },
    publicKeyJwk
  );
  const [url, data] = didAuthResponseJwt.urlEncoded.split("#");
  console.log(didAuthResponseJwt);
  response = await axios
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
  const verifiableCredntial = response.data.verifiableCredential;

  console.log(verifiableCredntial);

  const verifiablePresentation = await createVP(client.did, client.privateKey, verifiableCredntial);

  console.log(verifiablePresentation);
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
  console.log("here......");

  console.log(awa);
  const siopSessionResponse = await siopSession(
    client,
    publicKeyJwk,
    uriDecoded.client_id,
    uriDecoded.nonce,
    canonicalizedVP
  );
  console.log(siopSessionResponse);

  let accessToken: string;

  const siopAgent = new Agent({
    privateKey: client.privateKey.slice(2),
    didRegistry: "https://api.preprod.ebsi.eu/did-registry/v2/identifiers",
  });
  accessToken = await siopAgent.verifyAuthenticationResponse(
    siopSessionResponse.response,
    siopSessionResponse.nonce
  );
  console.log(accessToken);
  return { id_token: accessToken.toString() };
};

// const authenticationResponse = await createAuthenticationResponse({
//   hexPrivatekey: client.privateKey,
//   did: client.did,
//   nonce,
//   redirectUri: "/siop-sessions",
//   response_mode: "form_post",
//   claims: {
//     verified_claims: canonicalizedVP,
//     encryption_key: publicKeyJwk,
//   },
// });
// // working....
// const authResponseDecoded = querystring.decode(
//   authenticationResponse.bodyEncoded
// );

// const idToken = authResponseDecoded.id_token;
// console.log("id token :  " + idToken);

// const siopAuthSession = await axios.post(
//   "https://api.preprod.ebsi.eu/authorisation/v1/siop-sessions",
//   { id_token: idToken }
// );
// const agent = new Agent({
//   privateKey: client.privateKey.slice(2),
//   didRegistry: `https://api.preprod.ebsi.eu/did-registry/v2/identifiers`,
// });

// const token2 = await agent.verifyAuthenticationResponse(
//   siopAuthSession.data,
//   nonce
// );

// console.log(siopAuthSession.data);

// console.log(token2);

// return { id_token: token2 };
