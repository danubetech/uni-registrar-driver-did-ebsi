import axios from "axios";
import { createVP } from "./util";

const { v4: uuidv4 } = require("uuid");
const base64url = require("base64url");
const canonicalize = require("canonicalize");
const querystring = require("querystring");
const { EbsiDidAuth, Agent } = require("@cef-ebsi/siop-auth");

export const userOnBoardAuthReq = async (
  token: string,
  client: any,
  publicKeyJwk: any
): Promise<{ id_token: string }> => {
  let response;

  const nonce = await uuidv4();

  const didAuthResponseJwt = await EbsiDidAuth.createAuthenticationResponse(
    {
      hexPrivatekey: client.privateKey,
      did: client.did,
      nonce,
      redirectUri: `https://api.preprod.ebsi.eu/users-onboarding/v1/authentication-responses`,
    },
    publicKeyJwk
  );
  console.log(didAuthResponseJwt);
  try {
    await axios
      .post(
        "https://api.preprod.ebsi.eu/users-onboarding/v1/authentication-responses",
        {
          id_token: didAuthResponseJwt.urlEncoded,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      )
      .then((res) => {
        response = res;
      });
  } catch (error) {
    // Handle Error Here
    console.error(error.message);
    throw error.message;
  }
  const verifiableCredntial = response.data;

  console.log(verifiableCredntial);

  const verifiablePresentation = await createVP(
    client.did,
    client.privateKey,
    verifiableCredntial.verifiableCredential
  );

  console.log(verifiablePresentation);
  const canonicalizedVP = await base64url.encode(
    canonicalize(verifiablePresentation)
  );

  const authenticationResponse = await EbsiDidAuth.createAuthenticationResponse(
    {
      hexPrivatekey: client.privateKey,
      did: client.did,
      nonce,
      redirectUri: "/siop-sessions",
      response_mode: "form_post",
      claims: {
        verified_claims: canonicalizedVP,
        encryption_key: publicKeyJwk,
      },
    }
  );

  const authResponseDecoded = querystring.decode(
    authenticationResponse.bodyEncoded
  );

  const idToken = authResponseDecoded.id_token;
  console.log("id token :  " + idToken);

  const siopAuthSession = await axios.post(
    "https://api.preprod.ebsi.eu/authorisation/v1/siop-sessions",
    { id_token: idToken }
  );
  const agent = new Agent({
    privateKey: client.privateKey.slice(2),
    didRegistry: `https://api.preprod.ebsi.eu/did-registry/v2/identifiers`,
  });

  const token2 = await agent.verifyAuthenticationResponse(
    siopAuthSession.data,
    nonce
  );

  console.log(siopAuthSession.data);

  console.log(token2);

  return { id_token: token2 };
};
