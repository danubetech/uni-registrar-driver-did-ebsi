import { createVP, prefixWith0x } from "./utils";
import {
  createAuthenticationResponse,
  verifyAuthenticationRequest,
  siopSession,
} from "./onboardingUtils";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";
import querystring from "querystring";
import { Agent } from "@cef-ebsi/siop-auth";
import base64url from "base64url";
const canonicalize = require("canonicalize");
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";

export const signer = async (
  uTx: any,
  privateKey: any
): Promise<{ signedTx: any }> => {
  console.log(privateKey);
  const pk = prefixWith0x(privateKey);
  let client = new ethers.Wallet(pk);
  const sgnTx = await client.signTransaction(uTx);
  return { signedTx: sgnTx };
};

export const keyGen = async () => {
  const keyPairs = await EbsiWallet.generateKeyPair({ format: "hex" });
  const wallet = await new EbsiWallet(keyPairs.privateKey);
  const publicKeyJwk = await wallet.getPublicKey({ format: "jwk" });
  console.log(publicKeyJwk);
  return {
    privateKey: keyPairs.privateKey,
    publicKey: publicKeyJwk,
    clientAddress: prefixWith0x(wallet.getEthereumAddress()),
  };
};

export const userOnBoardAuthReq = async (
  token: string
): Promise<{ id_token: string }> => {
  let response;
  const keyPairs = await EbsiWallet.generateKeyPair({ format: "hex" });
  let client;
  const privateKey = "0x" + keyPairs.privateKey;
  client = new ethers.Wallet(privateKey);
  const did = await EbsiWallet.createDid();
  client.did = did;
  const wallet = await new EbsiWallet(privateKey);
  const publicKeyJwk = await wallet.getPublicKey({ format: "jwk" });

  const nonce = await uuidv4();
  console.log("User onboarding initialted");
  const didAuthResponseJwt = await createAuthenticationResponse({
    hexPrivatekey: client.privateKey,
    did: client.did,
    nonce,
    redirectUri: `https://api.preprod.ebsi.eu/users-onboarding/v1/authentication-responses`,
  });
  const [url, data] = didAuthResponseJwt.urlEncoded.split("#");
  console.log(didAuthResponseJwt);
  try {
    await axios
      .post(url, data, {
        headers: {
          Authorization: `Bearer ${token}`,
          "content-type": "application/x-www-form-urlencoded",
        },
      })
      .then((res) => {
        response = res;
      });
  } catch (error) {
    // Handle Error Here
    console.log("User Onboarding error");
    console.error(error.message);
    throw Error("Invalid onboarding token");
  }
  const verifiableCredntial = response.data.verifiableCredential;

  console.log(verifiableCredntial);

  const verifiablePresentation = await createVP(
    client.did,
    client.privateKey,
    verifiableCredntial
  );

  console.log(verifiablePresentation);
  const canonicalizedVP = base64url.encode(
    canonicalize(verifiablePresentation)
  );

  const siopResponse = await axios.post(
    "https://api.preprod.ebsi.eu/authorisation/v1/authentication-requests",
    {
      scope: "openid did_authn",
    }
  );
  console.log(siopResponse.data);
  const uriDecoded = querystring.decode(
    siopResponse.data.uri.replace("openid://?", "")
  ) as {
    client_id: string;
    request: string;
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

var __classPrivateFieldGet =
  (this && __classPrivateFieldGet) ||
  function (receiver, privateMap) {
    if (!privateMap.has(receiver)) {
      throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
  };
