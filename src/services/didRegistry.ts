import { sendApiTransaction, remove0xPrefix } from "../utils/utils";

import { userOnBoardAuthReq } from "../utils/userOnboarding/userOnboarding";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";
import { JwkKeyFormat, DidRegistrationResponse } from "../utils/types";
import { buildParams } from "../utils/didRegistryUtils";
import { DIDDocument } from "../utils/types";
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";
import { base64url } from "multiformats/bases/base64";

export const didRegistry = async (
  token: string,
  didDocument?: DIDDocument,
  secretKey?: object
): Promise<DidRegistrationResponse> => {
  const keyPairs = await EbsiWallet.generateKeyPair({ format: "hex" });
  let client;
  let buffer = secretKey != null ? Buffer.from(secretKey["d"], "base64") : null;

  if (secretKey != null && buffer == null)
    throw new Error("Unsupported key format");
  const privateKey =
    buffer != null ? buffer.toString("hex") : "0x" + keyPairs.privateKey;

  client = new ethers.Wallet(privateKey);
  const did = EbsiWallet.createDid();
  client.did = did;
  const wallet = new EbsiWallet(privateKey);
  console.log("did " + did);

  let publicKeyJwk = <JwkKeyFormat> wallet.getPublicKey({ format: "jwk" });
  publicKeyJwk.kid = did + "#keys-1";
  const key = await EbsiWallet.ec.keyFromPrivate(remove0xPrefix(privateKey));
  const privateKeyJwk = await EbsiWallet.formatPrivateKey(key.getPrivate(), "jwk");
  console.log("publicKeyJwk....." + JSON.stringify(publicKeyJwk));
  const idToken = (
    await userOnBoardAuthReq(token, did, publicKeyJwk, privateKey)
  ).id_token;
  console.log(idToken);

  const buildParam = await buildParams({
    publicKey: [publicKeyJwk],
    didDoc: didDocument,
    did: client.did,
  });
  let param = {
    from: client.address,
    ...buildParam.param,
  };

  await sendApiTransaction("insertDidDocument", idToken, param, client, () => {
    console.log(buildParam.info.title);
    console.log(buildParam.info.data);
  });
  const keyObj = {
    verificationMethod: [
      {
        id: did + "#keys-1",
        type: "JsonWebKey2020",
        controller: did,
        purpose: ["authentication", "assertionMethod"],
        privateKeyJwk: privateKeyJwk,
      },
    ],
  };
  return {
    didState: {
      state: "finished",
      identifier: did,
      secret: keyObj,
      didDocument: buildParam.info.data,
    },
  };
};

export const naturalPersonDID = async (
  token: string,
  didDocument?: DIDDocument,
  secretKey?: object,
  options?:object,
): Promise<DidRegistrationResponse> => {

  return null;
};
