import {
  createDidAuthResponsePayload,
  signDidAuthInternal,
  prepareDidDocument,
  jsonrpcSendTransaction,
  remove0xPrefix,
} from "./util";

import { userOnBoardAuthReq } from "./userOnboarding";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";
const uuid_1 = require("uuid");

export const didRegistry = async (
  token: string,
  id_token: string,
  didDocument: object
): Promise<{ didState: didRegResponse }> => {
  const keyPairs = await EbsiWallet.generateKeyPair({ format: "hex" });
  const privateKey = "0x" + keyPairs.privateKey;
  let client;

  client = new ethers.Wallet(privateKey);
  const did = await EbsiWallet.createDid();
  client.did = did;
  const wallet = await new EbsiWallet(privateKey);
  console.log("did " + did);
  const publicKeyJwk = await wallet.getPublicKey({ format: "jwk" });
  const key = await EbsiWallet.ec.keyFromPrivate(remove0xPrefix(privateKey));
  let privateKeyJwk;
  privateKeyJwk = await EbsiWallet.formatPrivateKey(key.getPrivate(), {
    format: "jwk",
  });
  console.log("publicKeyJwk....." + JSON.stringify(publicKeyJwk));
  const idToken =
    id_token != null
      ? id_token
      : await (await userOnBoardAuthReq(token, client, publicKeyJwk)).id_token;
  console.log(idToken);
  const buildParam = await buildParams(client, didDocument);
  let param = {
    from: client.address,
    ...buildParam.param,
  };

  await sendApiTransaction("insertDidDocument", idToken, param, client, () => {
    console.log(buildParam.info.title);
    console.log(buildParam.info.data);
  });
  privateKeyJwk["kid"] = did + "#keys-1";
  const keyObj = { keys: [privateKeyJwk] };
  return {
    didState: {
      state: "finished",
      identifier: did,
      secret: keyObj,
      didDocument: buildParam.info.data,
    },
  };
};

const sendApiTransaction = async (
  method: any,
  token: string,
  param: any,
  client: any,
  callback: any
) => {
  const url = `https://api.preprod.ebsi.eu/did-registry/v2/jsonrpc`;
  callback();
  const response = await jsonrpcSendTransaction(
    client,
    token,
    url,
    method,
    param
  );

  if (response.status < 400 && (await waitToBeMined(response.data.result))) {
    callback();
  }
  return response.data;
};

const buildParams = async (client: any, didDoc: object) => {
  const controllerDid = client.did;
  const newDidDocument = await prepareDidDocument(
    controllerDid,
    "publicKeyJwk",
    client.privateKey,
    didDoc
  );

  const {
    didDocumentBuffer,
    canonicalizedDidDocumentHash,
    timestampDataBuffer,
    didVersionMetadataBuffer,
  } = newDidDocument;
  console.log(newDidDocument);

  const identifier = `0x${Buffer.from(controllerDid).toString("hex")}`;
  const didVersionInfo = `0x${didDocumentBuffer.toString("hex")}`;
  const timestampData = `0x${timestampDataBuffer.toString("hex")}`;
  const didVersionMetadata = `0x${didVersionMetadataBuffer.toString("hex")}`;

  return {
    info: {
      title: "Did document",
      data: newDidDocument.didDocument,
    },
    param: {
      identifier,
      hashAlgorithmId: 1,
      hashValue: canonicalizedDidDocumentHash,
      didVersionInfo,
      timestampData,
      didVersionMetadata,
    },
  };
};

const createDidAuthRequestPayload = async (
  input
): Promise<{ RequestPayload: object }> => {
  const requestPayload = {
    iss: input.issuer,
    scope: "open_id did_authn",
    response_type: "id_token",
    client_id: input.redirectUri,
    nonce: uuid_1.v4(),
    claims: input.claims,
  };
  return { RequestPayload: requestPayload };
};

const createAuthenticationResponses = async (didAuthResponseCall, jwk) => {
  if (
    !didAuthResponseCall ||
    !didAuthResponseCall.hexPrivatekey ||
    !didAuthResponseCall.did ||
    !didAuthResponseCall.redirectUri
  )
    throw new Error("Invalid params");

  const payload = await createDidAuthResponsePayload(didAuthResponseCall, jwk);
  //console.log(payload);
  // signs payload using internal libraries
  const jwt = await signDidAuthInternal(
    didAuthResponseCall.did,
    payload,
    didAuthResponseCall.hexPrivatekey
  );
  const params = `id_token=${jwt}`;
  const uriResponse = {
    urlEncoded: "",
    encoding: "application/x-www-form-urlencoded",
    response_mode: didAuthResponseCall.response_mode
      ? didAuthResponseCall.response_mode
      : "fragment", // FRAGMENT is the default
  };
  if (didAuthResponseCall.response_mode === "form_post") {
    uriResponse.urlEncoded = encodeURI(didAuthResponseCall.redirectUri);
    //uriResponse.bodyEncoded = encodeURI(params);
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

async function waitToBeMined(txId) {
  let mined = false;
  let receipt = null;
  console.log(txId);

  // if (!oauth2token) {
  //   utils.yellow(
  //     "Wait some seconds while the transaction is mined and check if it was accepted"
  //   );
  //   return 0;
  // }

  //utils.yellow("Waiting to be mined...");
  /* eslint-disable no-await-in-loop */
  // while (!mined) {
  //   await new Promise((resolve) => setTimeout(resolve, 5000));
  //   receipt = await getLedgerTx(txId);
  //   mined = !!receipt;
  // }
  // /* eslint-enable no-await-in-loop */
  // if(!receipt) return 0;
  // if('statreturn Number(receipt.status?) === 1;us' in receipt)
  return 0;
}

interface didRegResponse {
  state;
  identifier: string;
  secret: object;
  didDocument: object;
}

var __classPrivateFieldGet =
  (this && __classPrivateFieldGet) ||
  function (receiver, privateMap) {
    if (!privateMap.has(receiver)) {
      throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
  };
