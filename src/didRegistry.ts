import {
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
    didDocument,
    timestampDataBuffer,
    didVersionMetadataBuffer,
  } = newDidDocument;
  console.log(newDidDocument);

  const didDocumentBuffer = Buffer.from(JSON.stringify(didDocument));

  return {
    info: {
      title: "Did document",
      data: didDocument,
    },
    param: {
      identifier: `0x${Buffer.from(controllerDid).toString("hex")}`,
      hashAlgorithmId: 1,
      hashValue: ethers.utils.sha256(didDocumentBuffer),
      didVersionInfo: `0x${didDocumentBuffer.toString("hex")}`,
      timestampData: `0x${timestampDataBuffer.toString("hex")}`,
      didVersionMetadata: `0x${didVersionMetadataBuffer.toString("hex")}`,
    },
  };
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
