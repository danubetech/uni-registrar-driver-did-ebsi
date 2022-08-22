import axios from "axios";
import {
  CONTEXT_W3C_DID,
  CONTEXT_W3C_SEC_JWS2020,
  ASSERTION_METHOD,
  AUTHENTICATION,
  VERIFICATION_METHOD,
  CONTEXT,
  JSON_WEB_Key_2020,
  KEY_1,
} from "./constants";
import { ethers } from "ethers";
import crypto from "crypto";
import {
  UnsignedTX,
  DIDDocument,
  VerificationMethod,
  JsonWebKey,
} from "../utils/types";
import * as u8a from "uint8arrays";
import {config} from '../config';

const baseUrl = config.baseUrl;
const ebsiDidRegistryUrl = `${baseUrl}/did-registry/${config.didRegistryApiVersion}/jsonrpc`;
const ebsiDidResolverUrl = `${baseUrl}/did-registry/${config.didRegistryApiVersion}/identifiers`;
const ebsiTIRUrl = `${baseUrl}/trusted-issuers-registry/${config.tirApiVersion}/issuers`;



export const prepareDIDRegistryObject = async (
  didDocument: any
): Promise<{
  didDocument: any;
  timestampDataBuffer: Buffer;
  didVersionMetadataBuffer: Buffer;
}> => {
  const timestampData = { data: crypto.randomBytes(32).toString("hex") };
  const didVersionMetadata = {
    meta: crypto.randomBytes(32).toString("hex"),
  };

  const timestampDataBuffer = Buffer.from(JSON.stringify(timestampData));
  const didVersionMetadataBuffer = Buffer.from(
    JSON.stringify(didVersionMetadata)
  );

  return {
    didDocument,
    timestampDataBuffer,
    didVersionMetadataBuffer,
  };
};

export const sendApiTransaction = async (
  method: any,
  token: string,
  param: any,
  client: any,
  registryUrl: string,
  callback: any
) => {
  const url = registryUrl;
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

export const constructDidDoc = async (
  didUser: string,
  publicKey: Array<JsonWebKey>,
  didDocument?: DIDDocument,
  keyId?: string
): Promise<{ didDoc: DIDDocument }> => {
  if (didDocument == null || Object.keys(didDocument).length < 1)
    return { didDoc: defaultDidDoc(didUser, publicKey) };
  else {
    let kid = keyId == null ? KEY_1 : `${keyId}`;
    //\\ TODO: construct the did doc and insert the key properly
    let doc: DIDDocument = didDocument;
    let publicKeyObj: Array<JsonWebKey | VerificationMethod> = [];
    publicKeyObj.push.apply(publicKeyObj, publicKey);
    if (!Array.isArray(doc[CONTEXT]) || doc[CONTEXT].length == 1)
      doc[CONTEXT] = [CONTEXT_W3C_DID,CONTEXT_W3C_SEC_JWS2020];
    doc["id"] = didUser;

    if (!Array.isArray(doc.assertionMethod) || doc.assertionMethod.length == 0)
      doc[ASSERTION_METHOD] = [`${didUser}${kid}`];
    if (doc.verificationMethod) {
      publicKeyObj.push.apply(publicKeyObj, doc[VERIFICATION_METHOD]);
    }
    if (!Array.isArray(doc.authentication) || doc.authentication.length == 0)
      doc[AUTHENTICATION] = [`${didUser}${kid}`];
    else if (doc.authentication) {
      publicKeyObj.push.apply(publicKeyObj, doc[AUTHENTICATION]);
      let auth: Array<string> = [];
      for (let i = 0; i < doc.authentication.length; i++) { 
        const keyId = doc.authentication[i]["id"]
          ? `${didUser}${doc.authentication[i]["id"]}`
          : `${didUser}#key-${publicKeyObj.length}`;
        auth.push(keyId);
      }
      console.log(auth);
      doc[AUTHENTICATION] = auth;
    }
    doc[VERIFICATION_METHOD] = verificationMethod(didUser, publicKeyObj, keyId);

    return { didDoc: doc };
  }
};

const defaultDidDoc = (
  didUser: string,
  publicKey: Array<JsonWebKey>
): DIDDocument => {
  return {
    "@context": [CONTEXT_W3C_DID,CONTEXT_W3C_SEC_JWS2020],
    id: didUser,
    verificationMethod: verificationMethod(didUser, publicKey),
    authentication: [`${didUser}${KEY_1}`],
    assertionMethod: [`${didUser}${KEY_1}`],
  };
};

export const fromHexString = (hexString: string) => {
  const match = hexString.match(/.{1,2}/g);
  if (!match) throw new Error("String could not be parsed");
  return new Uint8Array(match.map((byte) => parseInt(byte, 16)));
};

export const verificationMethod = (
  didUser: string,
  publicKey: Array<JsonWebKey | VerificationMethod>,
  keyId?: string
): Array<VerificationMethod> => {
  let verificationMethodObject: Array<VerificationMethod> = [];

  for (let i = 0; i < publicKey.length; i++) {
    let id = publicKey[i].id
      ? `${didUser}${publicKey[i].id}`
      : `${didUser}#key-${i + 1}`;
    if (i == 0 && keyId && keyId != KEY_1) id = `${didUser}${keyId}`;
    const type =
      publicKey[i].type && publicKey[i].type != null
        ? publicKey[i].type
        : JSON_WEB_Key_2020;
    const publicKeyJwk = publicKey[i].publicKeyJwk
      ? publicKey[i].publicKeyJwk
      : publicKey[i];

    verificationMethodObject.push({
      id: id,
      controller: didUser,
      type: type,
      publicKeyJwk: publicKeyJwk,
    });
  }
  return verificationMethodObject;
};

export const jsonrpcSendTransaction = async (
  client: any,
  token: string,
  url: string,
  method: string,
  param: any
) => {
  const body = jsonrpcBody(method, [param]);
  console.log(JSON.stringify(param));
  const response = await axios
    .post(url, body, {
      headers: { Authorization: `Bearer ${token}` },
    })
    .catch((error) => {
      console.log(error.message);
      throw error(error.message);
    });
  const unsignedTransaction = response.data.result;
  const uTx = formatEthersUnsignedTransaction(JSON.parse(JSON.stringify(unsignedTransaction)));

  const sgnTx = await client.signTransaction(uTx);
  console.log("signed tx");
  console.log(sgnTx);
  const bodySend = jsonrpcBody("signedTransaction", [
    paramSignedTransaction(unsignedTransaction, sgnTx),
  ]);

  return axios
    .post(url, bodySend, {
      headers: { Authorization: `Bearer ${token}` },
    })
    .catch((error) => {
      console.log(error.message);
      throw error(error.message);
    });
};

export const jsonrpcBody = (method: string, params: any) => {
  return {
    jsonrpc: "2.0",
    method,
    params,
    id: Math.ceil(Math.random() * 1000),
  };
};

const formatEthersUnsignedTransaction = (unsignedTransaction: UnsignedTX): UnsignedTX => {
  return {
    to: unsignedTransaction.to,
    data: unsignedTransaction.data,
    value: unsignedTransaction.value,
    nonce: Number(unsignedTransaction.nonce),
    chainId: Number(unsignedTransaction.chainId),
    gasLimit: unsignedTransaction.gasLimit,
    gasPrice: unsignedTransaction.gasPrice,
  };
};

export const paramSignedTransaction = (tx: UnsignedTX, sgnTx) => {
  const { r, s, v } = ethers.utils.parseTransaction(sgnTx);
  return {
    protocol: "eth",
    unsignedTransaction: tx,
    r,
    s,
    v: `0x${Number(v).toString(16)}`,
    signedRawTransaction: sgnTx,
  };
};

export const resolveDid = async (did: string): Promise<{ didDocument: DIDDocument }> => {
  const encodedDid = "/did%3Aebsi%3A" + did.split(":")[2];
  const response = await axios.get(ebsiDidResolverUrl + encodedDid, {
    headers: { "Content-Type": "application/did+ld+json" },
  });
  return response.data.didDoc;
};

export const remove0xPrefix = (str: string): string => {
  return str.startsWith("0x") ? str.slice(2) : str;
};

export const prefixWith0x = (key: string): string => {
  return key.startsWith("0x") ? key : `0x${key}`;
};

export const base64ToBase64Url = (base64 : string) => {
  return base64
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
};

const getLedgerTx = async (txId: string, token: string) => {
  const url = `${baseUrl}/ledger/${config.ledgerApiVersion}/blockchains/besu`;
  const body = jsonrpcBody("eth_getTransactionReceipt", txId);
  const response = await axios.post(url, body, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (response.status > 400) throw new Error(response.data);
  const receipt = response.data.result;
  if (receipt && Number(receipt.status) !== 1) {
    console.log(`Transaction failed: Status ${receipt.status}`);
    if (receipt.revertReason)
      console.log(`revertReason: ${Buffer.from(receipt.revertReason.slice(2), "hex").toString()}`);
  }
  return receipt;
};

const waitToBeMined = async (txId) => {
  let mined = false;
  let receipt = null;

  // if (!oauth2token) {
  //   utils.yellow(
  //     "Wait some seconds while the transaction is mined and check if it was accepted"
  //   );
  //   return 0;
  // }
  // while (!mined) {
  //   await new Promise((resolve) => setTimeout(resolve, 5000));
  //   receipt = await getLedgerTx(txId);
  //   mined = !!receipt;
  // }
  // /* eslint-enable no-await-in-loop */
  // if(!receipt) return 0;
  // if('statreturn Number(receipt.status?) === 1;us' in receipt)
  return 0;
};

export const base64UrlToBytes = (inputBase64Url: string): Uint8Array => {
  //const inputBase64Url = s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  return u8a.fromString(inputBase64Url, "base64url");
};
