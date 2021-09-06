import { ES256KSigner, createJWT } from "@cef-ebsi/did-jwt";
import axios from "axios";
import {
  CONTEXT_W3C_DID,
  CONTEXT_W3C_SEC,
  CONTEXT_W3C_VC,
  OIDC_ISSUE,
  VERIFIABLE_PRESENTATION,
  ECDSA_SECP_256_K1_SIGNATURE_2019,
  ECDSA_SECP_256_K1_VERIFICATION_KEY_2019,
  ES256K,
  ASSERTION_METHOD,
} from "../types";

import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";
import base64url from "base64url";
import buffer_1 from "buffer";
import { createVerifiablePresentation } from "@cef-ebsi/verifiable-presentation";
import bs58 from "bs58";
import crypto from "crypto";

export const signDidAuthInternal = async (did, payload, hexPrivateKey) => {
  // check hexPrivateKey is valid
  const request = !!payload.client_id;

  let response = await createJWT(
    { ...payload },
    {
      issuer: OIDC_ISSUE,
      alg: ES256K,
      signer: ES256KSigner(hexPrivateKey.replace("0x", "")),
      expiresIn: 5 * 60,
    },
    {
      alg: ES256K,
      typ: "JWT",
      kid: request ? did : `${did}#key-1`,
    }
  );
  return response;
};

export const createVP = async (did, privateKey, vc) => {
  const options = {
    resolver: `https://api.preprod.ebsi.eu/did-registry/v2/identifiers`,
    tirUrl: `https://api.preprod.ebsi.eu/trusted-issuers-registry/v2/issuers`,
  };
  const requiredProof = {
    type: ECDSA_SECP_256_K1_SIGNATURE_2019,
    proofPurpose: ASSERTION_METHOD,
    verificationMethod: `${did}#keys-1`,
  };
  const presentation = {
    "@context": [CONTEXT_W3C_VC],
    type: VERIFIABLE_PRESENTATION,
    verifiableCredential: [vc],
    holder: did,
  };
  const vpSigner = ES256KSigner(privateKey);

  const jwtdata = await createJWT(
    presentation,
    {
      alg: ES256K,
      issuer: did,
      signer: vpSigner,
      canonicalize: true,
    },
    {
      alg: ES256K,
      typ: "JWT",
      kid: `${options.resolver}/${did}#keys-1`,
    }
  );

  const vpToken = jwtdata.split(".");

  const signatureValue = {
    proofValue: `${vpToken[0]}..${vpToken[2]}`,
    proofValueName: "jws",
    iat: extractIatFromJwt(jwtdata),
  };
  return createVerifiablePresentation(
    presentation,
    requiredProof,
    signatureValue,
    options
  );
};

const extractIatFromJwt = (jwt) => {
  const token = jwt.split(".");
  const payload = base64url.decode(token[1]);
  return JSON.parse(payload).iat;
};

export const serialize = async (object) => {
  if (object === null || typeof object !== "object" || object.toJSON != null) {
    return JSON.stringify(object);
  }
};

export const prepareDIDRegistryObject = async (
  didDocument: any
): Promise<{
  didDocument: any;
  timestampDataBuffer: any;
  didVersionMetadataBuffer: any;
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

export const constructDidDoc = async (
  didUser: string,
  publicKey: object,
  didDocument: object
): Promise<{ didDoc: object }> => {
  if (didDocument == null || Object.keys(didDocument).length < 3)
    return { didDoc: defaultDidDoc(didUser, publicKey) };
  else {
    //\\ TODO: construct the did doc and insert the key properly
    let doc: object = didDocument;
    if (!("@context" in didDocument) || doc["@context"].length == 0)
      doc["@context"] = [CONTEXT_W3C_DID, CONTEXT_W3C_SEC];
    doc["id"] = didUser;
    doc["verificationMethod"] = [verificationMethod(didUser, publicKey)];
    if (!("authentication" in didDocument) || doc["authentication"].length == 0)
      doc["authentication"] = [`${didUser}#keys-1`];
    if (!(ASSERTION_METHOD in didDocument) || doc[ASSERTION_METHOD].length == 0)
      doc["assertionMethod"] = [`${didUser}#keys-1`];
    return { didDoc: doc };
  }
};

const defaultDidDoc = (didUser: string, publicKey: object) => {
  return {
    "@context": [CONTEXT_W3C_DID, CONTEXT_W3C_SEC],
    id: didUser,
    verificationMethod: [verificationMethod(didUser, publicKey)],
    authentication: [`${didUser}#keys-1`],
    assertionMethod: [`${didUser}#keys-1`],
  };
};

export const prepareUpdateDidDocument = async (
  didUser,
  publicKeyType,
  privateKeyController,
  flag: string,
  didDoc: any | null
) => {
  let didDocument;

  didDocument =
    didDoc == null || Object.keys(didDoc).length < 3
      ? await resolveDid(didUser)
      : didDocument;

  if (flag == "updateKey") {
    didDocument = await resolveDid(didUser);
    console.log("resolved Did Doc");
    console.log(didDocument);
    let publicKey;
    const controller = new ethers.Wallet(privateKeyController);
    switch (publicKeyType) {
      case "publicKeyHex":
        publicKey = { publicKeyHex: controller.publicKey.slice(2) };
        break;
      case "publicKeyJwk":
        publicKey = {
          publicKeyJwk: new EbsiWallet(controller.privateKey).getPublicKey({
            format: "jwk",
          }),
        };
        break;
      case "publicKeyBase58":
        publicKey = {
          publicKeyBase58: bs58.encode(
            fromHexString(controller.publicKey.slice(2))
          ),
        };
        break;
      default:
        throw new Error(`invalid type ${publicKeyType}`);
    }
    didDocument["verificationMethod"] = verificationMethod(didUser, publicKey);
  }

  return await prepareDIDRegistryObject(didDocument);
};

export const fromHexString = (hexString: string) => {
  const match = hexString.match(/.{1,2}/g);
  if (!match) throw new Error("String could not be parsed");
  return new Uint8Array(match.map((byte) => parseInt(byte, 16)));
};

const verificationMethod = (didUser: string, publicKey: object) => {
  return {
    id: `${didUser}#keys-1`,
    type: ECDSA_SECP_256_K1_VERIFICATION_KEY_2019,
    controller: didUser,
    ...publicKey,
  };
};

export const jsonrpcSendTransaction = async (
  client,
  token,
  url,
  method,
  param
) => {
  const body = jsonrpcBody(method, [param]);
  console.log(JSON.stringify(param));
  const response = await axios.post(url, body, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const unsignedTransaction = response.data.result;
  const uTx = formatEthersUnsignedTransaction(
    JSON.parse(JSON.stringify(unsignedTransaction))
  );
  console.log("unsigned tx");
  console.log(uTx);

  const sgnTx = await client.signTransaction(uTx);
  console.log("signed tx");
  console.log(sgnTx);
  const bodySend = jsonrpcBody("signedTransaction", [
    paramSignedTransaction(unsignedTransaction, sgnTx),
  ]);

  return axios.post(url, bodySend, {
    headers: { Authorization: `Bearer ${token}` },
  });
};

export const jsonrpcBody = (method, params) => {
  return {
    jsonrpc: "2.0",
    method,
    params,
    id: Math.ceil(Math.random() * 1000),
  };
};

const formatEthersUnsignedTransaction = (unsignedTransaction) => {
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

const paramSignedTransaction = (tx, sgnTx) => {
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

export const resolveDid = async (
  did: string
): Promise<{ didDocument: object }> => {
  const url = "https://api.preprod.ebsi.eu/did-registry/v2/identifiers/";
  const encodedDid = "did%3Aebsi%3A" + did.split(":")[2];
  console.log(`${url + encodedDid}`);
  const response = await axios.get(url + encodedDid, {
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

export const base64ToBase64Url = (privateKey) => {
  const privateKeyBuffer = privateKey.toArrayLike(buffer_1.Buffer);
  return privateKeyBuffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
};

export const getLedgerTx = async (txId, token) => {
  const url = `https://api.preprod.ebsi.eu/ledger/v2/blockchains/besu`;
  const body = jsonrpcBody("eth_getTransactionReceipt", txId);
  const response = await axios.post(url, body, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (response.status > 400) throw new Error(response.data);
  const receipt = response.data.result;
  if (receipt && Number(receipt.status) !== 1) {
    console.log(`Transaction failed: Status ${receipt.status}`);
    if (receipt.revertReason)
      console.log(
        `revertReason: ${Buffer.from(
          receipt.revertReason.slice(2),
          "hex"
        ).toString()}`
      );
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
};
