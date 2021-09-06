import { jsonrpcBody } from "./utils/utils";
import { didRegResponse, buildParams } from "./utils/didRegistryUtils";
import axios from "axios";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";
import { v4 as uuidv4 } from "uuid";

let didDoc;
let unSigned;
let did;
let idToken;

let map = new Map();

export const didRegistryClientSideSecret = async (
  clientAddress: string,
  id_token: string,
  didDocument: object,
  publicKeyJwk: object,
  jobID?: any,
  signedTransaction?: any
): Promise<didRegResponse> => {
  did = await EbsiWallet.createDid();

  idToken = id_token;
  let currentState = jobID == null ? "initial" : "action";
  const url = `https://api.preprod.ebsi.eu/did-registry/v2/jsonrpc`;

  switch (currentState) {
    case "initial":
      const buildParam = await buildParams({
        did: did,
        publicKey: publicKeyJwk,
        didDoc: didDocument,
      });
      let param = {
        from: clientAddress,
        ...buildParam.param,
      };
      didDoc = buildParam.info.data;
      const uTx = await constructUnsignedTx(
        idToken,
        url,
        "insertDidDocument",
        param
      );
      const jobId = uuidv4();
      const objectStore = {
        did: did,
        didDocument: didDoc,
        unsignedTx: unSigned,
        idToken: idToken,
      };
      console.log(jobId);
      map.set(jobId, objectStore);
      return {
        jobId: jobId,
        didState: {
          state: "action",
          unSignedTx: uTx,
        },
      };
    case "action":
      console.log(signedTransaction);
      if (jobID == null || signedTransaction == null)
        throw new Error("Invalid params");

      const objectMap = map.get(jobID);
      if (objectMap == null) throw new Error("Invalid JobId");
      console.log(objectMap);
      const token = id_token != null ? id_token : objectMap.idToken;
      const res = await constructSignedTx(
        token,
        url,
        signedTransaction,
        objectMap.unsignedTx
      );
      console.log(res.data);
      // remove jobId after completion
      map.delete(jobID);
      return {
        didState: {
          state: "finished",
          identifier: objectMap.did,
          didDocument: objectMap.didDocument,
        },
      };
    default:
      throw new Error("Invalid action");
  }
};

const constructUnsignedTx = async (token, url, method, param) => {
  const body = jsonrpcBody(method, [param]);
  console.log(JSON.stringify(param));
  let response;
  try {
    response = await axios.post(url, body, {
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch (error) {
    console.log(error.message);
    throw new Error("Failed to create unsignedTX");
  }
  console.log(response);
  const unsignedTransaction = response.data.result;
  unSigned = unsignedTransaction;
  const uTx = formatEthersUnsignedTransaction(
    JSON.parse(JSON.stringify(unsignedTransaction))
  );
  console.log("unsigned tx");
  console.log(uTx);
  return uTx;
};

const constructSignedTx = async (token, url, signedTx, unSignedTx) => {
  const bodySend = jsonrpcBody("signedTransaction", [
    paramSignedTransaction(unSignedTx, signedTx),
  ]);
  console.log(signedTx);
  console.log(unSignedTx);
  return axios.post(url, bodySend, {
    headers: { Authorization: `Bearer ${token}` },
  });
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
