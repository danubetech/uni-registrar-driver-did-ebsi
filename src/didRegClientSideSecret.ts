import { jsonrpcBody, paramSignedTransaction } from "./utils/utils";
import { didRegResponse, buildParams } from "./utils/didRegistryUtils";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { step1, step2, step3, step4, } from "./userOnboardingClientSideSecretMode"
import { DidRegistrationResponse } from "./utils/types";
import {
  OIDC_ISSUE,
  ES256K,
} from "./types";
const elliptic = require("elliptic");
const Web3 = require("web3");

let didDoc;
let unSigned;

let map = new Map();

export const didRegistryClientSideSecret = async (
  options:any,
  token: string,
  didDocument: object,
  jobID?: any,
): Promise<DidRegistrationResponse> => {
  let currentState = options.action == null ? "initial" : options.action;
  
  const url = `https://api.preprod.ebsi.eu/did-registry/v2/jsonrpc`;
  const ec = new elliptic.ec("secp256k1");
  const web3 = new Web3();

  switch (currentState) {
    case "initial":
      const did = await EbsiWallet.createDid();
      let keyPair = ec.keyFromPublic(options.publicKeyHex, "hex");
      let pubkey = "0x" + keyPair.getPublic(false, "hex").substr(2);
      let adr = "0x".concat(
        web3.utils.keccak256(pubkey).substr(web3.utils.keccak256(pubkey).length - 40)
      );
      const clientAddress = web3.utils.toChecksumAddress(adr);
      const jwkPK = ec.keyFromPublic(options.publicKeyHex, "jwk");
      const req1 = await step1(did, jwkPK);

      let jobId = uuidv4();
      let objectStore = {
        did: did,
        didDocument: didDocument,
        unSignedTx: null,
        token: token,
        authReqPayload: req1.authRequestObject,
        publicKeyJwk: jwkPK,
        clientAddress: clientAddress,
      };
      map.set(jobId, objectStore);
      return {
        jobId: jobId,
        didState: {
          state: "action",
          action: "signOnboardRequest",
          signingRequest: {
            request1: {
              payload: req1.payload,
              kid: `${did}#key-1`,
              alg: ES256K,
              typ: "JWT",
              issuer: OIDC_ISSUE,
            },
          },
        },
      };
    case "signOnboardRequest":
      let objectMap = map.get(jobID);
      if (objectMap == null) throw new Error("Invalid JobId");
      console.log(objectMap.did);
      console.log(objectMap.didDocument);
      const req2 = await step2(objectMap.authReqPayload, options.signedPayload, objectMap.token);

      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "signVerifiableCredential",
          signingRequest: {
            request1: {
              payload: req2.verifiableCredential,
              kid: `${objectMap.did}#key-1`,
              alg: ES256K,
            },
          },
        },
      };
    case "signVerifiableCredential":
      objectMap = map.get(jobID);
      if (objectMap == null) throw new Error("Invalid JobId");
      const req3 = await step3(options.signedPayload, objectMap.publicKeyJwk, objectMap.did);

      objectStore = {
        did: objectMap.did,
        didDocument: objectMap.didDocument,
        unSignedTx: null,
        token: objectMap.token,
        authReqPayload: req3.authRequestObject,
        publicKeyJwk: objectMap.publicKeyJwk,
        clientAddress: objectMap.clientAddress,
      };
      map.set(jobID, objectStore);

      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "signSIOPRequest",
          signingRequest: {
            request1: {
              payload: req3.payload,
              kid: `${objectMap.did}#key-1`,
              alg: ES256K,
              typ: "JWT",
              issuer: OIDC_ISSUE,
            },
          },
        },
      };

    case "signSIOPRequest":
      objectMap = map.get(jobID);
      if (objectMap == null) throw new Error("Invalid JobId");
      const req4 = await step4(objectMap.authReqPayload, options.signedPayload);

      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "decodeToken",
          signingRequest: {
            request1: {
              payload: req4.siopResponse,
              kid: `${objectMap.did}#key-1`,
              alg: ES256K,
              typ: "JWT",
              issuer: OIDC_ISSUE,
            },
          },
        },
      };
    case "decodeToken":
      objectMap = map.get(jobID);
      if (objectMap == null) throw new Error("Invalid JobId");

      const buildParam = await buildParams({
        did: objectMap.did,
        publicKey: objectMap.publicKeyJwk,
        didDoc: objectMap.didDocument,
      });
      let param = {
        from: clientAddress,
        ...buildParam.param,
      };
      didDoc = buildParam.info.data;
      const uTx = await constructUnsignedTx(token, url, "insertDidDocument", param);
      objectStore = {
        did: objectMap.did,
        didDocument: didDoc,
        unSignedTx: unSigned,
        token: token,
        authReqPayload: null,
        publicKeyJwk: objectMap.publicKeyJwk,
        clientAddress: objectMap.clientAddress,
      };
      console.log(jobID);
      map.set(jobID, objectStore);
      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "signEthereumTxRequest",
          signingRequest: {
            request1: {
              payload: uTx,
              kid: `${did}#key-1`,
              alg: "secp256k1",
            },
          },
        },
      };
    case "signEthereumTxRequest":
      objectMap = map.get(jobID);
      if (objectMap == null) throw new Error("Invalid JobId");
      console.log(objectMap.did);
      console.log(objectMap.didDocument);
      const res = await constructSignedTx(token, url, options.signedPayload, objectMap.unSignedTx);
      console.log("Signed Tx response..............");
      console.log(res.data);
      // remove jobId after completion
      map.delete(jobID);
      return {
        jobId: null,
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
  const uTx = formatEthersUnsignedTransaction(JSON.parse(JSON.stringify(unsignedTransaction)));
  console.log("unsigned tx");
  console.log(uTx);
  return uTx;
};

const constructSignedTx = async (token, url, signedTx, unSignedTx) => {
  const bodySend = jsonrpcBody("signedTransaction", [paramSignedTransaction(unSignedTx, signedTx)]);
  console.log(signedTx);
  console.log(unSignedTx);
  let response;
  try {
    response = await axios.post(url, bodySend, {
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch (error) {
    console.log(error);
    throw new Error("Failed to send signed TX....");
  }
  console.log(response.status);
  return response;
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
