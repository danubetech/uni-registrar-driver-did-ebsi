import { jsonrpcBody, paramSignedTransaction } from "./utils/utils";
import {  buildParams } from "./utils/didRegistryUtils";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { step1, step2, step3, step4, } from "./userOnboardingClientSideSecretMode"
import { DidRegistrationResponse } from "./utils/types";
import { Base64 } from "js-base64";
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
      console.log(currentState);
      const did = EbsiWallet.createDid();
      let keyPair =await  ec.keyFromPublic(options.publicKey, "hex");
      let pubkey = "0x" + keyPair.getPublic(false, "hex").substr(2);
      let adr = "0x".concat(
        web3.utils.keccak256(pubkey).substr(web3.utils.keccak256(pubkey).length - 40)
      );
      const clientAddress = web3.utils.toChecksumAddress(adr);
      const jwkPK = {
        kty: "EC",
        crv: "secp256k1",
        x: Base64.fromUint8Array(keyPair.getPublic().getX().toArrayLike(Buffer), true),
        y: Base64.fromUint8Array(keyPair.getPublic().getY().toArrayLike(Buffer), true),
      };
      console.log(jwkPK);
      const req1 = await step1(did, jwkPK);
      console.log(req1);
      let job_Id = uuidv4();
      const objectStore = {
        did: did,
        didDocument: didDocument,
        unSignedTx: null,
        token: token,
        authReqPayload: req1.authRequestObject,
        publicKeyJwk: jwkPK,
        clientAddress: clientAddress,
      };
      map.set(job_Id, objectStore);
      return {
        jobId: job_Id,
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
      console.log(currentState);
      const objectMap1 = map.get(jobID);
      if (objectMap1 == null) throw new Error("Invalid JobId");
      console.log(objectMap1.did);
      console.log(objectMap1.token);
      const req2 = await step2(objectMap1.authReqPayload, options.signedPayload, objectMap1.token);

      const objectStore1 = {
        did: objectMap1.did,
        didDocument: objectMap1.didDocument,
        unSignedTx: null,
        token: objectMap1.token,
        authReqPayload: objectMap1.authRequestObject,
        publicKeyJwk: objectMap1.publicKeyJwk,
        clientAddress: objectMap1.clientAddress,
      };
      console.log(objectStore1);
      map.delete(jobID);
      map.set(jobID, objectStore1);

      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "signVerifiableCredential",
          signingRequest: {
            request1: {
              payload: req2.verifiableCredential,
              kid: `${objectMap1.did}#key-1`,
              alg: ES256K,
            },
          },
        },
      };
    case "signVerifiableCredential":
      console.log(currentState);
      const objectMap2 = map.get(jobID);
      if (objectMap2 == null) throw new Error("Invalid JobId");
      console.log(options.signedPayload);
      const req3 = await step3(options.signedPayload, objectMap2.publicKeyJwk, objectMap2.did);

      const objectStore2 = {
        did: objectMap2.did,
        didDocument: objectMap2.didDocument,
        unSignedTx: null,
        token: objectMap2.token,
        authReqPayload: req3.authRequestObject,
        publicKeyJwk: objectMap2.publicKeyJwk,
        clientAddress: objectMap2.clientAddress,
      };
      map.delete(jobID);
      map.set(jobID, objectStore2);

      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "signSIOPRequest",
          signingRequest: {
            request1: {
              payload: req3.payload,
              kid: `${objectMap2.did}#key-1`,
              alg: ES256K,
              typ: "JWT",
              issuer: OIDC_ISSUE,
            },
          },
        },
      };

    case "signSIOPRequest":
      console.log(currentState);
      const objectMap3 = map.get(jobID);
      if (objectMap3 == null) throw new Error("Invalid JobId");
      const req4 = await step4(objectMap3.authReqPayload, options.signedPayload);

      const objectStore3 = {
        did: objectMap3.did,
        didDocument: objectMap3.didDocument,
        unSignedTx: null,
        token: objectMap3.token,
        authReqPayload: objectMap3.authRequestObject,
        publicKeyJwk: objectMap3.publicKeyJwk,
        clientAddress: objectMap3.clientAddress,
      };
      map.delete(jobID);
      map.set(jobID, objectStore3);

      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "decodeToken",
          signingRequest: {
            request1: {
              payload: req4.siopResponse,
              kid: `${objectMap3.did}#key-1`,
              alg: ES256K,
              typ: "JWT",
              issuer: OIDC_ISSUE,
            },
          },
        },
      };
    case "decodeToken":
      console.log(currentState);
      const objectMap4 = map.get(jobID);
      if (objectMap4 == null) throw new Error("Invalid JobId");

      const buildParam = await buildParams({
        did: objectMap4.did,
        publicKey: objectMap4.publicKeyJwk,
        didDoc: objectMap4.didDocument,
      });
      let param = {
        from: objectMap4.clientAddress,
        ...buildParam.param,
      };
      didDoc = buildParam.info.data;
      const uTx = await constructUnsignedTx(token, url, "insertDidDocument", param);
      const objectStore4 = {
        did: objectMap4.did,
        didDocument: didDoc,
        unSignedTx: unSigned,
        token: token,
        authReqPayload: null,
        publicKeyJwk: objectMap4.publicKeyJwk,
        clientAddress: objectMap4.clientAddress,
      };
      map.delete(jobID);
      map.set(jobID, objectStore4);
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
      console.log(currentState);
      const objectMap5 = map.get(jobID);
      if (objectMap5 == null) throw new Error("Invalid JobId");
      console.log(objectMap5.did);
      console.log(objectMap5.didDocument);
      const res = await constructSignedTx(token, url, options.signedPayload, objectMap5.unSignedTx);
      console.log("Signed Tx response..............");
      console.log(res.data);
      // remove jobId after completion
      map.delete(jobID);
      return {
        jobId: null,
        didState: {
          state: "finished",
          identifier: objectMap5.did,
          didDocument: objectMap5.didDocument,
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
