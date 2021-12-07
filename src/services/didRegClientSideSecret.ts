import { jsonrpcBody, paramSignedTransaction, extractIatFromJwt } from "../utils/utils";
import { buildParams } from "../utils/didRegistryUtils";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import {
  createAuthenticationRequest,
  getVerifiableCredential,
  siopPayload,
  getEncryptedToken,
} from "../utils/userOnboarding/userOnboarding";
import { DidRegistrationResponse, UnsignedTX } from "../utils/types";
import { Base64 } from "js-base64";
import { OIDC_ISSUE, ES256K } from "../utils/constants";
const elliptic = require("elliptic");
const Web3 = require("web3");
import { prepareJWSPayload, serializeTx, signedTransactionSignature, sha256 } from "../utils/signingUtils";
import { DIDDocument } from "../utils/types";

import { createVerifiablePresentation } from "@cef-ebsi/verifiable-presentation";

let didDoc;

let map = new Map();
let objectMap;

export const didRegistryClientSideSecret = async (
  options: any,
  token: string,
  didDocument: DIDDocument,
  jobID?: any
): Promise<DidRegistrationResponse> => {
  let currentState = "initial";

  const url = `https://api.preprod.ebsi.eu/did-registry/v2/jsonrpc`;
  const ec = new elliptic.ec("secp256k1");
  const web3 = new Web3();

  if (jobID != null) {
    console.log(jobID);
    objectMap = map.get(jobID);
    console.log(map);
    currentState = objectMap.currentState;
  }

  switch (currentState) {
    case "initial":
      console.log(currentState);
      const did = EbsiWallet.createDid();
      let keyPair = await ec.keyFromPublic(options.publicKey, "hex");
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
      const req1 = await createAuthenticationRequest(did, jwkPK);
      let signingPayload = await prepareJWSPayload(
        { ...req1.payload },
        {
          issuer: OIDC_ISSUE,
          alg: ES256K,
          expiresIn: 5 * 60,
        },
        {
          alg: ES256K,
          typ: "JWT",
          kid: `${did}#key-1`,
        }
      );
      let job_Id = uuidv4();
      const objectStore = {
        did: did,
        didDocument: didDocument,
        unSignedTx: null,
        token: token,
        authReqPayload: req1.authRequestObject,
        publicKeyJwk: jwkPK,
        clientAddress: clientAddress,
        signingPayload: signingPayload,
        currentState: "signOnboardRequest",
      };
      map.set(job_Id, objectStore);
      console.log(map.get(job_Id));
      return {
        jobId: job_Id,
        didState: {
          state: "action",
          action: "signPayload",
          signingRequest: {
            request1: {
              payload: req1.payload,
              did: did,
              kid: `${did}#key-1`,
              alg: ES256K,
              typ: "JWT",
              issuer: OIDC_ISSUE,
              serializedPayload: sha256(signingPayload),
            },
          },
        },
      };
    case "signOnboardRequest":
      console.log(currentState);

      if (objectMap == null) throw new Error("Invalid JobId");
      const jwt = [objectMap.signingPayload, options.signedPayload].join(".");
      const req2 = await getVerifiableCredential(objectMap.authReqPayload, jwt, objectMap.token);

      const resolverOptions = {
        resolver: `https://api.preprod.ebsi.eu/did-registry/v2/identifiers`,
        tirUrl: `https://api.preprod.ebsi.eu/trusted-issuers-registry/v2/issuers`,
      };
      const presentation = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        type: "VerifiablePresentation",
        verifiableCredential: [req2.verifiableCredential],
        holder: objectMap.did,
      };
      // this payload goes to client

      const vpPayload = await prepareJWSPayload(
        presentation,
        {
          alg: "ES256K",
          issuer: objectMap.did,
          canonicalize: true,
        },
        {
          alg: "ES256K",
          typ: "JWT",
          kid: `${resolverOptions.resolver}/${objectMap.did}#keys-1`,
        }
      );
      const objectStore1 = {
        did: objectMap.did,
        didDocument: objectMap.didDocument,
        unSignedTx: null,
        token: objectMap.token,
        authReqPayload: presentation,
        publicKeyJwk: objectMap.publicKeyJwk,
        clientAddress: objectMap.clientAddress,
        signingPayload: vpPayload,
        currentState: "signVerifiableCredential",
      };
      map.delete(jobID);
      map.set(jobID, objectStore1);

      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "signPayload",
          signingRequest: {
            request1: {
              payload: req2.verifiableCredential,
              kid: `${objectMap.did}#key-1`,
              alg: ES256K,
              did: objectMap.did,
              serializedPayload: sha256(vpPayload),
            },
          },
        },
      };
    case "signVerifiableCredential":
      console.log(currentState);
      if (objectMap == null) throw new Error("Invalid JobId");
      const jwtVP = [objectMap.signingPayload, options.signedPayload].join(".");
      const signatureValue = {
        proofValue: `${jwtVP}`,
        proofValueName: "jws",
        iat: extractIatFromJwt(jwtVP),
      };
      const requiredProof = {
        type: "EcdsaSecp256k1Signature2019",
        proofPurpose: "assertionMethod",
        verificationMethod: `${objectMap.did}#keys-1`,
      };
      const resolverOptions2 = {
        resolver: `https://api.preprod.ebsi.eu/did-registry/v2/identifiers`,
        tirUrl: `https://api.preprod.ebsi.eu/trusted-issuers-registry/v2/issuers`,
      };
      const verifiablePresentation = await createVerifiablePresentation(
        objectMap.authReqPayload,
        requiredProof,
        signatureValue,
        resolverOptions2
      );
      console.log(verifiablePresentation);
      const req3 = await siopPayload(verifiablePresentation, objectMap.publicKeyJwk, objectMap.did);
      const payloadSIOP = req3.payload;

      console.log(payloadSIOP);
      console.log("gereeresfsd");
      let signingPayloadSIOP = await prepareJWSPayload(
        { ...payloadSIOP },
        {
          issuer: OIDC_ISSUE,
          alg: ES256K,
          expiresIn: 5 * 60,
        },
        {
          alg: ES256K,
          typ: "JWT",
          kid: `${objectMap.did}#key-1`,
        }
      );

      const objectStore2 = {
        did: objectMap.did,
        didDocument: objectMap.didDocument,
        unSignedTx: null,
        token: objectMap.token,
        authReqPayload: req3.authRequestObject,
        publicKeyJwk: objectMap.publicKeyJwk,
        clientAddress: objectMap.clientAddress,
        signingPayload: signingPayloadSIOP,
        currentState: "signSIOPRequest",
      };
      map.delete(jobID);
      map.set(jobID, objectStore2);

      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "signPayload",
          signingRequest: {
            request1: {
              payload: req3.payload,
              kid: `${objectMap.did}#key-1`,
              alg: ES256K,
              did: objectMap.did,
              typ: "JWT",
              issuer: OIDC_ISSUE,
              serializedPayload: sha256(signingPayloadSIOP),
            },
          },
        },
      };

    case "signSIOPRequest":
      console.log(currentState);
      if (objectMap == null) throw new Error("Invalid JobId");
      const jwtSIOP = [objectMap.signingPayload, options.signedPayload].join(".");
      const req4 = await getEncryptedToken(objectMap.authReqPayload, jwtSIOP);

      const objectStore3 = {
        did: objectMap.did,
        didDocument: objectMap.didDocument,
        unSignedTx: null,
        token: objectMap.token,
        authReqPayload: objectMap.authRequestObject,
        publicKeyJwk: objectMap.publicKeyJwk,
        clientAddress: objectMap.clientAddress,
        currentState: "decryptPayload",
      };
      map.delete(jobID);
      map.set(jobID, objectStore3);

      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "decryptPayload",
          signingRequest: {
            request1: {
              payload: req4.siopResponse,
              kid: `${objectMap.did}#key-1`,
              alg: ES256K,
              typ: "JWT",
              issuer: OIDC_ISSUE,
              serializedPayload: req4.siopResponse.response.ake1_enc_payload,
            },
          },
        },
      };
    case "decryptPayload":
      console.log(currentState);
      if (objectMap == null) throw new Error("Invalid JobId");

      const buildParam = await buildParams({
        did: objectMap.did,
        publicKey: [objectMap.publicKeyJwk],
        didDoc: objectMap.didDocument,
      });
      let param = {
        from: objectMap.clientAddress,
        ...buildParam.param,
      };
      didDoc = buildParam.info.data;
      const unsignedTxs = await constructUnsignedTx(token, url, "insertDidDocument", param);
      const serializedPayload = await serializeTx(unsignedTxs.formatedUnsignedTx);

      const objectStore4 = {
        did: objectMap.did,
        didDocument: didDoc,
        unSignedTx: unsignedTxs.unsignedTx,
        token: token,
        authReqPayload: null,
        publicKeyJwk: objectMap.publicKeyJwk,
        clientAddress: objectMap.clientAddress,
        currentState: "signEthereumTxRequest",
      };
      map.delete(jobID);
      map.set(jobID, objectStore4);
      return {
        jobId: jobID,
        didState: {
          state: "action",
          action: "signPayload",
          signingRequest: {
            request1: {
              payload: unsignedTxs.formatedUnsignedTx,
              kid: `${objectMap.did}#key-1`,
              alg: "secp256k1",
              serializedPayload: serializedPayload,
            },
          },
        },
      };
    case "signEthereumTxRequest":
      console.log(currentState);
      if (objectMap == null) throw new Error("Invalid JobId");
      console.log(objectMap.did);
      console.log(objectMap.didDocument);
      const formatedTx = formatEthersUnsignedTransaction(objectMap.unSignedTx);
      console.log(formatedTx);
      const signature = await signedTransactionSignature(formatedTx, options.signedPayload);
      const res = await constructSignedTx(objectMap.token, url, signature, objectMap.unSignedTx);
      console.log("Signed Tx response..............");
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

const constructUnsignedTx = async (
  token: string,
  url: string,
  method: string,
  param: any
): Promise<{ unsignedTx: UnsignedTX ; formatedUnsignedTx: UnsignedTX }> => {
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
  const unsignedTransaction = response.data.result;
  const uTx = formatEthersUnsignedTransaction(JSON.parse(JSON.stringify(unsignedTransaction)));
  console.log("unsigned tx");
  console.log(uTx);
  return { unsignedTx: <UnsignedTX>unsignedTransaction, formatedUnsignedTx: uTx };
};

const constructSignedTx = async (token: string, url: string, signedTx: any, unSignedTx: any) => {
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
