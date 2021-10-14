import { jsonrpcBody, paramSignedTransaction } from "./utils/utils";
import { didRegResponse, buildParams } from "./utils/didRegistryUtils";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";

let didDoc;
let unSigned;
let idToken;

let map = new Map();

export const didRegistryClientSideSecret = async (
  did: string,
  clientAddress: string,
  id_token: string,
  didDocument: object,
  publicKeyObject: Array<object>,
  jobID?: any,
  signedTransaction?: any
): Promise<didRegResponse> => {
  idToken = id_token;
  let currentState = jobID == null ? "initial" : "action";
  const url = `https://api.preprod.ebsi.eu/did-registry/v2/jsonrpc`;

  switch (currentState) {
    case "initial":
      const buildParam = await buildParams({
        did: did,
        publicKey: publicKeyObject,
        didDoc: didDocument,
      });
      let param = {
        from: clientAddress,
        ...buildParam.param,
      };
      didDoc = buildParam.info.data;
      const uTx = await constructUnsignedTx(idToken, url, "insertDidDocument", param);
      const jobId = uuidv4();
      const objectStore = {
        did: did,
        didDocument: didDoc,
        unSignedTx: unSigned,
        idToken: idToken,
      };
      console.log(jobId);
      map.set(jobId, objectStore);
      return {
        jobId: jobId,
        didState: {
          state: "action",
          payload: uTx,
        },
      };
    case "action":
      if (jobID == null || signedTransaction == null) throw new Error("Invalid params");

      const objectMap = map.get(jobID);
      if (objectMap == null) throw new Error("Invalid JobId");
      const token = id_token != null ? id_token : objectMap.idToken;
      console.log(objectMap.did);
      console.log(objectMap.didDocument);
      const res = await constructSignedTx(token, url, signedTransaction, objectMap.unSignedTx);
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

