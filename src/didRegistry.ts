import {
  createDidAuthResponsePayload,
  signDidAuthInternal,
  prepareDidDocument,
  prepareUpdateDidDocument,
  jsonrpcSendTransaction,
} from "./util";
import { userOnBoardAuthReq } from "./userOnboarding";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";
const uuid_1 = require("uuid");

export const didRegistry = async (token: string, id_token: string,didDocument:object):Promise<{didState:didRegResponse}> => {
  const keyPairs = await EbsiWallet.generateKeyPair();
  const privateKey = "0x" + keyPairs.privateKey;
  let client;

  client = new ethers.Wallet(privateKey);
  const did = await EbsiWallet.createDid();
  client.did = did;
  console.log("did " + did);
  const wallet = new EbsiWallet(privateKey);

  // Get wallet's public key (different formats)
  const publicKey = await wallet.getPublicKey();
  const publicKeyPem = wallet.getPublicKey({ format: "pem" });
  const publicKeyJwk = await wallet.getPublicKey({ format: "jwk" });

  const idToken =
    id_token != null
      ? id_token
      : await (await userOnBoardAuthReq(token, client, publicKeyJwk)).id_token;
      console.log(idToken);
  const buildParam = await buildParams(client,didDocument);
  let param = {
    from: client.address,
    ...buildParam.param,
  };

  const res = await sendApiTransaction(
    "insertDidDocument",
    idToken,
    param,
    client,
    () => {
      console.log(buildParam.info.title);
      console.log(buildParam.info.data);
    }
  );
  return {didState:{state:'finished',identifier:did,secret:keyPairs,didDocument:buildParam.info.data}};
};

export const didUpdate = async (
  token: string,
  id_token: string,
  did: string,
  privateKey
) => {
  let client;
  client = new ethers.Wallet(privateKey);
  client.did = did;

  const keyPairs = await EbsiWallet.generateKeyPair();

  const newClient = await new ethers.Wallet(keyPairs.privateKey);

  // Creates a URI using the wallet backend that manages entity DID keys
  const buildParam = await buildUpdateParams(newClient, client);
  let param = {
    from: client.address,
    ...buildParam.param,
  };

  const res = await sendApiTransaction(
    "updateDidDocument",
    id_token,
    param,
    client,
    () => {
      console.log(buildParam.info.title);
      console.log(buildParam.info.data);
    }
  );
  console.log("did doc updated");
  //client = newClient;
  return res;
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

const buildParams = async (client: any,didDocument:object) => {
  const controllerDid = client.did;
  const newDidDocument = await prepareDidDocument(
    controllerDid,
    "publicKeyHex",
    client.privateKey,
    didDocument
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

const buildUpdateParams = async (newClient: any, client: any) => {
  const controllerDid = client.did;
  const newDidDocument = prepareUpdateDidDocument(
    controllerDid,
    "publicKeyHex",
    newClient.privateKey
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

// async function getLedgerTx(txId) {
//   const url = `https://api.preprod.ebsi.eu/ledger/v2/blockchains/besu`;
//   const body = jsonrpcBody("eth_getTransactionReceipt", txId);
//   const response = await axios.post(url, body, {
//     headers: { Authorization: `Bearer ${token2}` },
//   });

//   if (response.status > 400) throw new Error(response.data);
//   const receipt = response.data.result;
//   if (receipt && Number(receipt.status) !== 1) {
//     console.log(`Transaction failed: Status ${receipt.status}`);
//     if (receipt.revertReason)
//       console.log(
//         `revertReason: ${Buffer.from(
//           receipt.revertReason.slice(2),
//           "hex"
//         ).toString()}`
//       );
//   }
//   return receipt;
// }


interface didRegResponse {
            state,
            identifier:string,
            secret:object,
            didDocument:object
}
