import { prepareUpdateDidDocument, jsonrpcSendTransaction } from "./util";
import { userOnBoardAuthReq } from "./userOnboarding";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";
const uuid_1 = require("uuid");

export const didUpdate = async (
  token: string,
  id_token: string,
  did: string,
  privateKey: string,
  didDocument: object,
  flag: string
): Promise<{ didState: didRegResponse }> => {
  let client;
  client = new ethers.Wallet("0x" + privateKey);
  client.did = did;
  const wallet = new EbsiWallet("0x" + privateKey);
  const publicKeyJwk = await wallet.getPublicKey({ format: "jwk" });

  const keyPairs = await EbsiWallet.generateKeyPair();
  const newClient = await new ethers.Wallet("0x" + keyPairs.privateKey);
  const idToken =
    id_token != null
      ? id_token
      : await (await userOnBoardAuthReq(token, client, publicKeyJwk)).id_token;

  // Creates a URI using the wallet backend that manages entity DID keys

  const buildParam = await buildParams(newClient, client, didDocument, flag);
  let param = {
    from: client.address,
    ...buildParam.param,
  };

  const res = await sendApiTransaction(
    "updateDidDocument",
    idToken,
    param,
    client,
    () => {
      console.log(buildParam.info.title);
      console.log(buildParam.info.data);
    }
  );
  console.log("did doc updated");
  //client = newClient;
  console.log("here....");
  return {
    didState: {
      state: "finished",
      identifier: did,
      secret: { updatedKeys: keyPairs },
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

const buildParams = async (
  newClient: any,
  client: any,
  didDocument: object,
  flag
) => {
  const controllerDid = client.did;
  const newDidDocument = await prepareUpdateDidDocument(
    controllerDid,
    "publicKeyHex",
    newClient.privateKey,
    flag,
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
  state;
  identifier: string;
  secret: object;
  didDocument: object;
}
