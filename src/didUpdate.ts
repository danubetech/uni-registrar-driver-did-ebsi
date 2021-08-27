import { prepareUpdateDidDocument, sendApiTransaction } from "./util";
import { userOnBoardAuthReq } from "./userOnboarding";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";

export const didUpdate = async (
  token: string,
  id_token: string,
  did: string,
  privateKeyJWK: object,
  didDocument: object,
  options: any
): Promise<{ didState: didRegResponse }> => {
  let client;
  let buffer;
  buffer = privateKeyJWK["d"]
    ? Buffer.from(privateKeyJWK["d"], "base64")
    : null;
  if (buffer == null) throw new Error("Unsupported key format");
  const privateKey = buffer.toString("hex");
  const flag = options.flag;

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
  let method = "updateDidDocument";
  let buildParam;
  if (options.method == "insertDidController") {
    console.log("Insert DID Controller");
    method = options.method;
    buildParam = await buildDidControllerParams(
      client.did,
      options.controllerDID
    );
  } else if (options.method == "updateDidController") {
    console.log("Update DID Controller");
    method = options.method;
  } else {
    console.log("Update DID Document");
    buildParam = await buildParams(newClient, client, didDocument, flag);
  }
  let param = {
    from: client.address,
    ...buildParam.param,
  };

  await sendApiTransaction(method, idToken, param, client, () => {
    console.log(buildParam.info.title);
    console.log(buildParam.info.data);
  });
  console.log("did doc updated");
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

const buildParams = async (
  newClient: any,
  client: any,
  didDoc: object,
  flag
) => {
  const controllerDid = client.did;
  const newDidDocument = await prepareUpdateDidDocument(
    controllerDid,
    "publicKeyJwk",
    newClient.privateKey,
    flag,
    didDoc
  );
  const {
    didDocument,
    timestampDataBuffer,
    didVersionMetadataBuffer,
  } = newDidDocument;

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

const buildDidControllerParams = async (did: any, newController: any) => {
  return {
    info: { title: `New controller for ${did}`, data: newController },
    param: {
      identifier: `0x${Buffer.from(did).toString("hex")}`,
      newControllerId: newController,
      notBefore: Math.round(Date.now() / 1000),
      notAfter: 0,
    },
  };
};

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
