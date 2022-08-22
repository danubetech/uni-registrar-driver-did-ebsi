import { sendApiTransaction } from "../utils/utils";
import { userOnBoardAuthReq } from "../utils/userOnboarding/userOnboarding";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";
import { prepareDIDRegistryObject} from "../utils/utils"
import {  DidRegistrationResponse,JwkKeyFormat } from "../utils/types";
import {config} from '../config'

export const didUpdate = async (
  token: string,
  did: string,
  privateKeyInput: object,
  didDocument: object,
  options: any
): Promise<{ didState: DidRegistrationResponse }> => {
  let client;
  let privateKey;
  const baseUrl= config.baseUrl;
  const ebsiDidRegistryUrl=`${baseUrl}/did-registry/${config.didRegistryApiVersion}/jsonrpc`;

  if (privateKeyInput["d"] != null) {
    const buffer = Buffer.from(privateKeyInput["d"], "base64");
    privateKey = buffer.toString("hex");
  } else {
    privateKey = privateKeyInput;
  }

  client = new ethers.Wallet("0x" + privateKey);
  client.did = did;
  const wallet = new EbsiWallet("0x" + privateKey);
  const publicKeyJwk = <JwkKeyFormat> wallet.getPublicKey({ format: "jwk" });

  const idToken = (await userOnBoardAuthReq(token, did, publicKeyJwk, privateKey,baseUrl)).id_token;

  // Creates a URI using the wallet backend that manages entity DID keys
  let method = options.method ? options.method : "updateDidDocument";
  let buildParam;
  if (method == "insertDidController") {
    console.log("Insert DID Controller");
    buildParam = await buildDidControllerParams(client.did, options.controllerDID);
  } else if (method == "updateDidController") {
    console.log("Update DID Controller");
    throw "Method not implemented";
  } else if (method == "updateDidDocument") {
    console.log("Update DID Document");
    buildParam = await buildParams(client, didDocument);
  } else {
    throw 'Invalid DID update "options.method"';
  }
  let param = {
    from: client.address,
    ...buildParam.param,
  };

  await sendApiTransaction(method, idToken, param, client,ebsiDidRegistryUrl, () => {
    console.log(buildParam.info.title);
    console.log(buildParam.info.data);
  });
  console.log("did doc updated");
  console.log("here....");
  const didState = {
    state: "finished",
    identifier: did,
    didDocument: buildParam.info.data,
  }
  return { didState: {didState:didState}}

};

const buildParams = async ( client: any, didDoc: object) => {
  const controllerDid = client.did;
  const newDidDocument = await prepareDIDRegistryObject(didDoc);
  const { didDocument, timestampDataBuffer, didVersionMetadataBuffer } = newDidDocument;

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

const buildDidControllerParams = async (did: string, newController: string) => {
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
