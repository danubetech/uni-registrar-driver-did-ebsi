import { prepareDIDRegistryObject, constructDidDoc } from "./utils";
import { ethers } from "ethers";
import { buildParamsObject } from "../utils/types";

export const buildParams = async (buildParamsObj: buildParamsObject) => {
  const controllerDid = buildParamsObj.did;
  let newDidDocument;
  if (buildParamsObj.publicKey) {
    console.log(buildParamsObj.publicKey);
    newDidDocument = await prepareDidDocumentWithPublicKey(
      controllerDid,
      buildParamsObj.publicKey,
      buildParamsObj.didDoc
    );
  }

  const {
    didDocument,
    timestampDataBuffer,
    didVersionMetadataBuffer,
  } = newDidDocument;
  console.log(JSON.stringify(didDocument,null,2));
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

const prepareDidDocumentWithPublicKey = async (
  didUser: string,
  publicKey: Array<object>,
  reqDidDoc: object
) => {
  const didDocument = (await constructDidDoc(didUser, publicKey, reqDidDoc)).didDoc;
  return await prepareDIDRegistryObject(didDocument);
};

