import { prepareDidDocument, sendApiTransaction, remove0xPrefix } from "../utils/utils";

import { userOnBoardAuthReq } from "../utils/userOnboarding/userOnboarding";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";
import { didRegistrationResponse } from "../utils/interfaces";

export const didRegistry = async (
  token: string,
  didDocument: object,
  secretKey?: object
): Promise<{ didState: didRegistrationResponse }> => {
  const keyPairs = await EbsiWallet.generateKeyPair({ format: "hex" });
  let client;
  let buffer = secretKey != null ? Buffer.from(secretKey["d"], "base64") : null;
  if (secretKey != null && buffer == null) throw new Error("Unsupported key format");
  const privateKey = buffer != null ? buffer.toString("hex") : "0x" + keyPairs.privateKey;

  client = new ethers.Wallet(privateKey);
  const did = await EbsiWallet.createDid();
  client.did = did;
  const wallet = await new EbsiWallet(privateKey);
  console.log("did " + did);
  const publicKeyJwk = await wallet.getPublicKey({ format: "jwk" });
  const key = await EbsiWallet.ec.keyFromPrivate(remove0xPrefix(privateKey));
  let privateKeyJwk;
  privateKeyJwk = await EbsiWallet.formatPrivateKey(key.getPrivate(), {
    format: "jwk",
  });
  console.log("publicKeyJwk....." + JSON.stringify(publicKeyJwk));
  const idToken_response = await userOnBoardAuthReq(token, client, publicKeyJwk);
  console.log(idToken_response.id_token);
  const buildParam = await buildParams(client, didDocument);
  let param = {
    from: client.address,
    ...buildParam.param,
  };

  await sendApiTransaction("insertDidDocument", idToken_response.id_token, param, client, () => {
    console.log(buildParam.info.title);
    console.log(buildParam.info.data);
  });
  privateKeyJwk["kid"] = did + "#keys-1";
  const keyObj = { keys: [privateKeyJwk] };
  return {
    didState: {
      state: "finished",
      identifier: did,
      secret: keyObj,
      didDocument: buildParam.info.data,
    },
  };
};

const buildParams = async (client: any, didDoc: object) => {
  const controllerDid = client.did;
  const newDidDocument = await prepareDidDocument(
    controllerDid,
    "publicKeyJwk",
    client.privateKey,
    didDoc
  );

  const { didDocument, timestampDataBuffer, didVersionMetadataBuffer } = newDidDocument;
  console.log(newDidDocument);

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
