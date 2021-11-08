import { sendApiTransaction, remove0xPrefix } from "./utils/utils";
import { buildParams, didRegResponse } from "./utils/didRegistryUtils";
import { userOnBoardAuthReq } from "./userOnboarding";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { ethers } from "ethers";

export const didRegistry = async (
  token: string,
  id_token: string,
  didDocument: object,
  secretKey?: object
): Promise<didRegResponse> => {
  const keyPairs = await EbsiWallet.generateKeyPair({ format: "hex" });
  let client;

  let buffer = secretKey != null ? Buffer.from(secretKey["d"], "base64") : null;
  if (secretKey != null && buffer == null)
    throw new Error("Unsupported key format");
  const privateKey =
    buffer != null ? buffer.toString("hex") : "0x" + keyPairs.privateKey;
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
  const idToken =(await userOnBoardAuthReq(token, client, publicKeyJwk)).id_token;
  console.log(idToken);

  const buildParam = await buildParams({
    publicKey: publicKeyJwk,
    didDoc: didDocument,
    did: client.did,
  });
  let param = {
    from: client.address,
    ...buildParam.param,
  };

  await sendApiTransaction("insertDidDocument", idToken, param, client, () => {
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
