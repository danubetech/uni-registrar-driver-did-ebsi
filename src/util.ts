import { ES256KSigner, createJWT } from "@cef-ebsi/did-jwt";
import axios from "axios";

const { EbsiWallet } = require("@cef-ebsi/wallet-lib");
const { ethers } = require("ethers");
const elliptic_1 = require("elliptic");
const js_base64_1 = require("js-base64");
const base64url = require("base64url");
const buffer_1 = require("buffer");

const {
  createVerifiablePresentation,
} = require("@cef-ebsi/verifiable-presentation");
const canonicalize = require("canonicalize");
const bs58 = require("bs58");
const crypto = require("crypto");
const thumbprint_1 = require("jose/jwk/thumbprint");

const getJWK = (hexPrivateKey, kid) => {
  const { x, y } = getECKeyfromHexPrivateKey(hexPrivateKey);
  return {
    kid,
    kty: "EC",
    crv: "secp256k1",
    x,
    y,
  };
};

const getThumbprint = async (hexPrivateKey, kid) => {
  const jwk = getJWK(hexPrivateKey, kid);
  const thumbprint = await thumbprint_1.calculateThumbprint(jwk, "sha256");
  return thumbprint;
};

export const signDidAuthInternal = async (did, payload, hexPrivateKey) => {
  // check hexPrivateKey is valid
  const request = !!payload.client_id;

  let response = await createJWT(
    { ...payload },
    {
      issuer: "https://self-issued.me",
      alg: "ES256K",
      signer: ES256KSigner(hexPrivateKey.replace("0x", "")),
      expiresIn: 5 * 60,
    },
    {
      alg: "ES256K",
      typ: "JWT",
      kid: request ? did : `${did}#key-1`,
    }
  );
  return response;
};

const getECKeyfromHexPrivateKey = (hexPrivateKey) => {
  const ec = new elliptic_1.ec("secp256k1");
  const privKey = ec.keyFromPrivate(hexPrivateKey.replace("0x", ""), "hex");
  const pubPoint = privKey.getPublic();
  return {
    x: js_base64_1.Base64.fromUint8Array(
      pubPoint.getX().toArrayLike(Buffer),
      true
    ),
    y: js_base64_1.Base64.fromUint8Array(
      pubPoint.getY().toArrayLike(Buffer),
      true
    ),
  };
};

export const createVP = async (did, privateKey, vc) => {
  const options = {
    resolver: `https://api.preprod.ebsi.eu/did-registry/v2/identifiers`,
    tirUrl: `https://api.preprod.ebsi.eu/trusted-issuers-registry/v2/issuers`,
  };
  const requiredProof = {
    type: "EcdsaSecp256k1Signature2019",
    proofPurpose: "assertionMethod",
    verificationMethod: `${did}#keys-1`,
  };
  const presentation = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: "VerifiablePresentation",
    verifiableCredential: [vc],
    holder: did,
  };
  const vpSigner = ES256KSigner(privateKey);

  const jwtdata = await createJWT(
    presentation,
    {
      alg: "ES256K",
      issuer: did,
      signer: vpSigner,
      // canonicalize: true,
    },
    {
      alg: "ES256K",
      typ: "JWT",
      kid: `${options.resolver}/${did}#keys-1`,
    }
  );

  const vpToken = jwtdata.split(".");

  const signatureValue = {
    proofValue: `${vpToken[0]}..${vpToken[2]}`,
    proofValueName: "jws",
    iat: extractIatFromJwt(jwtdata),
  };
  return createVerifiablePresentation(
    presentation,
    requiredProof,
    signatureValue,
    options
  );
};

const extractIatFromJwt = (jwt) => {
  const token = jwt.split(".");
  const payload = base64url.decode(token[1]);
  return JSON.parse(payload).iat;
};

export const serialize = async (object) => {
  if (object === null || typeof object !== "object" || object.toJSON != null) {
    return JSON.stringify(object);
  }
};

export const prepareDidDocument = async (
  didUser,
  publicKeyType,
  privateKeyController,
  reqDidDoc
) => {
  let publicKey;
  const controller = new ethers.Wallet(privateKeyController);
  switch (publicKeyType) {
    case "publicKeyHex":
      publicKey = { publicKeyHex: controller.publicKey.slice(2) };
      break;
    case "publicKeyJwk":
      publicKey = {
        publicKeyJwk: new EbsiWallet(controller.privateKey).getPublicKey({
          format: "jwk",
        }),
      };
      break;
    case "publicKeyBase58":
      publicKey = {
        publicKeyBase58: bs58.encode(
          fromHexString(controller.publicKey.slice(2))
        ),
      };
      break;
    default:
      throw new Error(`invalid type ${publicKeyType}`);
  }
  const didDocument = await (
    await constructDidDoc(didUser, publicKey, reqDidDoc)
  ).didDoc;

  const didDocumentBuffer = Buffer.from(JSON.stringify(didDocument));

  const canonicalizedDidDocument = canonicalize(didDocument);

  const canonicalizedDidDocumentBuffer = Buffer.from(canonicalizedDidDocument);
  const canonicalizedDidDocumentHash = ethers.utils.sha256(
    canonicalizedDidDocumentBuffer
  );

  const timestampDataBuffer = Buffer.from(JSON.stringify({ time: Date.now() }));
  const didVersionMetadata = {
    meta: crypto.randomBytes(32).toString("hex"),
  };
  const didVersionMetadataBuffer = Buffer.from(
    JSON.stringify(didVersionMetadata)
  );

  return {
    didDocument,
    didDocumentBuffer,
    canonicalizedDidDocument,
    canonicalizedDidDocumentBuffer,
    canonicalizedDidDocumentHash,
    controllerDid: didUser,
    timestampDataBuffer,
    didVersionMetadata,
    didVersionMetadataBuffer,
  };
};

const constructDidDoc = async (
  didUser: string,
  publicKey: object,
  didDocument: object
): Promise<{ didDoc: object }> => {
  if (didDocument == null || Object.keys(didDocument).length < 3)
    return { didDoc: defaultDidDoc(didUser, publicKey) };
  else {
    //\\ TODO: construct the did doc and insert the key properly
    let doc: object = didDocument;
    if (!("@context" in didDocument) || doc["@context"].length == 0)
      doc["@context"] = [
        "https://w3id.org/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ];
    doc["id"] = didUser;
    doc["verificationMethod"] = [
      {
        id: `${didUser}#keys-1`,
        type: "Secp256k1VerificationKey2018",
        controller: didUser,
        ...publicKey,
      },
    ];
    if (!("authentication" in didDocument) || doc["authentication"].length == 0)
      doc["authentication"] = [`${didUser}#keys-1`];
    if (
      !("assertionMethod" in didDocument) ||
      doc["assertionMethod"].length == 0
    )
      doc["assertionMethod"] = [`${didUser}#keys-1`];
    return { didDoc: doc };
  }
};

const defaultDidDoc = (didUser: string, publicKey: object) => {
  return {
    "@context": "https://w3id.org/did/v1",
    id: didUser,
    verificationMethod: [
      {
        id: `${didUser}#keys-1`,
        type: "Secp256k1VerificationKey2018",
        controller: didUser,
        ...publicKey,
      },
    ],
    authentication: [`${didUser}#keys-1`],
    assertionMethod: [`${didUser}#keys-1`],
  };
};

export const prepareUpdateDidDocument = async (
  didUser,
  publicKeyType,
  privateKeyController,
  flag: string,
  didDoc: any | null
) => {
  let didDocument;

  didDocument =
    didDoc == null || Object.keys(didDoc).length < 3
      ? await resolveDid(didUser)
      : didDocument;

  if (flag == "updateKey") {
    didDocument = await resolveDid(didUser);
    console.log("resolved Did Doc");
    console.log(didDocument);
    let publicKey;
    const controller = new ethers.Wallet(privateKeyController);
    switch (publicKeyType) {
      case "publicKeyHex":
        publicKey = { publicKeyHex: controller.publicKey.slice(2) };
        break;
      case "publicKeyJwk":
        publicKey = {
          publicKeyJwk: new EbsiWallet(controller.privateKey).getPublicKey({
            format: "jwk",
          }),
        };
        break;
      case "publicKeyBase58":
        publicKey = {
          publicKeyBase58: bs58.encode(
            fromHexString(controller.publicKey.slice(2))
          ),
        };
        break;
      default:
        throw new Error(`invalid type ${publicKeyType}`);
    }
    didDocument["verificationMethod"] = {
      id: `${didUser}#keys-1`,
      type: "Secp256k1VerificationKey2018",
      controller: didUser,
      ...publicKey,
    };
  }

  const didDocumentBuffer = Buffer.from(JSON.stringify(didDocument));

  const canonicalizedDidDocument = canonicalize(didDocument);

  const canonicalizedDidDocumentBuffer = Buffer.from(canonicalizedDidDocument);
  const canonicalizedDidDocumentHash = ethers.utils.sha256(
    canonicalizedDidDocumentBuffer
  );

  const timestampDataBuffer = Buffer.from(JSON.stringify({ time: Date.now() }));
  const didVersionMetadata = {
    meta: crypto.randomBytes(32).toString("hex"),
  };
  const didVersionMetadataBuffer = Buffer.from(
    JSON.stringify(didVersionMetadata)
  );

  return {
    didDocument,
    didDocumentBuffer,
    canonicalizedDidDocument,
    canonicalizedDidDocumentBuffer,
    canonicalizedDidDocumentHash,
    controllerDid: didUser,
    timestampDataBuffer,
    didVersionMetadata,
    didVersionMetadataBuffer,
  };
};

function fromHexString(hexString) {
  const match = hexString.match(/.{1,2}/g);
  if (!match) throw new Error("String could not be parsed");
  return new Uint8Array(match.map((byte) => parseInt(byte, 16)));
}

export const jsonrpcSendTransaction = async (
  client,
  token,
  url,
  method,
  param
) => {
  const body = jsonrpcBody(method, [param]);
  console.log(JSON.stringify(param));
  const response = await axios.post(url, body, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const unsignedTransaction = response.data.result;
  const uTx = formatEthersUnsignedTransaction(
    JSON.parse(JSON.stringify(unsignedTransaction))
  );
  console.log("unsigned tx");
  console.log(uTx);
  uTx.chainId = Number(uTx.chainId);

  const sgnTx = await client.signTransaction(uTx);
  console.log("signed tx");
  console.log(sgnTx);
  const bodySend = jsonrpcBody("signedTransaction", [
    paramSignedTransaction(unsignedTransaction, sgnTx),
  ]);

  return axios.post(url, bodySend, {
    headers: { Authorization: `Bearer ${token}` },
  });
};

export function jsonrpcBody(method, params) {
  return {
    jsonrpc: "2.0",
    method,
    params,
    id: Math.ceil(Math.random() * 1000),
  };
}

function formatEthersUnsignedTransaction(unsignedTransaction) {
  return {
    to: unsignedTransaction.to,
    data: unsignedTransaction.data,
    value: unsignedTransaction.value,
    nonce: Number(unsignedTransaction.nonce),
    chainId: Number(unsignedTransaction.chainId),
    gasLimit: unsignedTransaction.gasLimit,
    gasPrice: unsignedTransaction.gasPrice,
  };
}

function paramSignedTransaction(tx, sgnTx) {
  const { r, s, v } = ethers.utils.parseTransaction(sgnTx);
  return {
    protocol: "eth",
    unsignedTransaction: tx,
    r,
    s,
    v: `0x${Number(v).toString(16)}`,
    signedRawTransaction: sgnTx,
  };
}

export const resolveDid = async (
  did: string
): Promise<{ didDocument: object }> => {
  const url = "https://api.preprod.ebsi.eu/did-registry/v2/identifiers/";
  const encodedDid = "did%3Aebsi%3A" + did.split(":")[2];
  console.log(`${url + encodedDid}`);
  const response = await axios.get(url + encodedDid, {
    headers: { "Content-Type": "application/did+ld+json" },
  });
  return response.data.didDoc;
};

export const remove0xPrefix = (str) =>
  str.startsWith("0x") ? str.slice(2) : str;

export const base64ToBase64Url = (privateKey) => {
  const privateKeyBuffer = privateKey.toArrayLike(buffer_1.Buffer);
  return privateKeyBuffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
};

export async function getLedgerTx(txId, token) {
  const url = `https://api.preprod.ebsi.eu/ledger/v2/blockchains/besu`;
  const body = jsonrpcBody("eth_getTransactionReceipt", txId);
  const response = await axios.post(url, body, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (response.status > 400) throw new Error(response.data);
  const receipt = response.data.result;
  if (receipt && Number(receipt.status) !== 1) {
    console.log(`Transaction failed: Status ${receipt.status}`);
    if (receipt.revertReason)
      console.log(
        `revertReason: ${Buffer.from(
          receipt.revertReason.slice(2),
          "hex"
        ).toString()}`
      );
  }
  return receipt;
}

export async function createAuthenticationResponse(didAuthResponseCall) {
  if (
    !didAuthResponseCall ||
    !didAuthResponseCall.hexPrivatekey ||
    !didAuthResponseCall.did ||
    !didAuthResponseCall.redirectUri
  )
    throw new Error("Invalid parmas");
  const payload = await createAuthenticationResponsePayload(
    didAuthResponseCall
  );
  // signs payload using internal libraries
  const jwt = await signDidAuthInternal(
    didAuthResponseCall.did,
    payload,
    didAuthResponseCall.hexPrivatekey
  );
  const params = `id_token=${jwt}`;
  let uriResponse = {
    urlEncoded: "",
    bodyEncoded: "",
    encoding: "application/x-www-form-urlencoded",
    response_mode: didAuthResponseCall.response_mode
      ? didAuthResponseCall.response_mode
      : "fragment", // FRAGMENT is the default
  };
  if (didAuthResponseCall.response_mode === "form_post") {
    uriResponse.urlEncoded = encodeURI(didAuthResponseCall.redirectUri);
    uriResponse.bodyEncoded = encodeURI(params);
    return uriResponse;
  }
  if (didAuthResponseCall.response_mode === "query") {
    uriResponse.urlEncoded = encodeURI(
      `${didAuthResponseCall.redirectUri}?${params}`
    );
    return uriResponse;
  }
  uriResponse.response_mode = "fragment";
  uriResponse.urlEncoded = encodeURI(`${jwt}`);
  return uriResponse;
}

async function createAuthenticationResponsePayload(input) {
  const responsePayload = {
    iss: "https://self-issued.me",
    sub: await getThumbprint(input.hexPrivatekey, null),
    aud: input.redirectUri,
    nonce: input.nonce,
    sub_jwk: getJWK(input.hexPrivatekey, `${input.did}#key-1`),
    claims: input.claims,
  };
  return responsePayload;
}
