import {ES256KSigner} from '@cef-ebsi/did-jwt';
import {createJWT} from '@cef-ebsi/did-jwt';
import axios from "axios";

const { EbsiWallet } = require("@cef-ebsi/wallet-lib");
const { ethers } = require("ethers");
const elliptic_1 = require("elliptic");
const js_base64_1 = require("js-base64");
const thumbprint_1 = require("jose/jwk/thumbprint");
const base64url = require("base64url");
const {
  createVerifiablePresentation,
} = require("@cef-ebsi/verifiable-presentation");
const canonicalize = require("canonicalize");
const bs58 = require("bs58");
const crypto = require("crypto");
  


export const  createDidAuthResponsePayload=async (input , jwk): Promise<{ResponsePayload:object}>=> {

    const responsePayload = {
      iss: 'https://self-issued.me',
      sub: await getThumbprint(input.hexPrivatekey,jwk.kid),
      aud: input.redirectUri,
      nonce: input.nonce,
      sub_jwk: jwk,
      claims: input.claims,
  };
    return {ResponsePayload:responsePayload};
  }
 
  
  const getJWK = (hexPrivateKey, kid)=> {
    const { x, y } = getECKeyfromHexPrivateKey(hexPrivateKey);
    return {
        kid,
        kty: 'EC',
        crv: 'secp256k1',
        x,
        y,
    };
  }
  
  const getThumbprint = async(hexPrivateKey,kid)=> {
    const jwk = getJWK(hexPrivateKey,kid);
    const thumbprint = await thumbprint_1.calculateThumbprint(jwk, "sha256");
    return thumbprint;
  }

  export const signDidAuthInternal= async (did, payload, hexPrivateKey)=> {
    // check hexPrivateKey is valid
    const request = !!payload.client_id;

    let response = await createJWT({ ...payload }, {
        issuer: 'https://self-issued.me',
        alg: 'ES256K',
        signer: ES256KSigner(hexPrivateKey.replace("0x", "")),
        expiresIn: 5 * 60,
    },
    {
      alg: 'ES256K',
      typ: 'JWT',
      kid: request ? did : `${did}#key-1`
  })
    return response;
}

const  getECKeyfromHexPrivateKey = (hexPrivateKey) => {
    const ec = new elliptic_1.ec("secp256k1");
    const privKey = ec.keyFromPrivate(hexPrivateKey.replace("0x", ""), "hex");
    const pubPoint = privKey.getPublic();
    return {
        x: js_base64_1.Base64.fromUint8Array(pubPoint.getX().toArrayLike(Buffer), true),
        y: js_base64_1.Base64.fromUint8Array(pubPoint.getY().toArrayLike(Buffer), true),
    };
}

export const createVP= async (did,privateKey, vc) =>{
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
}


const extractIatFromJwt = (jwt) => {
  const token = jwt.split(".");
  const payload = base64url.decode(token[1]);
  return JSON.parse(payload).iat;
};

export const serialize=  async (object)=> {
  if (object === null || typeof object !== 'object' || object.toJSON != null) {
    return JSON.stringify(object);
  }
}


export const prepareDidDocument = (didUser, publicKeyType, privateKeyController) => {
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
  const didDocument = {
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
    authentication: [didUser],
    assertionMethod: [`${didUser}#keys-1`],
  };

  const didDocumentBuffer = Buffer.from(JSON.stringify(didDocument));

  const canonicalizedDidDocument = canonicalize(didDocument);

  const canonicalizedDidDocumentBuffer = Buffer.from(canonicalizedDidDocument);
  const canonicalizedDidDocumentHash = ethers.utils.sha256(
    canonicalizedDidDocumentBuffer
  );

  const timestampDataBuffer = Buffer.from(JSON.stringify({ data: "test" }));
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


export const prepareUpdateDidDocument = (didUser, publicKeyType, privateKeyController) => {
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
  const didDocument = {
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
    authentication: [didUser],
    assertionMethod: [`${didUser}#keys-1`],
  };

  const didDocumentBuffer = Buffer.from(JSON.stringify(didDocument));

  const canonicalizedDidDocument = canonicalize(didDocument);

  const canonicalizedDidDocumentBuffer = Buffer.from(canonicalizedDidDocument);
  const canonicalizedDidDocumentHash = ethers.utils.sha256(
    canonicalizedDidDocumentBuffer
  );

  const timestampDataBuffer = Buffer.from(JSON.stringify({ data: "update" }));
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

export const jsonrpcSendTransaction= async(client, token, url, method, param)=> {
  
  const body = jsonrpcBody(method, [param]);
  console.log('start')
  const response = await axios.post(url,body,{headers: {Authorization: `Bearer ${token}`,},});
  console.log('end')
  const unsignedTransaction = response.data.result;
  const uTx = formatEthersUnsignedTransaction(
    JSON.parse(JSON.stringify(unsignedTransaction))
  );
  console.log('unsigned tx')
  console.log(uTx);
  uTx.chainId = Number(uTx.chainId);
  
  const sgnTx = await client.signTransaction(uTx);
  console.log('unsigned tx')
  console.log(sgnTx)
  const bodySend = jsonrpcBody("signedTransaction", [
    paramSignedTransaction(unsignedTransaction, sgnTx),
  ]);
  
  return axios.post(url,bodySend,{headers: {Authorization: `Bearer ${token}`,},});
}

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




