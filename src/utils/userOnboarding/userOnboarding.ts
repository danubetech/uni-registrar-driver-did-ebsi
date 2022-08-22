import { JwkKeyFormat } from "../types";
import { ES256K, OIDC_ISSUE} from "../constants";
import { prepareJWSPayload, signJWS,decrypt } from "../signingUtils";
import { ES256KSigner } from "@cef-ebsi/did-jwt";
import {
  createAuthenticationRequest,
  getVerifiableCredential,
  siopPayload,
  getEncryptedToken,
  buildVPJwtPayload,
  createJwtVP
} from "./onboardingUtils";
import {config} from '../../config';

export const userOnBoardAuthReq = async (
  token: string,
  did: string,
  publicKeyJwk: JwkKeyFormat,
  privateKey: any,
  baseUrl: string
): Promise<{ id_token: string }> => {
  console.log("User onboarding initiated");

  const ebsiOnboardingUrl =`${baseUrl}/users-onboarding/${config.userOnboardingApiVersion}/authentication-requests`;
  const ebsiDidResolverUrl=`${baseUrl}/did-registry/${config.didRegistryApiVersion}/identifiers`;
  const ebsiTIRUrl=`${baseUrl}/trusted-issuers-registry/${config.tirApiVersion}/issuers`;
  
  const authReq = await createAuthenticationRequest(did, publicKeyJwk,ebsiOnboardingUrl,"#key-1");
  //("------------------------------------------------------------------------------------------------");
  // signs payload using internal libraries
  //const jwt = await signDidAuthInternal(did, authReq.payload, privateKey);
  const signature = await signJWS(
    authReq.jwtPayload,
    ES256K,
    ES256KSigner(privateKey.replace("0x", ""))
  );
  const jwt = [authReq.jwtPayload, signature].join(".");

  //("------------------------------------------------------------------------------------------------");

  const verifiableCredential = (await getVerifiableCredential(authReq.payload.aud, jwt, token))
    .verifiableCredential;

  const vpJwtPayload = await buildVPJwtPayload(did,verifiableCredential,"#key-1")
  //("------------------------------------------------------------------------------------------------");

  //const verifiablePresentation = await createVP(did, privateKey, verifiableCredntial);


  const signatureVP = await signJWS(vpJwtPayload, ES256K, ES256KSigner(privateKey.replace("0x", "")));

  // signature is response from driver

  const verifiablePresentation = await createJwtVP(did,signature,vpJwtPayload,"#key-1");

  //("------------------------------------------------------------------------------------------------");
  console.log(verifiablePresentation);

  const siopPayloadRequest = await siopPayload(verifiablePresentation, publicKeyJwk, did,ebsiDidResolverUrl,baseUrl);
  const payloadSIOP = siopPayloadRequest.payload;
  //("------------------------------------------------------------------------------------------------");
  // signs payload using internal libraries
  //const jwtSIOP = await signDidAuthInternal(did, payloadSIOP, privateKey);

  let signingPayloadSIOP = await prepareJWSPayload(
    { ...payloadSIOP },
    {
      issuer: OIDC_ISSUE,
      alg: ES256K,
      expiresIn: 5 * 60,
    },
    {
      alg: ES256K,
      typ: "JWT",
      kid: `${did}#key-1`,
    }
  );
  const signatureSIOP = await signJWS(
    signingPayloadSIOP,
    ES256K,
    ES256KSigner(privateKey.replace("0x", ""))
  );
  const jwtSIOP = [signingPayloadSIOP, signatureSIOP].join(".");

  //("------------------------------------------------------------------------------------------------");

  const encryptedToken = await getEncryptedToken({vp:verifiablePresentation,...payloadSIOP}, jwtSIOP);

  const decrypted = await decrypt(
    encryptedToken.siopResponse.response.ake1_enc_payload,
    privateKey
  ).catch((error) => {
    console.log(error);
    throw Error(error);
  });
  const decryptedObject = JSON.parse(decrypted);
  if (decryptedObject.nonce !== encryptedToken.siopResponse.nonce)
    throw new Error("Invalid decrypted values");
  
  return { id_token: decryptedObject.access_token };
};
