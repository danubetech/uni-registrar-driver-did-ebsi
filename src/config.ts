import * as dotenv from 'dotenv';
dotenv.config();
export const config = {
  baseUrl: process.env.uniregistrar_driver_did_ebsi_api_operations_preprod,
  port: process.env.uniregistrar_driver_did_ebsi_port,
  mainnet: process.env.uniregistrar_driver_did_ebsi_api_operations_mainnet,
  testnet: process.env.uniregistrar_driver_did_ebsi_api_operations_test,
  didRegistryApiVersion: process.env.uniregistrar_driver_did_ebsi_didRegistry_api_version,
  tirApiVersion: process.env.uniregistrar_driver_did_ebsi_TIR_api_version,
  ledgerApiVersion: process.env.uniregistrar_driver_did_ebsi_ledger_api_version,
  authorizationApiVersion: process.env.uniregistrar_driver_did_ebsi_authorization_api_version,
  userOnboardingApiVersion: process.env.uniregistrar_driver_did_ebsi_usersOnboarding_api_version,
};