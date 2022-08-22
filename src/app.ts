import { createServer } from "./server";
import {config} from './config'


createServer()
  .then((server) => {
    server.listen(config.port, () => {
      console.log(`EBSI base url ${config.baseUrl}`);
      console.log(`EBSI DID registry api version ${config.didRegistryApiVersion}`);
      console.log(`EBSI tir api version ${config.tirApiVersion}`);
      console.log(`EBSI authorization api version ${config.authorizationApiVersion}`);
      console.log(`EBSI user-onboarding api version ${config.userOnboardingApiVersion}`);
      console.log(`EBSI ledger api version ${config.ledgerApiVersion}`);
      console.log(
        `⚡️[server]: Server is running at https://localhost:${config.port}`
      );
    });
  })
  .catch((err) => {
    console.error(`Error: ${err}`);
  });
