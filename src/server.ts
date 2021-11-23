import express from "express";

import * as OpenApiValidator from "express-openapi-validator";
import { Express } from "express-serve-static-core";
import { connector, summarise } from "swagger-routes-express";
import YAML from "yamljs";
import * as api from "./controllers";
import swaggerUi from "swagger-ui-express";

export async function createServer(): Promise<Express> {
  const yamlSpecFile = "./api/openapi.yml";
  const apiDefinition = YAML.load(yamlSpecFile);
  const apiSummary = summarise(apiDefinition);
  console.info(apiSummary);

  const server = express();
  server.use(express.json());

  // setup API validator
  const validatorOptions = {
    apiSpec: yamlSpecFile,
    validateRequests: true,
    validateResponses: true,
  };
  server.use(OpenApiValidator.middleware(validatorOptions));

  // error customization, if request is invalid
  server.use(
    (
      err: any,
      req: express.Request,
      res: express.Response,
      next: express.NextFunction
    ) => {
      console.log(err);
      res.status(err.status).json({
        error: {
          type: "request_validation",
          message: err.message,
          errors: err.errors,
        },
      });
    }
  );

  server.use(
    "/api-documents",
    swaggerUi.serve,
    swaggerUi.setup(apiDefinition)
  );

  const connect = connector(api, apiDefinition, {
    onCreateRoute: (method: string, descriptor: any[]) => {
      console.log(
        `${method}: ${descriptor[0]} : ${(descriptor[1] as any).name}`
      );
    },
  });

  connect(server);

  return server;
}
