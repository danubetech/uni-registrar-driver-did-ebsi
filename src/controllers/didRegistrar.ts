import { Request, Response } from "express";

import { didRegistry } from "../services/didRegistry";
import { didUpdate } from "../services/didUpdate";

export const create = async (req: Request, res: Response): Promise<void> => {
  console.log(req.body);
  if (req.body.secret == null) throw "Invalid params";
  console.log(req.body);
  const pk = req.body.secret.privateKey ? req.body.secret.privateKey : null;
  await didRegistry(
    req.body.secret.token,
    req.body.didDocument,
    req.body.secret.privateKey
  )
    .then((success) => {
      console.log(JSON.stringify(success, null, 2));
      res.status(200).send(success);
    })
    .catch((error) => {
      console.log(error);
      res.status(500).send(error);
    });
};

export const update = async (req: Request, res: Response): Promise<void> => {
  console.log(req.body);
  if (req.body.secret == null) throw "Invalid params";
  await didUpdate(
    req.body.secret.token,
    req.body.identifier,
    req.body.secret.privateKey,
    req.body.didDocument,
    req.body.options
  )
    .then((success) => {
      console.log(JSON.stringify(success, null, 2));
      res.status(200).send(success);
    })
    .catch((error) => {
      console.log(error);
      res.status(500).send(error);
    });
};

export const deactivate = async (req: Request, res: Response) => {
  console.log("Not implemented");
  res.status(400).send("Not implemented");
};
