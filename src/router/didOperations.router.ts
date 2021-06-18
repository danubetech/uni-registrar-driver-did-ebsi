import express, { Request, Response } from "express";

import { didRegistry } from "../didRegistry";
import { didUpdate } from "../didUpdate";
export const registerDid = express.Router();

registerDid.post("/", async (req: Request, res: Response) => {
  try {
    if (req.body.secret == null) throw "Invalid params";
    console.log(req.body);
    const response = await didRegistry(
      req.body.secret.token,
      req.body.secret.id_token,
      req.body.didDocument
    );
    try {
      console.log(response);
      res.send(response);
    } catch (e) {
      res.sendStatus(500);
    }
  } catch (error) {
    res.sendStatus(500);
  }
});

export const didUpdateDoc = express.Router();

didUpdateDoc.post("/", async (req: Request, res: Response) => {
  console.log(req.body);
  if (req.body.secret == null) throw "Invalid params";
  try {
    const response = await didUpdate(
      req.body.secret.token,
      req.body.secret.id_token,
      req.body.identifier,
      req.body.secret.privateKey,
      req.body.didDocument,
      req.body.options.flag
    );
    //console.log(req.body.data)
    //const response = await initializer.initialize(req.body.credential);
    try {
      console.log(response);
      res.send(response);
    } catch (e) {
      res.status(500);
    }
  } catch (error) {
    console.log("error");
    console.log(error);
    res.status(500).send(error);
  }
});
