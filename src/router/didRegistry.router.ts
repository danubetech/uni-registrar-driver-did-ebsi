import express, { Request, Response } from "express";

import { didRegistry,didUpdate } from "../didRegistry";


export const registerDid = express.Router();

registerDid.post("/", async (req: Request, res: Response) => {
  try {
    const response =await  didRegistry(req.body.secret.token,req.body.secret.id_token);
    //console.log(req.body.data)
    //const response = await initializer.initialize(req.body.credential);
    try {
      console.log(response)
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



export const didUpdateDoc = express.Router();

didUpdateDoc.post("/", async (req: Request, res: Response) => {
  try {
    const response =await  didUpdate(req.body.secret.toke,req.body.secret.id_token,req.body.identifier, req.body.secret.privateKey);
    //console.log(req.body.data)
    //const response = await initializer.initialize(req.body.credential);
    try {
      console.log(response)
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
