import express, { Request, Response } from "express";

import { userOnBoardAuthReq, signer, keyGen } from "../utils/helperAPI";
export const onboarding = express.Router();

onboarding.post("/", async (req: Request, res: Response) => {
  try {
    if (req.body.token == null) throw "Invalid params";
    console.log(req.body);

    const response = await userOnBoardAuthReq(req.body.token);
    try {
      console.log(JSON.stringify(response));
      res.send(response);
    } catch (e) {
      res.sendStatus(500);
    }
  } catch (error) {
    res.sendStatus(500);
  }
});

export const signing = express.Router();
signing.post("/", async (req: Request, res: Response) => {
  try {
    if (req.body.unSigned == null) throw "Invalid params";
    console.log(req.body);

    const response = await signer(req.body.unSigned, req.body.privateKey);
    try {
      console.log(JSON.stringify(response));
      res.send(response);
    } catch (e) {
      res.sendStatus(500);
    }
  } catch (error) {
    res.sendStatus(500);
  }
});

export const genKey = express.Router();
genKey.post("/", async (req: Request, res: Response) => {
  try {
    const response = await keyGen();
    try {
      console.log(JSON.stringify(response));
      res.send(response);
    } catch (e) {
      res.sendStatus(500);
    }
  } catch (error) {
    res.sendStatus(500);
  }
});
