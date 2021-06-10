//
import express from "express";
//import { revokerRouter } from "./revokerRouter/Revoker.router";
//import { verifierRouter } from "./verifierRouter/Verifier.router";
import { registerDid,didUpdateDoc } from "./router/didRegistry.router";
// rest of the code remains same
const app = express();
const PORT = 5050;
app.use(express.json());
app.use("/ebsi/registerDid", registerDid);
app.use("/ebsi/updateDid", didUpdateDoc);


//app.use("/revocationservicedriver/initialize", initializerRouter);
app.get("/", (req, res) => res.send("Express + TypeScript Server"));
app.listen(PORT, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${PORT}`);
});
