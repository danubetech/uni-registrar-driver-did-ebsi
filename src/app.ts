//
import express from "express";
//import { revokerRouter } from "./revokerRouter/Revoker.router";
//import { verifierRouter } from "./verifierRouter/Verifier.router";
import { registerDid,didUpdateDoc } from "./router/didRegistry.router";
// rest of the code remains same
const app = express();
const PORT = 9080;
app.use(express.json());
app.use("/1.0/create", registerDid);
app.use("/1.0/update", didUpdateDoc);

app.get("/", (req, res) => res.send("Express + TypeScript Server"));
app.listen(PORT, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${PORT}`);
});
