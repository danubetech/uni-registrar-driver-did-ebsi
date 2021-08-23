import express from "express";
import { registerDid, didUpdateDoc } from "./router/didOperations.router";
import cors = require("cors");

const app = express();
const PORT = 9080;
app.use(cors());
app.use(express.json());
app.use("/1.0/create", registerDid);
app.use("/1.0/update", didUpdateDoc);

app.get("/", (req, res) => res.send("Express + TypeScript Server"));
app.listen(PORT, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${PORT}`);
});
