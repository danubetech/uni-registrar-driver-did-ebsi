import { createServer } from "./server";
const PORT = 9080;

createServer()
  .then((server) => {
    server.listen(PORT, () => {
      console.log(
        `⚡️[server]: Server is running at https://localhost:${PORT}`
      );
    });
  })
  .catch((err) => {
    console.error(`Error: ${err}`);
  });
