"use strict";
const app = require("./src/app");
const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`agentgames-agent listening on :${port}`));
