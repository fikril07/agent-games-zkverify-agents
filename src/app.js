"use strict";
const express = require("express");
const { processRequest } = require("./core");

/** Express adapter (local dev, Fly/Railway/Render-style Node hosting). */
const app = express();
app.disable("x-powered-by");

app.get("/", (req, res) => res.json({ ok: true, service: "agentgames-agent", routes: ["/steal/agent", "/gatekeeper/agent"] }));
app.get("/health", (req, res) => res.json({ ok: true }));

for (const kind of ["steal", "gatekeeper"]) {
  app.post(`/${kind}/agent`, express.raw({ type: "*/*", limit: "1mb" }), async (req, res) => {
    try {
      const out = await processRequest(kind, req.body, req.header("x-agent-games-signature"), process.env);
      if (out.signature) res.setHeader("x-agent-games-signature", out.signature);
      res.status(out.status).type("application/json").send(out.body);
    } catch (e) {
      res.status(500).json({ error: "internal error" });
    }
  });
}

module.exports = app;
