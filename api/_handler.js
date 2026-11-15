"use strict";
const { processRequest } = require("../src/core");

/** Shared Vercel adapter: reads the RAW body (bodyParser disabled) so the
 * platform HMAC over the exact bytes can be verified. */
function makeHandler(kind) {
  const handler = async (req, res) => {
    if (req.method !== "POST") { res.status(405).json({ error: "method not allowed" }); return; }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks);
    try {
      const out = await processRequest(kind, rawBody, req.headers["x-agent-games-signature"], process.env);
      if (out.signature) res.setHeader("x-agent-games-signature", out.signature);
      res.status(out.status).setHeader("content-type", "application/json").send(out.body);
    } catch {
      res.status(500).json({ error: "internal error" });
    }
  };
  return handler;
}

module.exports = { makeHandler };
