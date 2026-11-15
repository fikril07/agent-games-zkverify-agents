"use strict";
const { makeHandler } = require("../_handler");
module.exports = makeHandler("gatekeeper");
module.exports.config = { api: { bodyParser: false } };
