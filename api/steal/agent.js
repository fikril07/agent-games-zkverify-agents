"use strict";
const { makeHandler } = require("../_handler");
module.exports = makeHandler("steal");
module.exports.config = { api: { bodyParser: false } };
