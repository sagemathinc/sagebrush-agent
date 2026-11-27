#!/usr/bin/env node
// sagebrush-agent: the chat agent (bin/sagebrush-agent-chat.mjs; its usage is there), or, as `sagebrush-agent host run |
// reset-identity`, the host daemon's root commands (lib/fleet/host/host-main.mjs).
//
// This file's static graph is node-check alone: each mode is loaded only once it is chosen, so host mode, run as root,
// loads none of the chat agent's modules (its server, Claude, WebSocket, notebooks or tasks) and runs none of their
// initializers.

import "../lib/node-check.mjs"; // (first: an old Node.js is said before anything else loads)

if (process.argv[2] === "host") process.exit(await (await import("../lib/fleet/host/host-main.mjs")).main(process.argv.slice(3)));
else await import("./sagebrush-agent-chat.mjs");
