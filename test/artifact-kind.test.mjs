// The artifact a written file becomes beside the chat: Markdown as markdown, a board as a board (the page shows it with
// its Open, not as JSON), anything else as code in its extension's language.
import test from "node:test";
import assert from "node:assert/strict";
import { artifactKind } from "../lib/turns.mjs";

test("artifactKind: markdown, board, code", () => {
  assert.deepEqual(artifactKind("/notes/a.md"), { kind: "markdown" });
  assert.deepEqual(artifactKind("/primes.board.json"), { kind: "board" });
  assert.deepEqual(artifactKind("/Primes.BOARD.JSON"), { kind: "board" });
  assert.deepEqual(artifactKind("/data.json"), { kind: "code", lang: "json" });
  assert.deepEqual(artifactKind("/sin.m"), { kind: "code", lang: "m" });
});
