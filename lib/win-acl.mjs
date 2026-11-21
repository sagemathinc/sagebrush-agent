// Windows: whether a folder is private to this account, by its owner and its access list (DACL), read by SID, which
// doesn't depend on the system's language, through Windows PowerShell's Get-Acl at its absolute System32 path (never
// one found on PATH). POSIX hosts check modes instead (codex-fetch.mjs, runner-fetch.mjs); nothing here runs there.
// Anything that can't be read, or read as expected, is a problem: the check never passes by default.

import { spawnSync } from "node:child_process";
import { win32 } from "node:path";

/** The SIDs, besides this account's own, that may hold access to a private folder. */
export const TRUSTED = Object.freeze({ SYSTEM: "S-1-5-18", ADMINISTRATORS: "S-1-5-32-544" });
// (CREATOR OWNER: a placeholder an inherit-only entry names, which Windows replaces with each new child's creator)
const CREATOR_OWNER = "S-1-3-0";
const SID = /^S-1-[0-9]+(-[0-9]+)+$/;

/** What the access part of a security descriptor's SDDL (`dacl`) says: "present" (a DACL, its entries read as
 *  rules), "null" (D:NO_ACCESS_CONTROL: a null DACL, which lets everyone do anything), "absent" (no D: part at all,
 *  which Windows treats the same way), or "unreadable". Only "present" can be private. */
export function daclState(dacl) {
  if (typeof dacl !== "string") return "unreadable";
  if (!dacl.startsWith("D:")) return dacl === "" ? "absent" : "unreadable";
  return dacl.includes("NO_ACCESS_CONTROL") ? "null" : "present";
}

/** Why `item` ({owner, dacl, rules: [{sid, type, rights, inheritOnly}]}, as Get-Acl reads it) isn't private to `user`,
 *  or null. It has a DACL (a null or absent one gives everyone access, whatever the rules list says); the owner is
 *  `user` (or Administrators, which own what an elevated administrator makes); every Allow entry that grants anything
 *  names `user`, SYSTEM or Administrators. An inherit-only entry counts too, since the folder's new children inherit
 *  it, except CREATOR OWNER's, which becomes their creator. Deny entries take nothing away. */
export function aclVerdict(item, user) {
  if (!item || typeof item !== "object" || !SID.test(user ?? "")) return "the access list couldn't be read";
  const dacl = daclState(item.dacl);
  if (dacl === "null" || dacl === "absent") return `it has ${dacl === "null" ? "a null" : "no"} access list, so anyone may use it`;
  if (dacl !== "present") return "the access list couldn't be read";
  if (item.owner !== user && item.owner !== TRUSTED.ADMINISTRATORS) return `it is owned by ${item.owner ?? "nobody"}, not this account`;
  if (!Array.isArray(item.rules)) return "the access list couldn't be read";
  for (const r of item.rules) {
    if (!r || !SID.test(r.sid ?? "") || (r.type !== "Allow" && r.type !== "Deny") || !Number.isSafeInteger(r.rights)) return "the access list couldn't be read";
    if (r.type !== "Allow" || r.rights === 0) continue;
    if (r.sid === user || r.sid === TRUSTED.SYSTEM || r.sid === TRUSTED.ADMINISTRATORS) continue;
    if (r.sid === CREATOR_OWNER && r.inheritOnly === true) continue;
    return `it gives access to ${r.sid}`;
  }
  return null;
}

// (the PowerShell side: the paths as JSON on stdin; out, this account's SID and each path's owner, the access part of
//  its SDDL (whether it has a DACL at all) and its rules, by SID)
const SCRIPT = `$ErrorActionPreference = 'Stop'
$paths = @([Console]::In.ReadToEnd() | ConvertFrom-Json)
$sid = [System.Security.Principal.SecurityIdentifier]
$items = @()
foreach ($p in $paths) {
  $a = Get-Acl -LiteralPath $p
  $rules = @($a.GetAccessRules($true, $true, $sid) | ForEach-Object { @{ sid = $_.IdentityReference.Value; type = [string]$_.AccessControlType; rights = [int]$_.FileSystemRights; inheritOnly = (($_.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) } })
  $dacl = $a.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
  $items += ,@{ path = $p; owner = $a.GetOwner($sid).Value; dacl = [string]$dacl; rules = $rules }
}
@{ user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; items = $items } | ConvertTo-Json -Depth 6 -Compress`;

/** Windows PowerShell by its absolute path: %SystemRoot% (a drive's absolute path, else C:\Windows), never PATH. */
export function powershellPath(env = process.env) {
  const root = env.SystemRoot ?? env.SYSTEMROOT;
  const base = typeof root === "string" && /^[A-Za-z]:\\[^"<>|?*]*$/.test(root) ? root : "C:\\Windows";
  return win32.join(base, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

/** Why the folders and files `paths` aren't all private to this account, or null; one PowerShell call for all of them.
 *  `run` is spawnSync's shape (for the rows). */
export function windowsPrivateProblem(paths, { run = spawnSync, env = process.env, timeoutMs = 30000 } = {}) {
  const encoded = Buffer.from(SCRIPT, "utf16le").toString("base64");
  let r;
  try {
    r = run(powershellPath(env), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
      { input: JSON.stringify(paths), encoding: "utf8", timeout: timeoutMs, windowsHide: true, maxBuffer: 1 << 20 });
  } catch (e) { return `its access list couldn't be read (${e?.code ?? e?.message ?? e})`; }
  if (!r || r.error || r.status !== 0) return `its access list couldn't be read (${r?.error?.code ?? `exit ${r?.status ?? r?.signal}`})`;
  let out;
  try { out = JSON.parse(String(r.stdout).trim()); } catch { return "its access list couldn't be read (unexpected output)"; }
  const items = Array.isArray(out?.items) ? out.items : out?.items ? [out.items] : [];
  if (items.length !== paths.length) return "its access list couldn't be read (an answer is missing)";
  for (let i = 0; i < paths.length; i++) {
    if (items[i]?.path !== paths[i]) return "its access list couldn't be read (answers out of order)";
    const why = aclVerdict({ owner: items[i].owner, dacl: items[i].dacl, rules: Array.isArray(items[i].rules) ? items[i].rules : items[i].rules ? [items[i].rules] : [] }, out.user);
    if (why) return `${paths[i]}: ${why}`;
  }
  return null;
}
