// Windows: a process started inside a job object, so that its whole tree ends with it. Windows has no process groups
// to signal, and taskkill /T misses a process whose parent has already gone; a job object with KILL_ON_JOB_CLOSE ends
// every process in it, orphans included, when its last handle closes.
//
// Node can't make a job object itself, so a small helper does: Windows PowerShell, at its absolute System32 path (never
// PATH), runs FIXED source (SOURCE below, compiled by Add-Type). The helper creates the job, puts itself in it, then
// starts the target with the caller's argv, folder and environment; the target inherits the helper's standard handles,
// which are the caller's pipes, so nothing comes between the caller and the target's stdin, stdout and stderr. The
// helper waits for the target and exits with its code. So the job (and every process the target started) ends when:
// the target exits; the caller kills the helper (Stop: child.kill() of what jobSpawn returns); or the caller itself
// ends, since the helper watches the caller's process (its handle, opened while the caller is alive, and its creation
// time, which must be before the helper's own, so a reused pid isn't taken for it).
//
// If the job can't be made, the helper writes one "sagebrush-job: <why>" line to stderr and exits with JOB_REFUSED,
// before the target exists. Callers refuse then; there is never a fallback to a tree outside a job.
// The script (its command line) is fixed, the same for every target: nothing variable is ever in it, so nothing of the
// target's (its argv, folder or environment, which may hold credentials) shows in a command line or a logged script.
// The target's spec travels in one variable of the helper's own environment, SAGEBRUSH_JOB_SPEC (base64 JSON), which
// the script reads and then removes from its own environment; the target gets exactly the spec's environment.

import { spawn } from "node:child_process";
import { powershellPath } from "./win-acl.mjs";

/** The helper's exit code when it couldn't make or join the job: the target was never started. */
export const JOB_REFUSED = 5458506; // ("SBJ")

export const SOURCE = String.raw`
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class SagebrushJob {
  [StructLayout(LayoutKind.Sequential)] struct BASIC { public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass; }
  [StructLayout(LayoutKind.Sequential)] struct IOC { public ulong a, b, c, d, e, f; }
  [StructLayout(LayoutKind.Sequential)] struct EXT { public BASIC Basic; public IOC Io; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateJobObjectW(IntPtr attributes, IntPtr name);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref EXT info, uint length);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
  [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint ms);
  const uint KILL_ON_JOB_CLOSE = 0x2000, SYNCHRONIZE = 0x100000, QUERY_LIMITED_INFORMATION = 0x1000, INFINITE = 0xFFFFFFFF;
  const int EXTENDED_LIMIT_INFORMATION = 9;

  // One argument as CommandLineToArgvW reads it back (the rules every C runtime's argv follows).
  static string Quote(string a) {
    if (a.Length > 0 && a.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0) return a;
    var sb = new StringBuilder("\"");
    int slashes = 0;
    foreach (char c in a) {
      if (c == '\\') { slashes++; continue; }
      if (c == '"') { sb.Append('\\', slashes * 2 + 1); sb.Append('"'); }
      else { sb.Append('\\', slashes); sb.Append(c); }
      slashes = 0;
    }
    sb.Append('\\', slashes * 2);
    sb.Append('"');
    return sb.ToString();
  }

  public static int Run(string file, string[] args, string cwd, string[] keys, string[] values, int parentPid) {
    IntPtr job = CreateJobObjectW(IntPtr.Zero, IntPtr.Zero);
    if (job == IntPtr.Zero) throw new Exception("CreateJobObject failed (" + Marshal.GetLastWin32Error() + ")");
    var info = new EXT();
    info.Basic.LimitFlags = KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, EXTENDED_LIMIT_INFORMATION, ref info, (uint)Marshal.SizeOf(typeof(EXT)))) throw new Exception("SetInformationJobObject failed (" + Marshal.GetLastWin32Error() + ")");
    if (!AssignProcessToJobObject(job, GetCurrentProcess())) throw new Exception("AssignProcessToJobObject failed (" + Marshal.GetLastWin32Error() + ")");
    // (the caller: its handle opened now, while it is alive; a process created after this helper can't be it)
    IntPtr parent = OpenProcess(SYNCHRONIZE | QUERY_LIMITED_INFORMATION, false, parentPid);
    if (parent == IntPtr.Zero) throw new Exception("the agent that started this is gone");
    long pc, me, x1, x2, x3;
    if (!GetProcessTimes(parent, out pc, out x1, out x2, out x3) || !GetProcessTimes(GetCurrentProcess(), out me, out x1, out x2, out x3) || pc > me) throw new Exception("the agent that started this is gone");
    var psi = new ProcessStartInfo(file);
    psi.UseShellExecute = false;
    var line = new StringBuilder();
    foreach (var a in args) { if (line.Length > 0) line.Append(' '); line.Append(Quote(a)); }
    psi.Arguments = line.ToString();
    if (!string.IsNullOrEmpty(cwd)) psi.WorkingDirectory = cwd;
    psi.Environment.Clear();
    for (int i = 0; i < keys.Length; i++) psi.Environment[keys[i]] = values[i];
    var target = Process.Start(psi);
    var watch = new Thread(() => { WaitForSingleObject(parent, INFINITE); Environment.Exit(1); });
    watch.IsBackground = true;
    watch.Start();
    target.WaitForExit();
    return target.ExitCode;
  }
}
`;

/** The helper's environment variable that carries the target's spec. */
export const SPEC_VAR = "SAGEBRUSH_JOB_SPEC";
// (Windows' limit on one environment variable's value, in characters)
const VAR_MAX = 32767;

/** The PowerShell script: SOURCE as it is, then the spec read from SPEC_VAR. Fixed: the same text for every target. */
export function jobScript() {
  return `$ErrorActionPreference = 'Stop'
try {
  Add-Type -TypeDefinition @'
${SOURCE}
'@ -Language CSharp
  $data = [Environment]::GetEnvironmentVariable('${SPEC_VAR}')
  [Environment]::SetEnvironmentVariable('${SPEC_VAR}', $null)
  $s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($data)) | ConvertFrom-Json
  $code = [SagebrushJob]::Run([string]$s.file, [string[]]@($s.args), [string]$s.cwd, [string[]]@($s.keys), [string[]]@($s.values), [int]$s.parent)
  exit $code
} catch {
  [Console]::Error.WriteLine('sagebrush-job: ' + $_.Exception.Message)
  exit ${JOB_REFUSED}
}
`;
}

// (the fixed command line, encoded once)
const ENCODED = Buffer.from(jobScript(), "utf16le").toString("base64");

/** child_process.spawn's shape, on Windows: `cmd` started inside a job object by the helper (above). What it returns is
 *  the helper: its stdio are the target's (inherited), its exit code the target's (or JOB_REFUSED), and killing it ends
 *  the whole tree. The target's environment is `opts.env` (else this process's), set whole. The helper's command line
 *  is fixed; the spec is in its environment (SPEC_VAR), never in its argv. */
export function jobSpawn(cmd, args = [], opts = {}, { spawnFn = spawn, env = process.env } = {}) {
  const targetEnv = opts.env ?? env;
  const keys = Object.keys(targetEnv);
  const spec = { file: cmd, args: args.map(String), cwd: opts.cwd ?? "", keys, values: keys.map((k) => String(targetEnv[k])), parent: process.pid };
  const data = Buffer.from(JSON.stringify(spec), "utf8").toString("base64");
  if (data.length > VAR_MAX) throw new Error("the program's arguments and environment are too large to start it in a job object");
  // (the helper's own environment is this process's, plus the spec: PowerShell needs SystemRoot and the rest)
  const helperEnv = { ...env };
  for (const k of Object.keys(helperEnv)) if (k.toUpperCase() === SPEC_VAR) delete helperEnv[k];
  helperEnv[SPEC_VAR] = data;
  return spawnFn(powershellPath(env), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", ENCODED],
    { cwd: opts.cwd, env: helperEnv, stdio: opts.stdio, windowsHide: true });
}

/** child_process.spawn on POSIX; jobSpawn on Windows: the way a tree this agent starts is started. */
export const treeSpawn = (cmd, args, opts) => (process.platform === "win32" ? jobSpawn(cmd, args, opts) : spawn(cmd, args, opts));

/** The words for a helper that couldn't make the job, or null for any other exit. */
export function jobRefusal(code, stderr = "") {
  if (code !== JOB_REFUSED) return null;
  const why = String(stderr).split("\n").find((l) => l.startsWith("sagebrush-job: "))?.slice("sagebrush-job: ".length).trim();
  return `Windows couldn't put it in a job object${why ? ` (${why})` : ""}, so it wasn't started: without one, its processes could outlive it`;
}
