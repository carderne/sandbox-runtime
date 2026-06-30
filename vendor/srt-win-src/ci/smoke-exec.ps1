<#
  Smoke test for `srt-win exec`.

  Self-contained: provisions WFP filters under a fixed test-only
  sublayer GUID and uses `BUILTIN\Administrators` (S-1-5-32-544) as
  the discriminator group SID. We do NOT create a custom group.

  Why Administrators as the group:
    - The custom-group approach can't exercise the WFP fence on
      hosted CI: the runner can't logout/login mid-job, so a freshly
      created group is *absent* from the token (not deny-only). With
      the machine-wide filter shape, an absent-group child is
      PERMITted by the non-member filter — the fence test would lie.
    - `BUILTIN\Administrators` IS in the runner token (the GHA
      Windows runner runs as admin). `srt-win exec` flips it
      deny-only along with the discriminator. The child therefore
      genuinely matches the BLOCK filter and is fenced.
    - It also means the broker pre-flight passes without
      `--skip-group-check` (Admins is enabled in the broker token),
      so we exercise the normal pre-flight path.

  This is a CI-only configuration. Production callers use a
  dedicated group. The `srt-win exec` code path is identical.

  The fixed sublayer GUID lets the workflow's `if: always()`
  cleanup step uninstall any leaked filters even if this script
  throws mid-run.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

# Fixed test-only sublayer; distinct from srt-win's compile-time
# default and from anything smoke.ps1 uses. Referenced verbatim by
# the workflow's always()-cleanup step.
$Sublayer  = '5b0e64f4-09f1-4c2e-8c97-4d2c0f4e9b7d'
$GroupSid  = 'S-1-5-32-544'   # BUILTIN\Administrators
# Loopback PERMIT is scoped to this port range (filter 2). Anything
# on 127.0.0.1 outside it is BLOCKed (filter 3). Match srt-win's
# default but pass it explicitly so this script doesn't drift if
# the default ever changes.
$PortRange = '60080-60089'
$PortLo    = 60080
$PortHi    = 60089

# Bind a TcpListener on the first free port from $candidates.
# Throws if none bind.
function Bind-Listener {
  param([int[]] $Candidates)
  foreach ($p in $Candidates) {
    try {
      $l = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, $p)
      $l.Start()
      return $l
    } catch {
      # port in use — try next
    }
  }
  throw "no free port among: $($Candidates -join ',')"
}

function Run {
  param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J { param([string[]] $argv) Run $argv | ConvertFrom-Json }

# Capture exit code + output without throwing on non-zero.
# `srt-win exec` writes its own diagnostics (self-protect SDDL,
# pre-flight warnings, errors) to stderr with a `srt-win:`
# prefix; the CHILD's output is everything else. We merge
# 2>&1 so nothing is lost, then split:
#   .exit — exit code
#   .raw  — full merged output (use for E-rows that assert on
#           srt-win's own messages: E6 diag, E9, E10, E10b)
#   .out  — child output only (lines NOT starting `srt-win:`),
#           rejoined; use for E-rows that parse what the
#           sandboxed child wrote: E2/E4/E5/E7
function Exec {
  param([string[]] $tail)
  $argv = @('exec', '--group-sid', $GroupSid) + $tail
  $raw = & $Exe @argv 2>&1 | Out-String
  $exit = $LASTEXITCODE
  $lines = $raw -split "`r?`n"
  $child = ($lines | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{
    exit = $exit; raw = $raw; out = $child
  }
}

$cmd  = Join-Path $env:SystemRoot 'System32\cmd.exe'
$pwsh = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# Enable srt-win's per-exec stderr diagnostics (notably the
# self-protect SDDL dump that E6 records). Production callers
# leave this unset; the Exec helper's .out filter tolerates it
# either way.
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'
Write-Host "smoke-exec: group_sid=$GroupSid  sublayer=$Sublayer  exe=$Exe"

# ── precondition: Administrators is enabled in this token ───────
# If the runner ever stops running as admin, the BLOCK filter
# wouldn't apply and E3 would false-pass; fail loudly here instead.
$gs = J @('group','status','--group-sid',$GroupSid)
if ($gs.state -ne 'ready') {
  throw "smoke-exec requires BUILTIN\Administrators enabled in the " +
        "broker token (got state=$($gs.state)). This script depends " +
        "on the GHA Windows runner running elevated."
}

# ── setup: WFP filters under the test sublayer ──────────────────
Run @('wfp','install',
      '--group-sid',$GroupSid,
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange)
$ws = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($ws.state -ne 'installed') {
  throw "wfp not installed under test sublayer: $($ws.state)"
}

# ── E1: exit code propagates verbatim ────────────────────────────
# .raw (not .out) on failure: this is the FIRST exec and srt-win's
# own stderr diagnostics (run_lockdown, self-protect) are the only
# clue when it fails before the child writes anything.
$r = Exec @('--', $cmd, '/c', 'exit 42')
if ($r.exit -ne 42) {
  throw "E1: expected exit 42, got $($r.exit). raw: $($r.raw)"
}
Write-Host 'E1 ok: exit code propagates'

# ── E2: group SID is deny-only in the child's token ──────────────
# `/FO CSV /NH` — machine-parseable, no header. The default table
# format pads columns to the widest value, which the SID column
# won't survive when the runner has long group names.
$r = Exec @('--', $cmd, '/c', 'whoami /groups /FO CSV /NH')
if ($r.exit -ne 0) { throw "E2: whoami exited $($r.exit): $($r.out)" }
$rows = $r.out | ConvertFrom-Csv -Header Name,Type,SID,Attributes
$g = $rows | Where-Object { $_.SID -eq $GroupSid }
if (-not $g) {
  throw "E2: SID $GroupSid not in whoami /groups:`n$($r.out)"
}
if ($g.Attributes -notmatch '(?i)deny') {
  throw "E2: $GroupSid attrs '$($g.Attributes)' — expected " +
        "'Group used for deny only'"
}
Write-Host 'E2 ok: discriminator SID is deny-only in child token'

# ── E3: outbound network blocked when no proxy is configured ─────
$r = Exec @('--', $cmd, '/c', 'curl -sS -m 5 https://example.com')
if ($r.exit -eq 0) {
  throw "E3: outbound curl succeeded under sandbox " +
        "(fence not in effect?). out: $($r.out)"
}
Write-Host "E3 ok: outbound blocked (curl exit=$($r.exit))"

# ── E4: loopback in proxy-port-range permitted ───────────────────
# Bind a real listener on the broker side at an in-range port and
# connect from inside the sandbox — proves filter 2 (PERMIT 127/8
# ∩ port-range) fires. A closed port wouldn't distinguish
# WFP-block from RST, hence the live listener. Try the high half
# of the range to avoid clashing with anything smoke.ps1 binds.
$inRange = Bind-Listener ($PortHi..($PortLo+5))
$portIn  = $inRange.LocalEndpoint.Port
try {
  $r = Exec @('--', $pwsh, '-NoProfile', '-Command',
    "(Test-NetConnection 127.0.0.1 -Port $portIn " +
    "-WarningAction SilentlyContinue).TcpTestSucceeded")
  if ($r.exit -ne 0) {
    throw "E4: Test-NetConnection exited $($r.exit): $($r.out)"
  }
  if ($r.out -notmatch '(?i)\bTrue\b') {
    throw "E4: loopback connect to in-range port $portIn did " +
          "not succeed. out: $($r.out)"
  }
  Write-Host "E4 ok: loopback to in-range port $portIn permitted"
} finally {
  $inRange.Stop()
}

# ── E4b: loopback outside proxy-port-range blocked ───────────────
# Same setup but on a port well outside the range. The listener
# is reachable from the broker (we bind it), but the sandboxed
# child must NOT reach it — filter 3 BLOCKs.
$outRange = Bind-Listener (50000, 50001, 50002, 49999)
$portOut  = $outRange.LocalEndpoint.Port
try {
  $r = Exec @('--', $pwsh, '-NoProfile', '-Command',
    "(Test-NetConnection 127.0.0.1 -Port $portOut " +
    "-WarningAction SilentlyContinue).TcpTestSucceeded")
  if ($r.out -match '(?i)\bTrue\b') {
    throw "E4b: loopback to out-of-range port $portOut " +
          "succeeded (range tightening not in effect?). out: $($r.out)"
  }
  # Sanity: prove the listener was actually live (reachable from
  # the unsandboxed broker), so a False isn't just "port closed".
  $bs = (Test-NetConnection 127.0.0.1 -Port $portOut `
         -WarningAction SilentlyContinue).TcpTestSucceeded
  if (-not $bs) {
    throw "E4b: broker-side connect to its own listener on " +
          "$portOut failed — test invalid"
  }
  Write-Host "E4b ok: loopback to out-of-range port $portOut blocked"
} finally {
  $outRange.Stop()
}

# ── E5: exec forwards the broker's env to the child verbatim ─────
# Proxy config is single-sourced by the TS caller now: `srt-win exec`
# has no --http-proxy/--socks-proxy flags and synthesizes nothing — it
# forwards its OWN environment to the child. Prove that by setting the
# proxy vars in THIS (broker) process and asserting the sandboxed child
# sees the same values. `cmd /c set VAR` prints `VAR=value` if set,
# exits 1 if unset. One Exec per var — no `&` chaining, so this row is
# independent of the cmd-quoting behaviour exercised by E7.

# Set $Var to $Value for the duration of $Body, then restore exactly
# what was there before (including absence).
function Invoke-WithEnv {
  param([string]$Var, [string]$Value, [scriptblock]$Body)
  $had = Test-Path "Env:$Var"
  $old = if ($had) { (Get-Item "Env:$Var").Value } else { $null }
  Set-Item -Path "Env:$Var" -Value $Value
  try { & $Body }
  finally {
    if ($had) { Set-Item -Path "Env:$Var" -Value $old }
    else { Remove-Item -Path "Env:$Var" -ErrorAction SilentlyContinue }
  }
}

function Assert-EnvPassthrough {
  param([string]$Var, [string]$Want)
  Invoke-WithEnv $Var $Want {
    $r = Exec @('--', $cmd, '/c', "set $Var")
    if ($r.exit -ne 0) {
      throw "E5: 'set $Var' exited $($r.exit) (var unset in child?). out: $($r.out)"
    }
    $line = ($r.out -split "`r?`n" |
             Where-Object { $_ -like "$Var=*" } |
             Select-Object -First 1)
    if ($line -ne "$Var=$Want") {
      throw "E5: $Var expected '$Want', got '$line'. full: $($r.out)"
    }
  }
}
# Values are arbitrary — this proves verbatim passthrough; the real
# values come from the TS generateProxyEnvVars. NO_PROXY doubles as the
# regression guard for the old exec blanking it.
Assert-EnvPassthrough 'HTTPS_PROXY' "http://127.0.0.1:$PortLo"
Assert-EnvPassthrough 'NO_PROXY'    'localhost,127.0.0.1'
Write-Host 'E5 ok: exec forwards broker env (incl. proxy set) to child verbatim'

# ── E5b: broker restores the twin casing of *_PROXY vars ────────
# The host spawn layer (Node/bun child_process on win32) keeps only ONE
# casing of an env key, but Cygwin/MSYS2 children have case-sensitive
# environments whose tools read the lowercase names — so exec appends
# the missing twin (identical value, never invented). The broker process
# itself can only hold one casing (Win32 env is case-insensitive), so
# setting HTTP_PROXY here and finding BOTH casings in the child proves
# the repair. `set http` lists matching vars with their STORED casing;
# -clike is the case-SENSITIVE match.
Invoke-WithEnv 'HTTP_PROXY' "http://127.0.0.1:$PortLo" {
  $r = Exec @('--', $cmd, '/c', 'set http')
  if ($r.exit -ne 0) {
    throw "E5b: 'set http' exited $($r.exit). out: $($r.out)"
  }
  $lines = $r.out -split "`r?`n"
  if (-not ($lines | Where-Object { $_ -clike 'http_proxy=*' })) {
    throw "E5b: lowercase http_proxy twin missing in child. out: $($r.out)"
  }
  if (-not ($lines | Where-Object { $_ -clike 'HTTP_PROXY=*' })) {
    throw "E5b: uppercase HTTP_PROXY missing in child. out: $($r.out)"
  }
}
Write-Host 'E5b ok: broker restores the lowercase twin of proxy vars for the child'

# ── E6: self-protect — child cannot OpenProcess the broker ──────
# The child discovers the broker by walking its parent-process chain
# by NAME (the depth differs between cmd / powershell / git-bash
# children, so no fixed hop count). Win32_Process.ParentProcessId is
# readable without any handle on the broker itself, so discovery does
# not depend on the access self-protect denies. The probe then
# P/Invokes OpenProcess directly with PROCESS_VM_READ — an unambiguous
# mask that the broker-only DACL must deny. (`.NET Process.Handle`
# is NOT sufficient: it lazily falls back to
# PROCESS_QUERY_LIMITED_INFORMATION, which can succeed via paths
# the DACL doesn't fully gate; that produced a false "OPENED"
# on the previous CI run.)
$probe = @'
$bp = 0
$why = ''
$cur = $PID
for ($i = 0; $i -lt 6; $i++) {
  $p = Get-CimInstance Win32_Process -Filter "ProcessId=$cur" -ErrorAction SilentlyContinue
  if (-not $p) { $why = "WMI query failed at pid $cur (hop $i)"; break }
  if ($p.Name -eq 'srt-win.exe') { $bp = [int]$p.ProcessId; break }
  if (-not $p.ParentProcessId) { $why = "no parent beyond pid $cur (hop $i)"; break }
  $cur = $p.ParentProcessId
}
if ($bp -eq 0) {
  if (-not $why) { $why = 'hop cap reached without finding srt-win.exe' }
  Write-Output "NOBROKER: $why"
  exit 0
}
$sig = '[DllImport("kernel32.dll",SetLastError=true)]public static extern System.IntPtr OpenProcess(uint a,bool b,uint p);'
$k32 = Add-Type -MemberDefinition $sig -Name K32 -Namespace W -PassThru
# 0x0010 = PROCESS_VM_READ
$h = $k32::OpenProcess(0x0010, $false, $bp)
$le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if ($h -ne [System.IntPtr]::Zero) {
  Write-Output "OPENED:vm_read handle=$h"
} elseif ($le -eq 5) {
  Write-Output "DENIED:vm_read le=5"
} else {
  Write-Output "OTHER:vm_read le=$le"
}
# Also try PROCESS_QUERY_LIMITED_INFORMATION (0x1000) so the CI
# log records whether THAT is granted — not asserted on, but
# useful diagnostic for the threat model.
$h2 = $k32::OpenProcess(0x1000, $false, $bp)
$le2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Output "INFO:limited_query handle=$h2 le=$le2"
'@
$r = Exec @('--', $pwsh, '-NoProfile', '-Command', $probe)
# self_protect.rs eprintln!s the applied SDDL to stderr; that
# line is in .raw (filtered out of .out by the `srt-win:`
# prefix). Surface it here so the DACL is visible next to the
# probe result.
$sddl = ($r.raw -split "`r?`n" |
         Where-Object { $_ -match 'self-protect applied' }) -join ' '
Write-Host "E6 broker DACL: $sddl"
Write-Host "E6 probe output: $($r.out.Trim())"
if ($r.out -match 'NOBROKER') {
  $reason = ($r.out -split "`r?`n" |
             Where-Object { $_ -match '^NOBROKER' }) -join ' '
  throw "E6: broker discovery failed — $reason. raw: $($r.raw)"
}
if ($r.out -match 'OPENED:vm_read') {
  throw "E6: child got PROCESS_VM_READ on broker " +
        "(self-protect ineffective). raw: $($r.raw)"
}
if ($r.out -notmatch 'DENIED:vm_read') {
  throw "E6: expected ACCESS_DENIED (5) for PROCESS_VM_READ. " +
        "raw: $($r.raw)"
}
Write-Host 'E6 ok: child denied PROCESS_VM_READ on broker'

# ── E7: cmd.exe /c passthrough — user-quoted payload survives ───
# build_cmdline wraps the post-/c content in ONE outer "…" pair
# for /s to strip; inner content is verbatim. The `&` is inside
# the user's own "…" so cmd treats it literally.
$r = Exec @('--', $cmd, '/d', '/s', '/c', 'echo "x & y"')
if ($r.exit -ne 0) { throw "E7 exited $($r.exit): $($r.out)" }
$got = $r.out.Trim()
if ($got -ne '"x & y"') {
  throw "E7: expected literal '`"x & y`"', got '$got'"
}
Write-Host 'E7 ok: user-quoted payload passes through verbatim'

# ── E7b: cmd metachar passthrough — `&` works as separator ──────
# By design: the post-/c string is the user's cmd command, NOT
# escaped. `&` chains commands inside the *sandboxed* cmd.exe.
# This is not the Phase-6 N1 host-shell injection — that
# concerned the OUTER spawn (solved by argv-mode in batch 03);
# the child here IS the sandbox.
$r = Exec @('--', $cmd, '/d', '/s', '/c', 'echo MARKER & exit 5')
if ($r.exit -ne 5) {
  throw "E7b: expected exit 5 from chained command, got $($r.exit). " +
        "out: $($r.out)"
}
if ($r.out.Trim() -notlike 'MARKER*') {
  throw "E7b: expected MARKER in output. out: $($r.out)"
}
Write-Host 'E7b ok: & chains commands inside sandboxed cmd (passthrough)'

# ── E7c: target_is_cmd recognises trailing-dot cmd.exe. ──────────
# Win32 strips trailing dots/spaces from the final path component
# but Path::file_name() does not; without target_is_cmd's trim,
# `cmd.exe.` would take the MSVCRT-quoting branch and the post-/c
# `&` chain would be wrapped as one literal argv element instead
# of passed through for cmd to interpret. Same payload as E7b.
$r = Exec @('--', "$cmd.", '/d', '/s', '/c', 'echo MARKER & exit 5')
if ($r.exit -ne 5 -or $r.out.Trim() -notlike 'MARKER*') {
  throw "E7c: trailing-dot cmd.exe. did NOT take the cmd-quoting " +
        "branch (target_is_cmd trim missing). exit=$($r.exit) " +
        "out: $($r.out)"
}
Write-Host 'E7c ok: target_is_cmd recognises trailing-dot cmd.exe.'

# ── E8: --name resolution path through exec ─────────────────────
# Every row above used --group-sid. Run one row via --name to cover
# `resolve_group_sid`'s LookupAccountNameW branch in the exec path.
# `BUILTIN\Administrators` resolves on every Windows install.
$r = & $Exe exec --name 'BUILTIN\Administrators' -- $cmd /c 'exit 7' 2>&1
if ($LASTEXITCODE -ne 7) {
  throw "E8: --name exec expected exit 7, got $LASTEXITCODE. out: $r"
}
Write-Host 'E8 ok: --name resolution path through exec works'

# ── E9: refuse to nest — exec from inside exec fails fast ───────
# Inside the sandbox child, the discriminator SID is deny-only;
# the inner `srt-win exec` pre-flight (no --skip-group-check) must
# refuse with the deny-only message.
$inner = "`"$Exe`" exec --group-sid $GroupSid -- $cmd /c exit 0"
$r = Exec @('--', $cmd, '/c', $inner)
if ($r.exit -eq 0) {
  throw "E9: nested exec succeeded; expected refusal. raw: $($r.raw)"
}
# The deny-only refusal comes from the INNER srt-win's stderr,
# which is `srt-win:`-prefixed and therefore in .raw (filtered
# out of .out — the filter can't distinguish inner-vs-outer
# srt-win lines).
if ($r.raw -notmatch '(?i)deny-only') {
  throw "E9: nested exec failed but not with the deny-only " +
        "message. raw: $($r.raw)"
}
Write-Host 'E9 ok: nested exec refused (deny-only guard)'

# ── E10: --skip-group-check is silent when group is ready ───────
# The flag must not break the run and must NOT warn when the
# group is in fact enabled (warning fires only on Absent).
$r = & $Exe exec --group-sid $GroupSid `
        --skip-group-check -- $cmd /c 'exit 0' 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
  throw "E10: --skip-group-check run exited ${LASTEXITCODE}: $r"
}
if ($r -match '(?i)WARNING:.*skip-group-check') {
  throw "E10: warning fired despite group being ready. out: $r"
}
Write-Host 'E10 ok: --skip-group-check silent when group is ready'

# ── E10b: --skip-group-check warns when group is ABSENT ─────────
# A well-formed but unmapped SID (alias RID 9999 doesn't exist)
# is Absent in the broker token. With the flag, exec must warn
# and proceed (exit = child's). Without the flag it would refuse
# — that path is covered by E9's deny-only refusal; the Absent
# refusal differs only in the message.
$r = & $Exe exec --group-sid S-1-5-32-9999 `
        --skip-group-check -- $cmd /c 'exit 0' 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
  throw "E10b: --skip-group-check + absent group exited ${LASTEXITCODE}: $r"
}
if ($r -notmatch '(?i)WARNING:.*skip-group-check') {
  throw "E10b: expected absent-group warning. out: $r"
}
Write-Host 'E10b ok: --skip-group-check warns when group is absent'

# (E11* removed: exec no longer pre-flights `wfp status` — BFE
# enumeration is admin-gated. The fence is verified BEHAVIORALLY by
# `wfp verify` at session start; that path is the V1 row below.)

# TODO E12: verify mitigation policies actually applied (child-side
#   GetProcessMitigationPolicy probe). Deferred — would need a
#   helper binary or P/Invoke from inside the sandboxed PowerShell.

# ── R-rows: --as-sandbox-user two-hop launch ────────────────────
# E1-E11 above exercised the same-user deny-only-group path. The
# R-rows provision the dedicated `srt-sandbox` account (one
# `srt-win install` under the same test sublayer, idempotent on the
# group filters already there) and exercise the two-hop: broker →
# CreateProcessWithLogonW(runner) → runner → restricted-token →
# child. The same-user path is unchanged — these rows are additive.

# CreateProcessWithLogonW routes through the Secondary Logon
# service. GHA runners have it; ensure it's running (idempotent).
try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke-exec: WARNING: Start-Service seclogon: $_"
}

# Full install under the test sublayer: provisions srt-sandbox +
# sandbox-runtime-users + DPAPI cred + setup marker + the user-SID
# WFP filter pair (F-USER-BLOCK / F-USER-LOOPBACK). The group-SID
# filters from `wfp install` above are left in place.
Run @('install',
      '--group-sid',$GroupSid,
      '--sublayer-guid',$Sublayer,
      '--proxy-port-range',$PortRange)
$us = J @('user','status')
if (-not $us.user.exists) { throw 'R: srt-sandbox not provisioned' }
$sbSid = $us.marker_user_sid
if (-not $sbSid) { throw 'R: setup marker missing user_sid' }
Write-Host "R: sandbox user provisioned (sid=$sbSid)"

# ── V1: wfp verify — behavioral egress-block probe ──────────────
# The non-elevated readiness check that replaced exec's WFP
# pre-flight. The block-user filter from `install` above fires at
# ALE_AUTH_CONNECT → WSAEACCES → exit 0 + "blocked". stderr (the
# runner's BLOCKED line) flows to the host so it's in the CI log;
# stdout is JUST the JSON line. `--target` is required: bind a
# local listener on an out-of-range loopback port (same shape as
# the product path — `verifyWindowsWfpEgress` does this in TS).
$v1Lsn = Bind-Listener (49990..49999)
$v1Tgt = "127.0.0.1:$($v1Lsn.LocalEndpoint.Port)"
$vout = & $Exe wfp verify --target $v1Tgt
$vexit = $LASTEXITCODE
$v1Lsn.Stop()
Write-Host "V1: wfp verify --target $v1Tgt exit=$vexit stdout='$vout'"
if ($vexit -ne 0) {
  throw "V1: wfp verify expected exit 0 (blocked), got $vexit"
}
$v = $vout | ConvertFrom-Json
if ($v.egress_probe -ne 'blocked') {
  throw "V1: wfp verify expected egress_probe=blocked, got '$($v.egress_probe)'"
}
Write-Host 'V1 ok: wfp verify reports egress_probe=blocked'

# Exec helper for the two-hop path. Same .exit/.raw/.out shape as
# Exec; adds --as-sandbox-user. The broker forwards exactly what it
# is told via --env (it does NOT enumerate its own environment), so
# pass PATH/PATHEXT here — same overlay the TS wrapper builds.
#
# Watchdog: the two-hop chain (broker → CPWLW runner → restricted
# child) has no console; a hang anywhere inside it would otherwise
# sit until the GHA job timeout. 30s is generous — every R-row
# payload is sub-second. System.Diagnostics.Process (not the `&`
# call operator or Start-Process) so we get (a) WaitForExit with a
# timeout and (b) per-element ArgumentList quoting that survives
# PATH-with-spaces.
function RExec {
  param([string[]] $tail)
  # No --group-sid: RExec is the SandboxUser path; --group-sid is the
  # SameUser-mode discriminator and is mutually exclusive with
  # --as-sandbox-user.
  $argv = @('exec',
            '--as-sandbox-user',
            '--env', "PATH=$($env:PATH)",
            '--env', "PATHEXT=$($env:PATHEXT)") + $tail
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName               = $Exe
  $psi.UseShellExecute        = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.Environment['SANDBOX_RUNTIME_WIN_DEBUG'] = '1'
  foreach ($a in $argv) { $null = $psi.ArgumentList.Add($a) }
  $p  = [System.Diagnostics.Process]::Start($psi)
  # Drain both pipes concurrently so a full pipe buffer can't wedge
  # WaitForExit.
  $so = $p.StandardOutput.ReadToEndAsync()
  $se = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit(30000)) {
    try { $p.Kill($true) } catch { }
    $p.WaitForExit()
    throw ("RExec: TIMEOUT after 30s. argv: $($argv -join ' ')`n" +
           "stderr: $($se.Result)`nstdout: $($so.Result)")
  }
  $exit  = $p.ExitCode
  $raw   = $so.Result + $se.Result
  $lines = $raw -split "`r?`n"
  $child = ($lines | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{ exit = $exit; raw = $raw; out = $child }
}

# ── R1: child runs as srt-sandbox ───────────────────────────────
$r = RExec @('--', $cmd, '/c', 'whoami /user /FO CSV /NH')
if ($r.exit -ne 0) { throw "R1: whoami exited $($r.exit). raw: $($r.raw)" }
$row = $r.out | ConvertFrom-Csv -Header Name,SID
if ($row.SID -ne $sbSid) {
  throw "R1: child user SID $($row.SID), expected $sbSid. raw: $($r.raw)"
}
if ($r.out -match $GroupSid) {
  # The discriminator group is the REAL user's; the sandbox user
  # is not a member. (whoami /user prints user only, so this is
  # belt-and-braces against output bleed.)
  throw "R1: discriminator SID found in child whoami. raw: $($r.raw)"
}
Write-Host "R1 ok: two-hop child runs as srt-sandbox (sid=$($row.SID))"

# ── R2: stdio piped broker ← runner ← child ─────────────────────
$r = RExec @('--', $cmd, '/c', 'echo R2-STDOUT-MARK & echo R2-STDERR-MARK 1>&2')
if ($r.out -notmatch 'R2-STDOUT-MARK') {
  throw "R2: stdout marker missing. raw: $($r.raw)"
}
if ($r.raw -notmatch 'R2-STDERR-MARK') {
  throw "R2: stderr marker missing. raw: $($r.raw)"
}
Write-Host 'R2 ok: stdout+stderr piped through runner to broker'

# ── R3: exit code propagates broker ← runner ← child ────────────
$r = RExec @('--', $cmd, '/c', 'exit 23')
if ($r.exit -ne 23) {
  throw "R3: expected exit 23, got $($r.exit). raw: $($r.raw)"
}
Write-Host 'R3 ok: child exit code propagates through runner'

# ── R4: env-merge — USERPROFILE isolated, PATH overlaid ─────────
# LOGON_WITH_PROFILE gives the runner the sandbox user's profile
# env (USERPROFILE/TEMP under C:\Users\srt-sandbox). The broker's
# PATH is overlaid via the spec so tools resolve. Probe both.
$r = RExec @('--', $cmd, '/c', 'echo UP=%USERPROFILE%& echo PATH=%PATH%')
if ($r.out -notmatch '(?i)UP=.*srt-sandbox') {
  throw "R4: USERPROFILE not isolated to srt-sandbox. out: $($r.out)"
}
if ($r.out -notmatch '(?i)PATH=.*System32') {
  throw "R4: PATH overlay missing System32. out: $($r.out)"
}
Write-Host 'R4 ok: USERPROFILE isolated, broker PATH overlaid'

# ── R5: outbound blocked by F-USER-BLOCK ────────────────────────
# The user-SID WFP filter (installed by `srt-win install` above)
# blocks all srt-sandbox egress except in-range loopback. No proxy
# env in this row, so the child's direct curl must fail.
$r = RExec @('--', $cmd, '/c', 'curl -sS -m 5 https://example.com')
if ($r.exit -eq 0) {
  throw "R5: outbound curl succeeded under --as-sandbox-user " +
        "(F-USER-BLOCK not in effect?). out: $($r.out)"
}
Write-Host "R5 ok: outbound blocked for srt-sandbox (curl exit=$($r.exit))"

# ── R5b: in-range loopback permitted (the via-proxy half) ────────
# F-USER-LOOPBACK permits srt-sandbox → 127.0.0.1:<port∈range>; the
# JS proxy binds there. R5 proved the BLOCK; this proves the PERMIT
# the proxy path rides on. (The e2e curl-via-proxy → 200 lives in
# winsrt.test.ts H-rows where the JS proxy actually runs.)
$inRangeR = Bind-Listener ($PortHi..($PortLo+5))
$portInR  = $inRangeR.LocalEndpoint.Port
try {
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command',
    "(Test-NetConnection 127.0.0.1 -Port $portInR " +
    "-WarningAction SilentlyContinue).TcpTestSucceeded")
  if ($r.out -notmatch '(?i)\bTrue\b') {
    throw "R5b: loopback to in-range port $portInR did not succeed " +
          "(F-USER-LOOPBACK not in effect?). raw: $($r.raw)"
  }
  Write-Host "R5b ok: in-range loopback permitted for srt-sandbox (port=$portInR)"
} finally {
  $inRangeR.Stop()
}

# ── R9: child cannot OpenProcess(PROCESS_CREATE_PROCESS) on a ────
#        real-user process (cross-user boundary)
# ── R9b: child cannot OpenProcess(PROCESS_CREATE_PROCESS) on the ─
#        RUNNER (runner self-protect — would let the child
#        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS-spawn under the
#        runner's unrestricted token and escape job/winsta/mitigations)
# R9 targets THIS pwsh process (real user, default DACL — same role
# explorer.exe plays on a desktop session; the GHA runner may not
# have explorer running). R9b finds the runner by walking the
# child's parent chain to the first srt-win.exe.
$hostPid = $PID
$probeR9 = @"
`$sig = '[DllImport("kernel32.dll",SetLastError=true)]public static extern System.IntPtr OpenProcess(uint a,bool b,uint p);'
`$k32 = Add-Type -MemberDefinition `$sig -Name K32R -Namespace W -PassThru
function Probe([string]`$tag, [int]`$targetPid) {
  # 0x0080 = PROCESS_CREATE_PROCESS
  `$h = `$k32::OpenProcess(0x0080, `$false, `$targetPid)
  `$le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (`$h -ne [System.IntPtr]::Zero) { "OPENED:`$tag pid=`$targetPid" }
  elseif (`$le -eq 5)                { "DENIED:`$tag pid=`$targetPid" }
  else                               { "OTHER:`$tag pid=`$targetPid le=`$le" }
}
`$rp = 0
`$cur = `$PID
for (`$i = 0; `$i -lt 8; `$i++) {
  `$p = Get-CimInstance Win32_Process -Filter "ProcessId=`$cur" -ea SilentlyContinue
  if (-not `$p) { break }
  if (`$p.Name -eq 'srt-win.exe') { `$rp = [int]`$p.ProcessId; break }
  if (-not `$p.ParentProcessId) { break }
  `$cur = `$p.ParentProcessId
}
Probe 'real-user' $hostPid
if (`$rp -eq 0) { 'NORUNNER' } else { Probe 'runner' `$rp }
"@
$r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR9)
Write-Host "R9 probe output: $($r.out.Trim())"
if ($r.out -match 'OPENED:real-user') {
  throw "R9: child got PROCESS_CREATE_PROCESS on a real-user " +
        "process (cross-user boundary breached). raw: $($r.raw)"
}
if ($r.out -notmatch 'DENIED:real-user') {
  throw "R9: expected ACCESS_DENIED for real-user target. raw: $($r.raw)"
}
Write-Host 'R9 ok: child denied PROCESS_CREATE_PROCESS on real-user process'
if ($r.out -match 'NORUNNER') {
  throw "R9b: runner discovery failed. raw: $($r.raw)"
}
if ($r.out -match 'OPENED:runner') {
  throw "R9b: child got PROCESS_CREATE_PROCESS on the runner " +
        "(runner self-protect ineffective — sandbox escape). raw: $($r.raw)"
}
if ($r.out -notmatch 'DENIED:runner') {
  throw "R9b: expected ACCESS_DENIED for runner target. raw: $($r.raw)"
}
Write-Host 'R9b ok: child denied PROCESS_CREATE_PROCESS on the runner (self-protect holds)'

# ── R11: child cannot OpenProcess(PROCESS_VM_READ) on a default-DACL ──
#         real-user process (logon-SID strip).
# seclogon stamps the broker's interactive logon SID into the
# runner's token; CreateRestrictedToken disables it so the child
# does NOT match the default per-process logon-session ACE
# (VM_READ|QUERY|TERMINATE) on same-session real-user processes.
# Without the strip the child can ReadProcessMemory the broker's
# browser/shell/host orchestrator. Spawn a fresh victim under the
# broker user so the target is unambiguously default-DACL (no
# harness side effects on its SD).
$victim = Start-Process -FilePath $cmd -ArgumentList '/c','timeout /t 60 >nul' `
            -PassThru -WindowStyle Hidden
try {
  $probeR11 = @"
`$sig = '[DllImport("kernel32.dll",SetLastError=true)]public static extern System.IntPtr OpenProcess(uint a,bool b,uint p);'
`$k32 = Add-Type -MemberDefinition `$sig -Name K32V -Namespace W -PassThru
function Probe([string]`$tag, [uint32]`$mask) {
  `$h = `$k32::OpenProcess(`$mask, `$false, $($victim.Id))
  `$le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if (`$h -ne [System.IntPtr]::Zero) { "OPENED:`$tag" }
  elseif (`$le -eq 5)                { "DENIED:`$tag" }
  else                               { "OTHER:`$tag le=`$le" }
}
# 0x0010 = PROCESS_VM_READ; 0x1000 = PROCESS_QUERY_LIMITED_INFORMATION
Probe 'vm-read'  0x0010
Probe 'query-li' 0x1000
"@
  $r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR11)
  Write-Host "R11 probe output: $($r.out.Trim())"
  if ($r.out -match 'OPENED:vm-read') {
    throw "R11: child got PROCESS_VM_READ on a default-DACL " +
          "real-user process (logon-SID not stripped — child " +
          "can ReadProcessMemory the broker's session). raw: $($r.raw)"
  }
  if ($r.out -notmatch 'DENIED:vm-read') {
    throw "R11: expected ACCESS_DENIED for VM_READ. raw: $($r.raw)"
  }
  if ($r.out -match 'OPENED:query-li') {
    throw "R11: child got PROCESS_QUERY_LIMITED_INFORMATION on a " +
          "default-DACL real-user process. raw: $($r.raw)"
  }
  if ($r.out -notmatch 'DENIED:query-li') {
    throw "R11: expected ACCESS_DENIED for QUERY_LIMITED. raw: $($r.raw)"
  }
  Write-Host ('R11 ok: child denied VM_READ + QUERY_LIMITED on ' +
              'default-DACL real-user process (logon-SID stripped)')
} finally {
  try { $victim.Kill() } catch { }
}

# ── R12: child is on the broker-created srt-sb-* desktop ─────────
# The broker creates `WinSta0\srt-sb-<pid>-<rand>` and passes it via
# CreateProcessWithLogonW's lpDesktop; the runner attaches there and
# the lockdown child inherits. If the child reports `Default`, the
# fail-closed assertion in run_lockdown was bypassed and the child
# can WH_KEYBOARD_LL-hook the interactive desktop (the Job's UI
# limits do NOT gate low-level hooks). The child's own
# GetThreadDesktop name is the substantive check (the runner's
# `caller_desk=` debug line is gated on SANDBOX_RUNTIME_WIN_DEBUG
# in the RUNNER's env, which isn't in the --env overlay).
$probeR12 = @"
`$sig = @'
[DllImport("user32.dll")]public static extern System.IntPtr GetThreadDesktop(uint t);
[DllImport("kernel32.dll")]public static extern uint GetCurrentThreadId();
[DllImport("user32.dll",CharSet=CharSet.Unicode)]public static extern bool GetUserObjectInformationW(System.IntPtr h,int i,System.Text.StringBuilder b,uint n,out uint r);
'@
`$u = Add-Type -MemberDefinition `$sig -Name U32D -Namespace W -PassThru
`$d = `$u::GetThreadDesktop(`$u::GetCurrentThreadId())
`$sb = [System.Text.StringBuilder]::new(256); `$r = 0
[void]`$u::GetUserObjectInformationW(`$d, 2, `$sb, 512, [ref]`$r)
"CHILD_DESK=" + `$sb.ToString()
"@
$r = RExec @('--', $pwsh, '-NoProfile', '-Command', $probeR12)
Write-Host "R12 probe output: $($r.out.Trim())"
if ($r.out -notmatch 'CHILD_DESK=srt-sb-') {
  throw "R12: child not on srt-sb-* desktop — desktop isolation " +
        "broken (WH_KEYBOARD_LL keylogging risk). raw: $($r.raw)"
}
if ($r.out -match 'CHILD_DESK=Default') {
  throw "R12: child on Default desktop. raw: $($r.raw)"
}
Write-Host 'R12 ok: child on broker-created srt-sb-* desktop (not Default)'

# ── R6: child cannot read state.db (sandbox-runtime-users DENY) ──
$stateDb = Join-Path $env:LOCALAPPDATA 'sandbox-runtime\state.db'
if (-not (Test-Path $stateDb)) { throw "R6: $stateDb missing" }
$r = RExec @('--', $cmd, '/c', "type `"$stateDb`"")
if ($r.exit -eq 0) {
  throw "R6: child READ state.db (DENY ACE not in effect?). raw: $($r.raw)"
}
if ($r.raw -notmatch '(?i)access is denied') {
  throw "R6: expected Access is denied. raw: $($r.raw)"
}
Write-Host 'R6 ok: child cannot read state.db (cred file gate holds)'

# (CA trust is install-time, not per-exec — covered in smoke.ps1.)

# ── G-rows: per-session FS access for the sandbox user ──────────
# Under separate-user the sandbox child has NO inherent rights on
# real-user-owned files. `acl grant` adds an inheritable
# MODIFY_NO_FDC ACE on the working-tree root; `acl stamp
# --trustee-sid <real-user>` PROTECTEDs paths inside it. The G-rows
# are the design probe: with grant on the root + PROTECTED stamp on
# a file inside, the child reads siblings but not the stamped file
# AND cannot del/ren the stamped file (the grant lacks FDC) — so
# the per-target parent allow-list is redundant.
$gRoot = Join-Path $env:TEMP "srt-gscratch-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $gRoot -Force | Out-Null
# Expand to the long-form path: $env:TEMP on the GHA runner is
# `C:\Users\RUNNER~1\...` (8.3 short name). The grant lands on the
# canonical (long-form) file object regardless, but the CHILD opens
# by the path we pass it — and resolving an 8.3 component requires
# enumerating the parent dir, which srt-sandbox cannot do for the
# real user's profile. Passing the long form lets bypass-traverse
# (SeChangeNotifyPrivilege) reach the file directly without an
# enumerate step.
$k32 = Add-Type -PassThru -Namespace W -Name K -MemberDefinition `
  '[DllImport("kernel32.dll",CharSet=CharSet.Unicode)] public static extern uint GetLongPathName(string s,System.Text.StringBuilder l,uint n);'
$lp  = [System.Text.StringBuilder]::new(1024)
if ($k32::GetLongPathName($gRoot, $lp, 1024) -gt 0) { $gRoot = $lp.ToString() }
$gSub  = Join-Path $gRoot  'sub'
New-Item -ItemType Directory -Path $gSub -Force | Out-Null
$secret  = Join-Path $gSub 'secret.txt'
$sibling = Join-Path $gSub 'sibling.txt'
$subDeny = Join-Path $gRoot 'sub-deny'
New-Item -ItemType Directory -Path $subDeny | Out-Null
$inDeny  = Join-Path $subDeny 'inner.txt'
$inAllow = Join-Path $subDeny 'reallow.txt'
# NOT -NoNewline: RExec concatenates child stdout + broker stderr
# before line-splitting, so a no-newline file body would fuse with
# the first `srt-win:` diag line and survive the `^srt-win:` filter.
'SECRET'  | Set-Content -Encoding ASCII $secret
'SIBLING' | Set-Content -Encoding ASCII $sibling
'INNER'   | Set-Content -Encoding ASCII $inDeny
'REALLOW' | Set-Content -Encoding ASCII $inAllow
Write-Host "G: scratch=$gRoot  sbSid=$sbSid"
function Stdin { param([string[]] $argv, [string] $json)
  $raw = $json | & $Exe @argv 2>&1 | Out-String
  Write-Host -NoNewline $raw
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited ${LASTEXITCODE}: $raw"
  }
}

try {
  # ── G1: working-tree grant — child can list/read/write inside ────
  Stdin @('acl','grant','--group-sid',$GroupSid,'--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"write`":[`"$($gRoot -replace '\\','\\')`"]}"
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.exit -ne 0 -or $r.out -notmatch 'SIBLING') {
    throw "G1: child read sibling failed. exit=$($r.exit) raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "echo G1-NEW> `"$gSub\new.txt`"")
  if ($r.exit -ne 0 -or -not (Test-Path "$gSub\new.txt")) {
    throw "G1: child write under granted tree failed. raw: $($r.raw)"
  }
  Write-Host 'G1 ok: working-tree MODIFY_NO_FDC grant — child reads + creates inside'

  # ── G2: DENY ACE inside the grant — read denied ──────────────────
  Stdin @('acl','stamp','--group-sid',$GroupSid,'--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"denyRead`":[`"$($secret -replace '\\','\\')`"]}"
  $r = RExec @('--', $cmd, '/c', "type `"$secret`"")
  if ($r.exit -eq 0 -or $r.out -match 'SECRET') {
    throw "G2: child READ the stamped file. raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.out -notmatch 'SIBLING') {
    throw "G2: sibling no longer readable post-stamp. raw: $($r.raw)"
  }
  Write-Host 'G2 ok: DENY ACE + working-tree grant compose — sibling readable, stamped file denied'

  # ── G3: parent-FDC DENY — child cannot del/ren the stamped file ──
  # The stamp adds (D;OICI;FILE_DELETE_CHILD;;;<sb-SID>) on the
  # parent; explicit DENY is evaluated first, so even where the
  # parent inherits an allow-FDC the child has no path through it.
  $r = RExec @('--', $cmd, '/c', "del `"$secret`"")
  if (-not (Test-Path $secret) -or
      (Get-Content -Raw $secret).Trim() -ne 'SECRET') {
    throw "G3: child deleted/altered the stamped file (parent-FDC DENY did not take). raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "ren `"$secret`" gone.txt")
  if (-not (Test-Path $secret) -or (Test-Path "$gSub\gone.txt")) {
    throw "G3: child renamed the stamped file. raw: $($r.raw)"
  }
  Write-Host 'G3 ok: parent-FDC DENY ACE — child cannot del/ren the stamped file'

  # ── G3b: parent-FDC DENY overrides BUILTIN\Users:FA on parent ────
  # The sandbox user is a Users member; without the explicit DENY a
  # parent with Users:(F) would give it FILE_DELETE_CHILD directly
  # (the C:\ProgramData case). The DENY ACE is evaluated before
  # any ALLOW, so the deny still holds.
  $g3bDir  = Join-Path $gRoot 'g3b'
  New-Item -ItemType Directory -Path $g3bDir | Out-Null
  & icacls $g3bDir /grant '*S-1-5-32-545:(OI)(CI)(F)' | Out-Null
  $g3bFile = Join-Path $g3bDir 'sec.txt'
  'G3B' | Set-Content -Encoding ASCII $g3bFile
  Stdin @('acl','stamp','--group-sid',$GroupSid,'--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"denyRead`":[`"$($g3bFile -replace '\\','\\')`"]}"
  $r = RExec @('--', $cmd, '/c', "del `"$g3bFile`"")
  if (-not (Test-Path $g3bFile) -or
      (Get-Content -Raw $g3bFile).Trim() -ne 'G3B') {
    throw "G3b: child deleted file under Users:FA parent (DENY did not override). raw: $($r.raw)"
  }
  $r = RExec @('--', $cmd, '/c', "type `"$g3bFile`"")
  if ($r.exit -eq 0 -or $r.out -match 'G3B') {
    throw "G3b: child READ file under Users:FA parent. raw: $($r.raw)"
  }
  Write-Host 'G3b ok: parent-FDC DENY overrides inherited BUILTIN\Users:(F) on parent'

  # ── G4: broker (real user) can still read the stamped file ───────
  if ((Get-Content -Raw $secret).Trim() -ne 'SECRET') {
    throw 'G4: broker lost read on the stamped file'
  }
  Write-Host 'G4 ok: real-user trustee keeps full access to stamped file'

  # ── G5: directory deny — (OI)(CI) DENY ACE covers the subtree; ───
  # allowWithinDeny via grant on an inner file.
  Stdin @('acl','stamp','--group-sid',$GroupSid,'--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"denyRead`":[`"$($subDeny -replace '\\','\\')`"]}"
  Stdin @('acl','grant','--group-sid',$GroupSid,'--holder-pid',$PID,
          '--sandbox-user-sid',$sbSid) `
        "{`"read`":[`"$($inAllow -replace '\\','\\')`"]}"
  # Instrumentation: dump exactly what landed on the inner file
  # post dir-stamp + inner-grant. The icacls/SDDL pair shows the
  # explicit srt-sandbox ALLOW ACE alongside the inherited DENY
  # ACE; the child-side `if exist` tells us whether
  # bypass-traverse through the denied dir works. Kept on the
  # success path too — the dump is the proof for the design claim
  # (explicit ALLOW is evaluated before inherited DENY).
  Write-Host "G5 diag: icacls $inAllow ->"
  & icacls $inAllow
  Write-Host "G5 diag: inAllow Sddl=$((Get-Acl $inAllow).Sddl)"
  Write-Host "G5 diag: subDeny Sddl=$((Get-Acl $subDeny).Sddl)"
  $r = RExec @('--', $cmd, '/c',
    "whoami /priv | findstr /i SeChangeNotify")
  Write-Host "G5 diag: child SeChangeNotify=$($r.out)"
  $r = RExec @('--', $cmd, '/c', "type `"$inDeny`"")
  if ($r.exit -eq 0 -or $r.out -match 'INNER') {
    throw "G5: child read file under denied dir. raw: $($r.raw)"
  }
  # Combined probe: echo the path the child sees + if-exist +
  # type-via-builtin + read-via-stdin-redirect (cmd's `<` is a
  # direct CreateFileW(GENERIC_READ) — bypasses any extra path
  # checks `type` might do). Everything goes through one RExec so
  # the throw carries it all.
  $r = RExec @('--', $cmd, '/c',
    ("echo PATH=$inAllow & " +
     "if exist `"$inAllow`" (echo IFEXIST=YES) else (echo IFEXIST=NO) & " +
     "type `"$inAllow`" 2>&1 & echo --- & " +
     "more < `"$inAllow`" 2>&1"))
  if ($r.out -notmatch 'REALLOW') {
    throw ("G5: allowWithinDeny grant on inner file did not take " +
           "effect.`n  child raw: $($r.raw)`n  " +
           "inAllow Sddl: $((Get-Acl $inAllow).Sddl)`n  " +
           "subDeny Sddl: $((Get-Acl $subDeny).Sddl)")
  }
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.out -notmatch 'SIBLING') {
    throw "G5: sibling-of-denied-dir lost access. raw: $($r.raw)"
  }
  Write-Host 'G5 ok: dir-deny (OI)(CI) covers subtree; sibling unaffected; inner grant overrides'

  # ── G6: revoke + restore — child loses access; DACLs round-trip ──
  Run @('acl','revoke','--group-sid',$GroupSid,'--holder-pid',$PID,
        '--sandbox-user-sid',$sbSid)
  Run @('acl','restore','--group-sid',$GroupSid,'--holder-pid',$PID,
        '--sandbox-user-sid',$sbSid)
  $post = (Get-Acl $gRoot).Sddl
  if ($post -match [regex]::Escape($sbSid)) {
    throw "G6: srt-sandbox ACE still present on root after revoke: $post"
  }
  $postSub = (Get-Acl $subDeny).Sddl
  if ($postSub -match [regex]::Escape($sbSid)) {
    throw "G6: srt-sandbox ACE still on dir after restore: $postSub"
  }
  $r = RExec @('--', $cmd, '/c', "type `"$sibling`"")
  if ($r.exit -eq 0) {
    throw "G6: child still reads after revoke. raw: $($r.raw)"
  }
  Write-Host 'G6 ok: revoke + restore remove all sb-user ACEs; child loses access'
} finally {
  # Best-effort: don't leak ACEs/stamps if a G-row threw mid-way.
  & $Exe acl revoke  --group-sid $GroupSid --holder-pid $PID `
        --sandbox-user-sid $sbSid 2>&1 | Out-Null
  & $Exe acl restore --group-sid $GroupSid --holder-pid $PID `
        --sandbox-user-sid $sbSid 2>&1 | Out-Null
  Remove-Item -Recurse -Force $gRoot -ErrorAction SilentlyContinue
}

# ── R8: exec --as-sandbox-user without provisioning → exit 15 ────
# Clear the cred row (uninstall does this) and assert the broker
# refuses with the dedicated exit code instead of failing the
# logon. Re-install afterward is unnecessary — teardown follows.
Run @('uninstall','--sublayer-guid',$Sublayer)
$r = & $Exe exec --as-sandbox-user -- $cmd /c 'exit 0' 2>&1 | Out-String
if ($LASTEXITCODE -ne 15) {
  throw "R8: expected exit 15 (not provisioned), got ${LASTEXITCODE}. out: $r"
}
if ($r -notmatch '(?i)srt-win install') {
  throw "R8: expected re-run install hint. out: $r"
}
Write-Host 'R8 ok: --as-sandbox-user exits 15 with install hint when not provisioned'

# ── teardown ─────────────────────────────────────────────────────
# `uninstall` (R8) already removed filters + user. Belt-and-braces
# wfp uninstall for the case where R-rows were skipped or threw
# before R8.
& $Exe wfp uninstall --sublayer-guid $Sublayer 2>&1 | Out-Null
$post = J @('wfp','status','--sublayer-guid',$Sublayer)
if ($post.state -ne 'absent') {
  throw "post-uninstall expected absent, got $($post.state)"
}
Write-Host 'smoke-exec: PASS (E1-E11c incl. E4b/E7b/E7c, R1-R6/R8/R9/R9b/R12 incl. R5b, G1-G6)'
