<#
  srt-win end-to-end smoke test.

  Exercises the full group + WFP lifecycle against a built srt-win.exe.
  Throws on any assertion failure. Requires elevation (NetLocalGroup*
  and Fwpm* both need admin).

  Usage (local dev machine):
    pwsh vendor/srt-win-src/ci/smoke.ps1 .\target\release\srt-win.exe

  Usage (CI — workflow passes the path):
    pwsh vendor/srt-win-src/ci/smoke.ps1 vendor\srt-win-src\target\release\srt-win.exe

  All WFP operations target $TestSublayer (a fixed test GUID), NOT
  the production default sublayer — safe to run on a dev machine
  that has real sandbox-runtime filters installed; the idempotent
  install's purge-then-re-add only touches the test sublayer.

  When running under GitHub Actions, the random alt-sublayer GUID is
  also written to $env:GITHUB_ENV so the always()-gated cleanup step
  can remove those filters even if this script throws midway.
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$Exe,
  [string]$GroupName = 'srt-ci-test',
  # Distinct from wfp::DEFAULT_SUBLAYER_GUID so local runs never
  # touch a production install.
  [string]$TestSublayer = 'a91b6f12-4c0e-4e30-b1f7-3d52890ce117',
  # Second sublayer for the single-install convenience-subcommand
  # row, so it doesn't perturb the lifecycle section's $TestSublayer.
  [string]$InstallSublayer = 'b2e8a6c4-1f73-4d09-9e25-c7b0d3a48f61'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Exe)) {
  throw "srt-win.exe not found at '$Exe'"
}

# user_sid logged for debug context only (whose TokenGroups the
# group-status / fence assertions are evaluating against).
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Host "srt-win smoke: exe=$Exe group=$GroupName sublayer=$TestSublayer user_sid=$me"
$sl = @('--sublayer-guid', $TestSublayer)
# Explicit so the assertions below are deterministic even if the
# compiled-in default changes.
$pr = @('--proxy-port-range', '60080-60089')

function Run([string[]]$argv) {
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}
function J([string[]]$argv) { Run $argv | ConvertFrom-Json }
function MustFail([string[]]$argv, [string]$why) {
  & $Exe @argv 2>$null
  if ($LASTEXITCODE -eq 0) {
    throw "expected non-zero ($why): srt-win $($argv -join ' ')"
  }
}

# The admin mutators below (group create|delete, wfp install|uninstall)
# self-elevate via maybe_self_elevate (batch 02b). The CI runner is
# already elevated, so the helper returns None and they run in-process,
# same as before; the UAC self-elevate relaunch path is interactive-only
# (see 02b) and is not exercised here.
# ── group create (idempotent) ────────────────────────────────────────
Run @('group', 'create', '--name', $GroupName)
Run @('group', 'create', '--name', $GroupName)   # second call must succeed

$gs = J @('group', 'status', '--name', $GroupName)
Write-Host "group status (--name): $($gs | ConvertTo-Json -Compress)"
# In CI there's no logout, so the new group SID is not yet on the
# runner's token: `created-not-on-token` is expected. On a dev box
# that already has the group from a prior run, `ready` is fine too.
if ($gs.state -notin 'created-not-on-token', 'ready') {
  throw "unexpected group state: $($gs.state)"
}
if (-not $gs.sid -or -not $gs.sid.StartsWith('S-1-')) {
  throw "group status did not return a SID"
}

# --group-sid path returns the same SID.
$gs2 = J @('group', 'status', '--group-sid', $gs.sid)
if ($gs2.sid -ne $gs.sid) {
  throw "--group-sid status sid mismatch: $($gs2.sid) vs $($gs.sid)"
}
# Unmapped SID via --group-sid reports absent (not created-not-on-token).
$gsBad = J @('group', 'status', '--group-sid', 'S-1-5-21-1-2-3-9999999')
if ($gsBad.state -ne 'absent') {
  throw "unmapped --group-sid expected absent, got $($gsBad.state)"
}

# ── negative input ──────────────────────────────────────────────────
MustFail @('wfp', 'install', '--group-sid', 'not-a-sid') 'invalid --group-sid'
MustFail (@('wfp', 'install', '--name', $GroupName, '--proxy-port-range', '100-50') + $sl) 'low>high'
MustFail (@('wfp', 'install', '--name', $GroupName, '--proxy-port-range', '1-1000') + $sl) 'range too wide'
MustFail (@('wfp', 'install', '--name', $GroupName, '--proxy-port-range', '60080') + $sl) 'missing dash'

# ═════════════════════════════════════════════════════════════════════
# WFP lifecycle test — uses $GroupName.
#
# The WFP filters are machine-wide and keyed on the group SID. We
# can install/enumerate/uninstall them regardless of whether the
# group is on the current token, so $GroupName works fine for the
# *lifecycle* assertions below. It does NOT work for asserting
# "the broker gets through" — that needs a group already enabled
# on this token, which $GroupName isn't (no logout in CI). The
# fence-behaviour section further down uses BUILTIN\Administrators
# instead.
# ═════════════════════════════════════════════════════════════════════

# ── pre-install absent ───────────────────────────────────────────────
$pre = J (@('wfp', 'status') + $sl)
if ($pre.state -ne 'absent') {
  throw "pre-install wfp status expected absent, got $($pre.state)"
}

# First install via --name.
Run (@('wfp', 'install', '--name', $GroupName) + $sl + $pr)
$ws = J (@('wfp', 'status') + $sl)
Write-Host "wfp status: $($ws | ConvertTo-Json -Compress)"
if ($ws.state -ne 'installed') { throw "expected installed, got $($ws.state)" }
if ($ws.filters -lt 8)         { throw "expected >=8 filters, got $($ws.filters)" }
if ($ws.port_range[0] -ne 60080 -or $ws.port_range[1] -ne 60089) {
  throw "expected port_range [60080,60089], got [$($ws.port_range -join ',')]"
}

# Idempotency: second install via --group-sid path leaves the same
# filter count.
Run (@('wfp', 'install', '--group-sid', $gs.sid) + $sl + $pr)
$ws2 = J (@('wfp', 'status') + $sl)
if ($ws2.filters -ne $ws.filters) {
  throw "idempotency: filter count changed $($ws.filters) -> $($ws2.filters)"
}

# ── --proxy-port-range override round-trips through status ─────────
Run (@('wfp', 'install', '--name', $GroupName, '--proxy-port-range', '50000-50001') + $sl)
$wsR = J (@('wfp', 'status') + $sl)
if ($wsR.port_range[0] -ne 50000 -or $wsR.port_range[1] -ne 50001) {
  throw "expected port_range [50000,50001], got [$($wsR.port_range -join ',')]"
}
# No-flag install: assert the compiled-in DEFAULT_PROXY_PORT_RANGE.
Run (@('wfp', 'install', '--name', $GroupName) + $sl)
$wsD = J (@('wfp', 'status') + $sl)
if ($wsD.port_range[0] -ne 60080 -or $wsD.port_range[1] -ne 60089) {
  throw "no-flag default expected [60080,60089], got [$($wsD.port_range -join ',')]"
}

# ── --sublayer-guid isolation ────────────────────────────────────────
# Persist the alt GUID so an always()-gated cleanup step can remove
# its filters even if this script throws midway.
$altGuid = [guid]::NewGuid().ToString()
if ($env:GITHUB_ENV) {
  Add-Content $env:GITHUB_ENV "SRT_ALT_GUID=$altGuid"
}
Run (@('wfp', 'install', '--name', $GroupName, '--sublayer-guid', $altGuid) + $pr)
$alt = J @('wfp', 'status', '--sublayer-guid', $altGuid)
if ($alt.state -ne 'installed') {
  throw "alt sublayer expected installed, got $($alt.state)"
}
# Test sublayer is still its own thing.
$stillTest = J (@('wfp', 'status') + $sl)
if ($stillTest.filters -ne $ws.filters) {
  throw "test sublayer perturbed by alt install"
}
Run @('wfp', 'uninstall', '--sublayer-guid', $altGuid)
$altGone = J @('wfp', 'status', '--sublayer-guid', $altGuid)
if ($altGone.state -ne 'absent') {
  throw "alt sublayer expected absent after uninstall, got $($altGone.state)"
}

# ── teardown: uninstall on test sublayer ────────────────────────────
Run (@('wfp', 'uninstall') + $sl)
$post = J (@('wfp', 'status') + $sl)
if ($post.state -ne 'absent') {
  throw "post-uninstall expected absent, got $($post.state)"
}
# Idempotent no-op: second uninstall must also exit 0.
Run (@('wfp', 'uninstall') + $sl)

# ═════════════════════════════════════════════════════════════════════
# WFP fence-behaviour test — uses BUILTIN\Administrators (S-1-5-32-544).
#
# Why a different group: the fence relies on AccessCheck against the
# connecting token, so to assert "broker passes filter 1" we need a
# group that's *already enabled* on this token. $GroupName was just
# created and won't be in TokenGroups until a fresh logon. Admins is
# reliably enabled on the GHA runner.
# ═════════════════════════════════════════════════════════════════════

$adminsSid = 'S-1-5-32-544'
Run (@('wfp', 'install', '--group-sid', $adminsSid) + $sl + $pr)
try {
  # Broker-side: this process has Admins enabled, so filter 1
  # (PERMIT group-enabled) should let the connect through.
  $r = curl.exe -s -m 10 -o NUL -w "%{http_code}" https://example.com
  if ($LASTEXITCODE -ne 0 -or $r -ne '200') {
    throw "broker egress through filter 1 expected 200, got exit=$LASTEXITCODE code='$r'"
  }
  Write-Host "fence: broker egress OK ($r)"

  # Child-side (group deny-only) assertion lands in batch 02 once
  # `srt-win exec` exists; that batch's smoke-exec.ps1 will run
  #   srt-win exec --group-sid S-1-5-32-544 -- curl https://example.com
  # and assert it is BLOCKED.
}
finally {
  Run (@('wfp', 'uninstall') + $sl)
}

# ── group teardown ───────────────────────────────────────────────────
Run @('group', 'delete', '--name', $GroupName)
$gd = J @('group', 'status', '--name', $GroupName)
if ($gd.state -ne 'absent') {
  throw "post-delete group expected absent, got $($gd.state)"
}
# Idempotent no-op: second delete must also exit 0.
Run @('group', 'delete', '--name', $GroupName)

# ═════════════════════════════════════════════════════════════════════
# Single-step `install` / `uninstall` convenience subcommands.
#
# Distinct group name + sublayer so this section is isolated from the
# lifecycle assertions above. Verifies that one `install` call leaves
# both the group present AND the WFP filters installed, and that one
# `uninstall` call removes both.
# ═════════════════════════════════════════════════════════════════════

$instGrp = "$GroupName-inst"
$isl = @('--sublayer-guid', $InstallSublayer)

Run (@('install', '--name', $instGrp) + $isl + $pr)
$ig = J @('group', 'status', '--name', $instGrp)
if ($ig.state -notin 'created-not-on-token', 'ready') {
  throw "install: group expected created-not-on-token/ready, got $($ig.state)"
}
$iw = J (@('wfp', 'status') + $isl)
if ($iw.state -ne 'installed' -or $iw.filters -lt 8) {
  throw "install: wfp expected installed/>=8, got $($iw.state)/$($iw.filters)"
}

# ── sandbox user provisioned by install ────────────────────────────
$us = J @('user', 'status')
Write-Host "user status: $($us | ConvertTo-Json -Compress)"
if (-not $us.user.exists)            { throw "install: sandbox user not provisioned" }
if (-not $us.user.sid -or -not $us.user.sid.StartsWith('S-1-5-21-')) {
  throw "install: sandbox user SID missing or malformed: '$($us.user.sid)'"
}
if (-not $us.user.group_exists)      { throw "install: sandbox-runtime-users group missing" }
if (-not $us.user.in_builtin_users)  { throw "install: sandbox user not in BUILTIN\Users" }
if (-not $us.user.in_sandbox_group)  { throw "install: sandbox user not in sandbox-runtime-users" }
if (-not $us.user.hidden_from_logon) { throw "install: sandbox user not hidden from Winlogon" }
if (-not $us.cred_present)           { throw "install: credential not present in state DB" }
if ($us.marker_version -ne 1)        { throw "install: setup marker version expected 1, got $($us.marker_version)" }
if ($us.marker_user_sid -ne $us.user.sid) {
  throw "install: marker SID '$($us.marker_user_sid)' != live SID '$($us.user.sid)'"
}

# user-SID-keyed WFP filters present alongside the group set, with
# the right SID in their tag.
if ($iw.user_filters -lt 4) {
  throw "install: expected >=4 user-SID filters, got $($iw.user_filters)"
}
if ($iw.user_sid -ne $us.user.sid) {
  throw "install: WFP user_sid '$($iw.user_sid)' != provisioned '$($us.user.sid)'"
}

# read-cred returns the cleartext password — 32 chars from the
# documented alphabet. Run as the real user (the sandbox user is
# DENY'd on the directory; that side is verified once the runner
# exists).
$pw = & $Exe user read-cred
if ($LASTEXITCODE -ne 0) { throw "user read-cred exited $LASTEXITCODE" }
if ($pw.Length -ne 32)   { throw "user read-cred: expected 32 chars, got $($pw.Length)" }
if ($pw -match '["\s\\`&|<>^]') {
  throw "user read-cred: password contains an excluded char: '$pw'"
}

# State-dir DACL: explicit DENY for sandbox-runtime-users. This is
# the load-bearing gate on the credential file (machine-scope DPAPI
# is not a confidentiality boundary — any local account can decrypt
# a readable blob). The broker-only PROTECTED allow set already
# excludes the sandbox user, but the explicit DENY makes the intent
# auditable.
$stateDir = Join-Path $env:LOCALAPPDATA 'sandbox-runtime'
$acl = Get-Acl $stateDir
$deny = $acl.Access | Where-Object {
  $_.AccessControlType -eq 'Deny' -and
  $_.IdentityReference.Value -match 'sandbox-runtime-users$'
}
if (-not $deny) {
  throw "install: state-dir DACL has no DENY for sandbox-runtime-users; got:`n$($acl.Access | Out-String)"
}
if (-not (Test-Path (Join-Path $stateDir 'state.db'))) {
  throw "install: state.db missing at $stateDir"
}

# ── M1: schema-mismatch → .bak rename ──────────────────────────────
# Patch state.db's header user_version (big-endian uint32 at byte
# offset 60) to 1, then re-run install. open_db_at() sees v1≠SCHEMA,
# renames the file to state.db.v1.<ts>.bak, and creates a fresh DB.
# The .bak preserves the old cred/ca_cert rows for recovery; the
# fresh DB requires re-provisioning, which re-install does here.
$db = Join-Path $stateDir 'state.db'
Remove-Item -ea SilentlyContinue (Join-Path $stateDir 'state.db-wal'),
                                  (Join-Path $stateDir 'state.db-shm')
$bytes = [System.IO.File]::ReadAllBytes($db)
$bytes[60] = 0; $bytes[61] = 0; $bytes[62] = 0; $bytes[63] = 1
[System.IO.File]::WriteAllBytes($db, $bytes)
# M1b: open_db_ro() bails on v≠SCHEMA (fail-closed — an empty
# fence-plan would otherwise run the child unfenced). `user status`
# routes through it via read_ca_cert()? → exits non-zero with the
# migrate hint.
$m1b = & $Exe user status 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) {
  throw "M1b: user status on stale-schema DB expected non-zero exit; got 0. out: $m1b"
}
if ($m1b -notmatch '(?i)schema v1.*expected v\d+.*re-run.*install') {
  throw "M1b: expected 'schema v1, expected vN; re-run install' hint. out: $m1b"
}
Write-Host "M1b ok: user status fails closed on stale schema"
# install (no --force): read_setup().ok() swallows the same Err →
# None → idempotent early-out FALLS THROUGH ("partial install
# detected … completing"), reaching write_setup() → open_db_at() →
# .bak rename. Regression-guard: "already installed; no changes" =
# open_db_ro() lost the version check.
$m1out = & $Exe @(@('install', '--name', $instGrp) + $isl + $pr) 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "M1: install exited $LASTEXITCODE. out: $m1out" }
if ($m1out -match '(?i)already installed.*no changes') {
  throw "M1: install short-circuited on stale-schema DB (open_db_ro missed user_version check). out: $m1out"
}
if ($m1out -notmatch '(?i)partial install detected|completing') {
  throw "M1: expected install to fall through with 'partial install detected'/'completing'. out: $m1out"
}
$bak = Get-ChildItem -Path $stateDir -Filter 'state.db.v1.*.bak' -ea Stop
if (-not $bak) {
  throw "M1: expected state.db.v1.*.bak in $stateDir; got: $(Get-ChildItem $stateDir | Out-String)"
}
$freshBytes = [System.IO.File]::ReadAllBytes($db)
$freshVer = ([int]$freshBytes[60] -shl 24) -bor ([int]$freshBytes[61] -shl 16) -bor `
            ([int]$freshBytes[62] -shl 8)  -bor  [int]$freshBytes[63]
if ($freshVer -le 1) {
  throw "M1: fresh state.db user_version expected >1 (current SCHEMA), got $freshVer"
}
# .bak inherits broker-only from the PROTECTED state dir (open_db
# stamps the dir on every open); no per-file stamp.
Write-Host "M1 ok: schema mismatch → $($bak[0].Name); fresh DB at v$freshVer"
Remove-Item $bak.FullName, "$($bak[0].FullName)-wal", "$($bak[0].FullName)-shm" -ea SilentlyContinue
# Re-install above re-wrote the cred; downstream rows (read-cred
# etc.) already ran and don't depend on it.

# block-user must NOT match the REAL user — its SD allows only the
# sandbox user's SID. (The sandbox-side "is blocked" assertion needs
# the runner; deferred.)
$r = curl.exe -s -m 10 -o NUL -w "%{http_code}" https://example.com
if ($LASTEXITCODE -ne 0 -or $r -ne '200') {
  throw "install: real-user egress past block-user expected 200, got exit=$LASTEXITCODE code='$r'"
}
Write-Host "install: real-user egress past block-user OK ($r)"

# `wfp install` (group set only) must NOT drop the user-SID set —
# the two sets are independent.
Run (@('wfp', 'install', '--name', $instGrp) + $isl + $pr)
$iwAfter = J (@('wfp', 'status') + $isl)
if ($iwAfter.user_filters -ne $iw.user_filters) {
  throw "wfp install perturbed user-SID filters: $($iw.user_filters) -> $($iwAfter.user_filters)"
}

# Idempotency, same range: second install with identical flags is
# a no-op (exit 0, "already installed").
$out = & $Exe @(@('install', '--name', $instGrp) + $isl + $pr) 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
  throw "install idempotency: same-range expected exit 0, got $LASTEXITCODE"
}
if ($out -notmatch 'already installed') {
  throw "install idempotency: expected 'already installed' in output, got '$out'"
}
$iw2 = J (@('wfp', 'status') + $isl)
if ($iw2.filters -ne $iw.filters) {
  throw "install idempotency: filters $($iw.filters) -> $($iw2.filters)"
}

# Conflict, different range without --force: exits 13.
& $Exe @(@('install', '--name', $instGrp, '--proxy-port-range', '50000-50001') + $isl) 2>$null
if ($LASTEXITCODE -ne 13) {
  throw "install conflict: different-range without --force expected exit 13, got $LASTEXITCODE"
}
# Original range still in place.
$iw3 = J (@('wfp', 'status') + $isl)
if ($iw3.port_range[0] -ne 60080) {
  throw "install conflict: range was overwritten without --force"
}

# --force replaces.
Run (@('install', '--name', $instGrp, '--proxy-port-range', '50000-50001', '--force') + $isl)
$iwF = J (@('wfp', 'status') + $isl)
if ($iwF.port_range[0] -ne 50000 -or $iwF.port_range[1] -ne 50001) {
  throw "install --force: expected port_range [50000,50001], got [$($iwF.port_range -join ',')]"
}

# --group-sid path (group externally managed; here it already
# exists from the --name install above). With matching range
# this is the same-range no-op.
Run (@('install', '--group-sid', $ig.sid, '--proxy-port-range', '50000-50001') + $isl)

# Distinct exit code 11: group step fails on a malformed
# --group-sid (canonicalize_sid rejects). --force so the
# pre-check (which would otherwise fire on the existing
# install above) is skipped and we reach the group step.
& $Exe @(@('install', '--group-sid', 'not-a-sid', '--force') + $isl) 2>$null
if ($LASTEXITCODE -ne 11) {
  throw "install: invalid --group-sid expected exit 11, got $LASTEXITCODE"
}

# `wfp verify` and `user trust-ca` route through
# CreateProcessWithLogonW (Secondary Logon). GHA runners have it;
# ensure it's running (idempotent).
try { Start-Service seclogon -ea Stop } catch {
  Write-Host "smoke: WARNING: Start-Service seclogon: $_"
}

# ── wfp verify: behavioral egress-block probe ───────────────────────
# Spawns the runner as the sandbox user and direct-connects to a
# target. The block-user filter fires at ALE_AUTH_CONNECT (before
# any packet leaves) → WSAEACCES → exit 0 + "blocked". This is the
# non-elevated readiness check (BFE enum is admin-gated; this
# isn't). stderr (the runner's BLOCKED/UNREACHABLE line) flows to
# the host so it's in the CI log; stdout is JUST the JSON line.
#
# `--target 127.0.0.1:49999` (a local listener bound below) — OUT of
# the WFP loopback permit range, so block-user fires when the fence
# is active and the connect succeeds when it isn't. Deterministic;
# no internet. This is the same shape as the product path
# (`verifyWindowsWfpEgress` binds an ephemeral out-of-range loopback
# listener and passes it as `--target`).
$probePort = 49999
$probeTgt = "127.0.0.1:$probePort"
$probeLsn = [System.Net.Sockets.TcpListener]::new(
  [System.Net.IPAddress]::Loopback, $probePort)
$probeLsn.Start()
function WfpVerify([string]$tgt) {
  $out = & $Exe wfp verify --target $tgt
  $ec = $LASTEXITCODE
  Write-Host "wfp verify --target ${tgt}: exit=$ec stdout='$out'"
  return [pscustomobject]@{ exit = $ec; json = $out | ConvertFrom-Json }
}
$v = WfpVerify $probeTgt
if ($v.exit -ne 0 -or $v.json.egress_probe -ne 'blocked') {
  throw ("wfp verify (fence-active): expected exit 0 + blocked, " +
         "got exit=$($v.exit) probe='$($v.json.egress_probe)'")
}
if ($v.json.target -ne $probeTgt) {
  throw "wfp verify: --target not honoured; got '$($v.json.target)'"
}
Write-Host "wfp verify ok: fence-active → blocked (target=$probeTgt)"

# ── user trust-ca: cert recorded + written ─────────────────────────
# Cert lifecycle = sandbox-user lifecycle (set via `user trust-ca`,
# persistent until uninstall); `srt-win install` and `srt-win exec`
# never touch it. Mint a throwaway self-signed cert (PEM), pass it
# via `user trust-ca`, and assert `user status` surfaces
# the thumb + a PEM that round-trips back to the same DER. The
# one-shot CPWLW(runner) registry write into `HKU\<sbSid>` is
# verified by the runner's stderr logging + a real-user-store leak
# check; child-visibility under the restricted token is a Server-SKU
# anomaly (see cert_store.rs) and is left to Win11 manual probes.
$caDir = Join-Path $env:TEMP "srt-ca-$(Get-Random)"
$null = mkdir $caDir
try {
  $ca = New-SelfSignedCertificate -Subject 'CN=srt-smoke-ca DO NOT TRUST' `
          -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
  $caPem = Join-Path $caDir 'ca.pem'
  $b64 = [Convert]::ToBase64String($ca.RawData, 'InsertLineBreaks')
  "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----" |
    Set-Content -Path $caPem -Encoding ascii
  $thumb = $ca.Thumbprint
  Remove-Item "Cert:\CurrentUser\My\$thumb" -ea SilentlyContinue

  # `user trust-ca` is the FIRST `spawn_runner` call (CPWLW + the
  # WinSta0/BNO grants). A hang here is the broker waiting on a
  # runner that never finished init — e.g. an under-granted
  # WinSta0 mask. Marker so a hung CI log shows which step it is
  # (the captured `$out` never prints on a hang).
  Write-Host 'ca-trust: spawning runner (CPWLW + station/BNO grants)'
  $out = & $Exe user trust-ca $caPem 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) {
    throw "user trust-ca exited ${LASTEXITCODE}: $out"
  }
  if ($out -notmatch '(?i)CA installed.*thumb=') {
    throw "user trust-ca: runner did not log CA install. out: $out"
  }
  $usCa = J @('user', 'status')
  if ($usCa.ca_cert_thumb -ne $thumb) {
    throw "user status: ca_cert_thumb '$($usCa.ca_cert_thumb)' != '$thumb'"
  }
  if (-not $usCa.ca_cert_pem -or $usCa.ca_cert_pem -notmatch 'BEGIN CERTIFICATE') {
    throw "user status: ca_cert_pem missing or malformed"
  }
  # PEM round-trips back to the same DER (so der_to_pem and the
  # state-DB blob agree).
  $pemBody = ($usCa.ca_cert_pem -replace '-----[^-]+-----', '' -replace '\s', '')
  if ([Convert]::ToBase64String($ca.RawData) -ne $pemBody) {
    throw 'user status: ca_cert_pem does not round-trip to original DER'
  }
  # Real user's Root must NOT have it — the write is scoped to the
  # sandbox user's HKU\<SID>.
  if (Get-ChildItem Cert:\CurrentUser\Root |
      Where-Object Subject -match 'srt-smoke-ca') {
    throw 'user trust-ca: CA leaked into REAL user CurrentUser\Root'
  }
  Write-Host "ca-trust ok: thumb=$thumb recorded + written into sandbox-user Root"

  # `install --force` re-provisions the account but must preserve
  # the recorded CA — write_setup_info's ON CONFLICT DO UPDATE
  # excludes ca_cert (owned by set_ca_cert), so install never
  # touches it.
  Run (@('install', '--name', $instGrp, '--force') + $isl + $pr)
  $usCa3 = J @('user', 'status')
  if ($usCa3.ca_cert_thumb -ne $thumb) {
    throw ("install --force: ca_cert wiped — got " +
           "'$($usCa3.ca_cert_thumb)', expected '$thumb'")
  }
  Write-Host 'ca-trust ok: install --force preserves ca_cert'
} finally {
  Remove-Item $caDir -Recurse -Force -ea SilentlyContinue
}

# --keep-user: filters removed, sandbox user + cred file kept.
Run (@('uninstall', '--keep-user') + $isl)
$uw0 = J (@('wfp', 'status') + $isl)
if ($uw0.state -ne 'absent' -or $uw0.user_filters -ne 0) {
  throw "uninstall --keep-user: wfp expected absent/0, got $($uw0.state)/$($uw0.user_filters)"
}
$us0 = J @('user', 'status')
if (-not $us0.user.exists -or -not $us0.cred_present) {
  throw "uninstall --keep-user: sandbox user/cred should be kept"
}

# ── wfp verify (fence-INACTIVE): connect succeeds ───────────────────
# Filters were just removed (`uninstall --keep-user`) but the
# sandbox user is kept → the probe runs and the connect to the
# local listener SUCCEEDS (no WFP block) → exit 3 + "connected".
# This is the security-boundary proof that exit 0 above wasn't a
# false positive.
$v = WfpVerify $probeTgt
if ($v.exit -ne 3 -or $v.json.egress_probe -ne 'connected') {
  throw ("wfp verify (fence-inactive): expected exit 3 + " +
         "connected, got exit=$($v.exit) probe=" +
         "'$($v.json.egress_probe)' — probe cannot distinguish " +
         "fence-active from fence-missing")
}
Write-Host 'wfp verify ok: fence-inactive → exit 3 + connected'
$probeLsn.Stop()

# Re-install to set up for the full uninstall below.
Run (@('install', '--name', $instGrp) + $isl + $pr)

# Uninstall removes filters AND the sandbox user — discriminator
# group remains.
Run (@('uninstall') + $isl)
$uw = J (@('wfp', 'status') + $isl)
if ($uw.state -ne 'absent') {
  throw "uninstall: wfp expected absent, got $($uw.state)"
}
if ($uw.user_filters -ne 0) {
  throw "uninstall: user-SID filters expected 0, got $($uw.user_filters)"
}
$ug = J @('group', 'status', '--name', $instGrp)
if ($ug.state -notin 'created-not-on-token', 'ready') {
  throw "uninstall: group should be left intact, got $($ug.state)"
}
$usGone = J @('user', 'status')
if ($usGone.user.exists) {
  throw "uninstall: sandbox user should be removed, got $($usGone | ConvertTo-Json -Compress)"
}
if ($usGone.cred_present) {
  throw "uninstall: credential row should be cleared"
}
if ($null -ne $usGone.marker_version) {
  throw "uninstall: setup marker row should be cleared"
}
if ($null -ne $usGone.ca_cert_thumb) {
  throw "uninstall: ca_cert row should be cleared"
}
# Idempotent no-op: second uninstall must also exit 0.
Run (@('uninstall') + $isl)

# Explicit group teardown.
Run @('group', 'delete', '--name', $instGrp)

Write-Host 'srt-win smoke: OK'
