//! `srt-win` — CLI for the sandbox-runtime Windows network fence.
//!
//! Subcommands:
//!   install | uninstall                — convenience: group + WFP in one
//!                                         elevated call (one UAC prompt)
//!   group  create | status | delete    — manage the discriminator local group
//!   wfp    install | status | uninstall — manage the persistent WFP filters
//!   exec   -- <target> [args...]       — spawn under the deny-only-group
//!                                         token + job + hardening stack
//!   acl    stamp | restore | recover   — file-level denyRead/denyWrite via
//!                                         broker-only DACL stamp + state DB
//!
//! `status` subcommands write one line of JSON to stdout and exit 0.
//! Mutating subcommands require elevation and write human-readable
//! progress to stderr. `exec` propagates the child's exit code.

use clap::{Args, Parser, Subcommand};

/// Default group name. Lives here (not in the `#[cfg(windows)]`
/// library crate) so the clap-derive CLI structs compile on
/// non-Windows hosts where the library is empty.
const DEFAULT_GROUP_NAME: &str = "sandbox-runtime-net";

#[derive(Parser)]
#[command(name = "srt-win", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Group create + WFP install in one elevated step.
    ///
    /// Self-elevates via UAC if not already running as admin
    /// (one prompt; the elevated child does the work and the
    /// parent relays its exit code). With the machine-wide
    /// filter design, a token where the group is **absent**
    /// (i.e. this session, before logout) matches filter-0
    /// (PERMIT non-members) — so installing the WFP filters
    /// here does NOT break the user's network. Logout is still
    /// required before `srt-win exec` works (the broker
    /// pre-flight needs the group **enabled** to build a
    /// deny-only child token), but the install itself is one
    /// safe step → one UAC prompt.
    ///
    /// Equivalent to `group create --name <N> --user-sid <U>`
    /// followed by `wfp install --name <N> …`. With `--group-sid`,
    /// the group is assumed to already exist (e.g. provisioned by
    /// domain GPO) and only the filters are installed.
    ///
    /// Exit codes:
    ///   0  — installed (or already installed with the same
    ///        port-range; no changes)
    ///   10 — UAC prompt cancelled by the user
    ///   11 — group create / lookup failed
    ///   12 — WFP filter install failed
    ///   13 — already installed under this sublayer with a
    ///        DIFFERENT port-range; pass `--force` to replace
    ///   1  — other error (parse, elevation check, etc.)
    Install {
        #[command(flatten)]
        group: GroupRef,
        /// User SID to add to the group (default: current user).
        /// Ignored with `--group-sid`.
        #[arg(long)]
        user_sid: Option<String>,
        /// Sublayer GUID (default: compile-time constant).
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Loopback port range (`LOW-HIGH`, default 60080-60089).
        #[arg(long, value_name = "LOW-HIGH")]
        proxy_port_range: Option<String>,
        /// Replace an existing install whose port-range differs
        /// (otherwise exits 13).
        #[arg(long)]
        force: bool,
    },
    /// Remove the srt-win WFP filters under the sublayer.
    ///
    /// Self-elevates via UAC if not already admin. Does NOT
    /// delete the discriminator group — use `srt-win group
    /// delete --name <N>` for that explicitly. **Does** remove
    /// the sandbox user account, its credential file, and the
    /// setup marker, unless `--keep-user`.
    Uninstall {
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Keep the `srt-sandbox` account, its credential file,
        /// and the setup marker. Without this flag they are all
        /// removed (the credential is useless without the
        /// account and vice versa, so they're treated as one
        /// unit).
        #[arg(long)]
        keep_user: bool,
    },
    /// Inspect the sandbox user account that `srt-win install`
    /// provisions (and that the sandboxed child eventually runs
    /// as).
    User {
        #[command(subcommand)]
        sub: UserCmd,
    },
    /// Manage the local discriminator group.
    Group {
        #[command(subcommand)]
        sub: GroupCmd,
    },
    /// Manage the persistent WFP filters.
    Wfp {
        #[command(subcommand)]
        sub: WfpCmd,
    },
    /// Stamp/restore broker-only DACLs on file paths so the
    /// sandboxed child cannot read (or write) them. State is
    /// persisted in `%LOCALAPPDATA%\sandbox-runtime\state.db` so
    /// concurrent brokers refcount and a crash mid-session is
    /// recoverable by the next `acl` op.
    Acl {
        #[command(subcommand)]
        sub: AclCmd,
    },
    /// Spawn a process under the deny-only-group sandbox.
    ///
    /// Builds a restricted token (group + Admins flipped deny-only,
    /// LUA, Medium IL, all privs stripped except SeChangeNotify),
    /// self-protects the broker, assigns the child to a
    /// kill-on-close job with full UI lockdown, places it on a
    /// non-interactive desktop, applies process-mitigation
    /// policies + an explicit handle whitelist, and waits for it
    /// to exit. Propagates the child's exit code.
    ///
    /// The child inherits this process's environment verbatim — proxy
    /// configuration is single-sourced by the caller, which sets the
    /// proxy vars (TS `generateProxyEnvVars`) in the environment it
    /// spawns `srt-win exec` with. There are intentionally no
    /// `--http-proxy` / `--socks-proxy` flags and no proxy fallback.
    Exec {
        #[command(flatten)]
        group: GroupRef,
        /// Skip the "is the group enabled in the broker's token"
        /// pre-flight. **Fail-open** — the WFP fence depends on
        /// that membership; with this set the child may run with
        /// weaker isolation if the install was incomplete.
        /// Surfaced as a flag (not an env var) so the bypass is
        /// intentional and not accidentally inherited. Use ONLY
        /// in ephemeral CI runners that create the group in-job
        /// and cannot logout/login mid-run.
        #[arg(long)]
        skip_group_check: bool,
        /// PID of the long-lived host whose `acl stamp` holds this
        /// child should be fenced under. When set, exec opens a
        /// no-`FILE_SHARE_DELETE` handle on every file that holder
        /// has stamped and keeps it open until the child exits — the
        /// OS then refuses delete/rename of those files, which the
        /// file's DACL alone cannot prevent (delete is authorized by
        /// the parent directory). When omitted, exec runs with no
        /// state-DB dependency (current standalone behaviour).
        #[arg(long)]
        holder_pid: Option<u32>,
        /// Per-exec read-deny: stamp `<PATH>` broker-only for the
        /// lifetime of this exec (under THIS process's PID as
        /// holder), restored after the child exits. Repeatable.
        /// Same disk-first chokepoint as `acl stamp`'s ReadDeny.
        /// Fails the exec if any path cannot be stamped (stricter
        /// than `acl stamp`'s skip+exit-2 — the host passes raw
        /// paths and this is the first existence/type check, so
        /// per-exec is "deny THIS one command": a missing path
        /// is a caller error, not a skip).
        #[arg(long = "deny-read")]
        deny_read: Vec<String>,
        /// Per-exec write-deny — see `--deny-read`.
        #[arg(long = "deny-write")]
        deny_write: Vec<String>,
        /// Run the child as the dedicated `srt-sandbox` user via
        /// the two-hop launch: this process (the broker, real user)
        /// applies the per-exec stamps and self-protects, then
        /// `CreateProcessWithLogonW`s `srt-win runner` under
        /// `srt-sandbox`, which does the existing
        /// token/job/desktop/mitigation lockdown and spawns the
        /// child. Requires `srt-win install` to have provisioned
        /// the user (exit **15** otherwise). Opt-in — without this
        /// flag the same-user deny-only-group path is unchanged.
        /// Mutually exclusive with the `SameUser`-mode discriminator
        /// flags (`--group-sid` / `--skip-group-check`): the
        /// separate-user model has no discriminator group.
        #[arg(
            long,
            conflicts_with_all = ["group_sid", "skip_group_check"],
        )]
        as_sandbox_user: bool,
        /// `KEY=VALUE` pair overlaid on the sandbox-user runner's
        /// profile environment when building the child's env block
        /// (with `--as-sandbox-user`). Repeatable. The broker
        /// forwards exactly these — it does NOT enumerate its own
        /// environment for proxy/CA vars; the caller (whose
        /// `generateProxyEnvVars` is the single source) passes them
        /// here explicitly.
        #[arg(long = "env", value_name = "KEY=VALUE", requires = "as_sandbox_user")]
        env: Vec<String>,
        /// Target executable followed by its arguments. Use `--`
        /// to terminate srt-win's own option parsing.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required = true,
            num_args = 1..,
        )]
        target: Vec<String>,
    },
    /// Inside-the-logon half of `exec --as-sandbox-user`. Reads a
    /// length-prefixed `RunnerCmd` from stdin and dispatches as the
    /// current user — which, when launched by the broker via
    /// `CreateProcessWithLogonW`, is `srt-sandbox`. Not intended to
    /// be invoked directly.
    #[command(hide = true)]
    Runner,
}

/// Group resolution: either by name (looked up via
/// `LookupAccountNameW`) or directly by SID. If both are given the
/// SID wins; `group create`/`delete` always need a name.
#[derive(Args, Clone)]
struct GroupRef {
    /// Group name (local or `DOMAIN\name`). Default
    /// `sandbox-runtime-net`.
    #[arg(long, default_value = DEFAULT_GROUP_NAME)]
    name: String,
    /// Group SID (`S-1-…`). Overrides `--name` for SID resolution.
    /// Use when the group is provisioned by external tooling and name
    /// lookup may be unreliable.
    #[arg(long)]
    group_sid: Option<String>,
}

#[derive(Subcommand)]
enum UserCmd {
    /// Print the sandbox user's provisioning state as JSON:
    /// `{user: {exists, sid?, group_exists, group_sid?,
    /// in_builtin_users, in_sandbox_group, hidden_from_logon},
    /// cred_present, marker_version?, marker_user_sid?,
    /// ca_cert_thumb?, ca_cert_pem?}`.
    Status,
    /// Print the sandbox user's decrypted password (and only the
    /// password) to stdout. The broker uses this for
    /// `CreateProcessWithLogonW`. Fails when run as the sandbox
    /// user itself — the state-DB directory carries an explicit
    /// DENY for `sandbox-runtime-users`, and machine-scope DPAPI
    /// is **not** a confidentiality boundary without that DENY.
    ReadCred,
    /// Install (or replace) the MITM CA in the **sandbox user's**
    /// `CurrentUser\Root` and record it in the state DB. The cert
    /// has a separate lifecycle from `srt-win install` — install
    /// provisions the account/filters and never touches the CA;
    /// this is the only command that sets it. Does NOT require
    /// elevation. Persistent until `srt-win uninstall`.
    TrustCa {
        /// PEM- or DER-encoded CA certificate file.
        #[arg(value_name = "PATH")]
        path: String,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Create the local group and add the current (or `--user-sid`)
    /// user to it. Idempotent. Self-elevates via UAC if not already
    /// admin.
    Create {
        #[command(flatten)]
        group: GroupRef,
        /// User SID to add (default: current user).
        #[arg(long)]
        user_sid: Option<String>,
    },
    /// Print group state as JSON: `{state, sid?, warning?}`.
    Status {
        #[command(flatten)]
        group: GroupRef,
    },
    /// Delete the local group. Idempotent. Self-elevates via UAC if
    /// not already admin.
    Delete {
        #[command(flatten)]
        group: GroupRef,
    },
}

#[derive(Subcommand)]
enum AclCmd {
    /// Read `{denyRead:[…], denyWrite:[…]}` from stdin, stamp each
    /// path's DACL broker-only, and record this process as a
    /// holder. Idempotent across calls and brokers (refcounted).
    /// Globs are rejected; directory targets get an `(OI)(CI)`
    /// inheriting stamp covering the whole subtree.
    Stamp {
        #[command(flatten)]
        group: GroupRef,
        /// PID of the LONG-LIVED process that owns these stamps —
        /// normally the Node host (sandbox-runtime), which calls
        /// `acl stamp` at initialize() and `acl restore` at reset()
        /// from a SEPARATE short-lived `srt-win` process. The stamp
        /// persists until this PID exits or restores. Required:
        /// the `srt-win acl` process exits immediately, so keying
        /// on its own PID would orphan the stamp instantly.
        #[arg(long)]
        holder_pid: u32,
        /// Under the separate-user model, the sandbox user's SID
        /// (`srt-win user status` → `marker_user_sid`). Switches the
        /// stamp to an additive `(D;OICI;mask;;;<sid>)` ACE on the
        /// target plus a `(D;OICI;FILE_DELETE_CHILD;;;<sid>)` on
        /// the parent — NO PROTECTED rewrite, no SD snapshot.
        /// When omitted (same-user model), the PROTECTED
        /// broker-only stamp keyed on the discriminator group is
        /// applied.
        #[arg(long)]
        sandbox_user_sid: Option<String>,
    },
    /// Read `{read:[…], write:[…]}` from stdin and add an
    /// inheritable `(OI)(CI)` ACE for `--sandbox-user-sid` on each
    /// path (`FILE_GENERIC_READ|EXECUTE` for `read`,
    /// `MODIFY_NO_FDC` for `write`). Additive — the path's existing
    /// DACL and inheritance are untouched. Refcounted per holder;
    /// `acl revoke` removes the ACE when the last holder releases.
    Grant {
        #[command(flatten)]
        group: GroupRef,
        /// Holder PID (see `acl stamp`).
        #[arg(long)]
        holder_pid: u32,
        /// SID to grant — the dedicated sandbox user
        /// (`srt-win user status` → `marker_user_sid`).
        #[arg(long)]
        sandbox_user_sid: String,
    },
    /// Drop the holder's claim on every granted path; remove the
    /// sandbox-user ACE on any path whose refcount falls to zero.
    Revoke {
        #[command(flatten)]
        group: GroupRef,
        #[arg(long)]
        holder_pid: u32,
        #[arg(long)]
        sandbox_user_sid: String,
        #[arg(long)]
        json: bool,
    },
    /// Drop the holder's claim on every path it stamped; restore the
    /// original DACL on any path whose refcount falls to zero.
    Restore {
        #[command(flatten)]
        group: GroupRef,
        /// Holder PID whose stamps to release (see `acl stamp`).
        /// Must match the value passed at stamp time.
        #[arg(long)]
        holder_pid: u32,
        /// Under the separate-user model, the sandbox user's SID —
        /// switches restore to `REVOKE_ACCESS` for the SID instead
        /// of the SD-snapshot restore. Must match `acl stamp
        /// --sandbox-user-sid`.
        #[arg(long)]
        sandbox_user_sid: Option<String>,
        /// Emit a single JSON array of per-path
        /// `{path, status, expectedFileId?, movedTo?, leftStamped?}`
        /// objects on stdout (exit 0 always); the host raises any
        /// error AFTER reading the array. Without this flag, the
        /// existing human-readable summary goes to stderr.
        #[arg(long)]
        json: bool,
    },
    /// Run crash-recovery only: prune dead holders, restore any
    /// orphaned stamps. `--force` restores even when the file's
    /// current DACL no longer matches what we stamped (overwrites
    /// third-party edits — use with care).
    Recover {
        #[command(flatten)]
        group: GroupRef,
        #[arg(long)]
        force: bool,
        /// Emit a single JSON array of per-path outcomes on stdout
        /// (see `acl restore --json`).
        #[arg(long)]
        json: bool,
    },
}

/// One per-path entry of the structured `acl restore --json` /
/// `acl recover --json` result. The host reads the full array,
/// then raises if any entry is not `restored` — restore
/// processes ALL paths first; errors are surfaced afterward,
/// never mid-batch.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(windows), allow(dead_code))]
struct RestoreEntry {
    path: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    moved_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    left_stamped: Option<bool>,
}

/// A parent directory's restore outcome in the structured
/// `--json` result. `status: "leftStamped"` means the directory's
/// allow-list could NOT be removed (`restore_sd` failed) and the
/// `parent_stamps` row was kept for the next pass to retry.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(windows), allow(dead_code))]
struct ParentEntry {
    path: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Top-level shape of `acl restore --json` / `acl recover --json`.
#[derive(serde::Serialize)]
#[cfg_attr(not(windows), allow(dead_code))]
struct RestoreResult {
    paths: Vec<RestoreEntry>,
    parents: Vec<ParentEntry>,
    /// Separate-user model: per-DENY-ACE release outcomes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    aces: Vec<AceReleaseEntry>,
}

#[cfg(windows)]
fn parent_entries_from(
    entries: &[(String, srt_win::state_db::ParentRestoreOutcome)],
) -> Vec<ParentEntry> {
    use srt_win::state_db::ParentRestoreOutcome;
    entries
        .iter()
        .map(|(p, out)| ParentEntry {
            path: p.clone(),
            status: out.as_str(),
            error: if let ParentRestoreOutcome::Failed(e) = out {
                Some(e.clone())
            } else {
                None
            },
        })
        .collect()
}

#[cfg(windows)]
fn restore_entry(
    snap: &srt_win::state_db::Snapshot,
    out: &srt_win::state_db::RestoreOutcome,
) -> RestoreEntry {
    use srt_win::state_db::RestoreOutcome;
    let (status, moved_to, left_stamped) = match out {
        RestoreOutcome::Restored | RestoreOutcome::AlreadyOriginal => ("restored", None, None),
        RestoreOutcome::Relocated { moved_to } => ("relocated", Some(moved_to.clone()), Some(true)),
        RestoreOutcome::Missing => ("missing", None, Some(true)),
        RestoreOutcome::LeftChanged => ("leftChanged", None, Some(true)),
        RestoreOutcome::LeftUnreadable => ("leftUnreadable", None, Some(true)),
        RestoreOutcome::Tampered => ("originalSdTampered", None, Some(true)),
        RestoreOutcome::OriginalLost => ("originalSdLost", None, Some(true)),
        RestoreOutcome::StampedUnrecognized => ("stampedUnrecognized", None, Some(true)),
    };
    RestoreEntry {
        path: snap.canonical_path.clone(),
        status,
        expected_file_id: if status == "restored" {
            None
        } else {
            Some(snap.file_id.to_hex())
        },
        moved_to,
        left_stamped,
    }
}

/// Per-batch accounting derived from `StampWitness`es. The
/// `failed` count is reported separately; when `failed > 0`,
/// `stamp_targets` has already rolled the batch back and the
/// witness vec is INFORMATIONAL ONLY (so the summary can say
/// "9 newly stamped, …, 1 FAILED — rolled back" rather than
/// all-zeros).
#[derive(Default)]
#[cfg_attr(not(windows), allow(dead_code))]
struct StampTally {
    fresh: u32,
    restamped: u32,
    already: u32,
    fence: u32,
    lost: u32,
}

#[cfg(windows)]
impl StampTally {
    fn from_witnesses(ws: &[srt_win::state_db::StampWitness]) -> Self {
        use srt_win::state_db::StampAction;
        let mut t = Self::default();
        for w in ws {
            match w.action {
                StampAction::Fresh => t.fresh += 1,
                StampAction::ReStamped => t.restamped += 1,
                StampAction::AlreadyStamped => t.already += 1,
            }
            if w.needs_handle_fence {
                t.fence += 1;
            }
            if w.original_lost {
                t.lost += 1;
            }
        }
        t
    }
}

/// Canonicalize a `(denyRead, denyWrite)` input set into stamp
/// targets. Globs are a HARD error: glob expansion is the TS
/// caller's responsibility (`expandWindowsFsDenyPaths`,
/// point-in-time at `initialize()` or per-exec time), so a glob
/// reaching here means the caller bypassed that chokepoint —
/// abort the whole batch rather than silently skip a deny entry.
/// Volume-root directories (no stampable parent — the
/// `(OI)(CI)` stamp would propagate broker-only across the drive)
/// are likewise hard errors. Any other canonicalize failure
/// (nonexistent path, transient open error, unpaired-surrogate
/// canonical) is collected per-path into `bad_inputs`; the caller
/// decides whether to skip-and-continue (`acl stamp`) or treat as
/// a hard error (`exec --deny-*`).
///
/// Shared by `acl stamp` and `exec --deny-*` so the glob/root
/// rejection — the security-relevant guard — has one copy.
#[cfg(windows)]
#[allow(clippy::type_complexity)]
fn canonicalize_deny_targets(
    deny_read: &[String],
    deny_write: &[String],
) -> anyhow::Result<(
    Vec<(String, srt_win::acl::AclMask, bool)>,
    Vec<(String, String)>,
)> {
    use anyhow::anyhow;
    use srt_win::{acl, path_id};
    let mut targets = Vec::new();
    let mut bad_inputs = Vec::new();
    for (list, mask) in [
        (deny_read, acl::AclMask::ReadDeny),
        (deny_write, acl::AclMask::WriteDeny),
    ] {
        for p in list {
            match path_id::canonicalize_path(p) {
                Ok((canon, is_dir)) => {
                    if is_dir && path_id::canonical_parent_of(&canon).is_none() {
                        return Err(anyhow!(
                            "refusing to deny a volume root: '{p}' \
                             (canonical '{canon}') — the (OI)(CI) \
                             stamp would propagate broker-only across \
                             the drive"
                        ));
                    }
                    targets.push((canon, mask, is_dir));
                }
                Err(path_id::CanonError::Glob) => {
                    return Err(anyhow!(
                        "Windows fs deny requires explicit file or \
                         directory paths; got glob '{p}'."
                    ));
                }
                Err(path_id::CanonError::Other(e)) => {
                    bad_inputs.push((p.clone(), format!("{e:#}")));
                }
            }
        }
    }
    Ok((targets, bad_inputs))
}

/// Canonicalize a list of `(paths, ace)` pairs for `apply_aces`.
/// Directories are accepted; volume roots are accepted too (an
/// additive ACE on `C:\` is wide but not destructive — the user can
/// remove it). Globs are a hard error.
#[cfg(windows)]
#[allow(clippy::type_complexity)]
fn canonicalize_ace_targets(
    label: &str,
    inputs: &[(&[String], srt_win::acl::SbAce)],
) -> anyhow::Result<(Vec<(String, srt_win::acl::SbAce)>, Vec<(String, String)>)> {
    use anyhow::anyhow;
    use srt_win::path_id;
    let mut targets = Vec::new();
    let mut bad_inputs = Vec::new();
    for (list, ace) in inputs {
        for p in *list {
            match path_id::canonicalize_path(p) {
                Ok((canon, _is_dir)) => targets.push((canon, *ace)),
                Err(path_id::CanonError::Glob) => {
                    return Err(anyhow!(
                        "Windows fs {label} requires explicit file \
                         or directory paths; got glob '{p}'."
                    ));
                }
                Err(path_id::CanonError::Other(e)) => {
                    bad_inputs.push((p.clone(), format!("{e:#}")));
                }
            }
        }
    }
    Ok((targets, bad_inputs))
}

/// Read `path` and decode it as a single DER-encoded X.509
/// certificate (PEM, base64, or raw DER input — see
/// [`srt_win::cert_store::CertDer::from_pem_or_der`]). Used by
/// `user trust-ca`.
#[cfg(windows)]
fn read_ca_der(path: &str) -> anyhow::Result<srt_win::cert_store::CertDer> {
    use anyhow::Context;
    srt_win::cert_store::CertDer::from_pem_or_der(
        &std::fs::read(path).with_context(|| format!("read CA cert '{path}'"))?,
    )
    .with_context(|| format!("decode CA cert '{path}'"))
}

/// Drop-guarded per-exec restore. Constructed immediately after a
/// successful per-exec stamp so EVERY exit path between stamp and
/// `process::exit` — `?`, panic, or normal return — runs the
/// matching restore for `holder`. A panic in `open_holder_fences`
/// or `launch::run_lockdown` would otherwise unwind past the
/// restore and leak the stamp under a now-dead PID. A leaked stamp
/// is fail-closed and crash-recovery reaps it once `holder` is
/// observed dead by the next `with_init_lock`, so `failed > 0` is
/// logged but never changes the child's exit code.
#[cfg(windows)]
#[allow(clippy::large_enum_variant)]
enum PerExecRestore {
    /// Same-user model: PROTECTED-stamp restore via
    /// `restore_all(dacls)`.
    SameUser {
        gsid: String,
        holder: srt_win::state_db::HolderPid,
        dacls: srt_win::acl::PrebuiltDacls,
    },
    /// Separate-user model: DENY-ACE release via
    /// `release_aces(KIND_DENY)`. The state-DB / init-mutex
    /// discriminator is the SANDBOX user SID (`with_init_lock`'s
    /// first arg) — the discriminator group is `SameUser`-only.
    SandboxUser {
        holder: srt_win::state_db::HolderPid,
        sandbox_sid: String,
    },
}

#[cfg(windows)]
impl PerExecRestore {
    fn holder(&self) -> srt_win::state_db::HolderPid {
        match self {
            Self::SameUser { holder, .. } | Self::SandboxUser { holder, .. } => *holder,
        }
    }
}

#[cfg(windows)]
impl Drop for PerExecRestore {
    fn drop(&mut self) {
        use srt_win::state_db;
        let (failed, err) = match self {
            Self::SameUser {
                gsid,
                holder,
                dacls,
            } => {
                match state_db::with_init_lock(gsid, *holder, Some(dacls), false, |db| {
                    db.restore_all(dacls)
                }) {
                    Ok((out, _)) => (out.failed, None),
                    Err(e) => (0, Some(e)),
                }
            }
            Self::SandboxUser {
                holder,
                sandbox_sid,
            } => {
                match state_db::with_init_lock(sandbox_sid, *holder, None, false, |db| {
                    db.release_aces(sandbox_sid, state_db::KIND_DENY)
                }) {
                    Ok(((_, failed), _)) => (failed, None),
                    Err(e) => (0, Some(e)),
                }
            }
        };
        if failed > 0 {
            eprintln!(
                "srt-win: WARNING: per-exec restore left {failed} \
                 path(s) stamped (fail-closed) — see prior \
                 per-path warnings; `acl recover` will clear \
                 them once pid {} is dead",
                self.holder().0,
            );
        }
        if let Some(e) = err {
            eprintln!(
                "srt-win: WARNING: per-exec restore failed \
                 ({e:#}); leftover stamps stay fail-closed and \
                 are reaped by the next `acl` op once pid {} is \
                 dead",
                self.holder().0,
            );
        }
    }
}

/// Open the per-exec delete/rename fence for `holder`'s stamps:
/// the LOAD-BEARING file fence on `parent_stamp_failed=1` files
/// (must succeed — `?` propagates) plus the best-effort dir fence
/// on stamped parents and the state-DB dir.
///
/// `fence_plan_for_holder` reads both lists in one RO snapshot
/// (single WAL frame) so a concurrent re-stamp's step-4 upsert
/// (which forces `parent_stamp_failed=1` until step 7) cannot
/// drop a parent from BOTH lists.
///
/// The dir fence is best-effort: a no-`FILE_SHARE_DELETE` handle
/// blocks the child renaming the parent dir ITSELF (rename is
/// authorized by the GRANDPARENT's `FILE_DELETE_CHILD`, which we
/// don't stamp) — preventing path substitution of the directory
/// while the child runs. The state-DB dir is fenced for the same
/// reason (a child renaming it could plant a poisoned DB at the
/// path). Open-fail → log + continue: file DACLs still hold; only
/// directory-rename is unguarded (the documented residual).
///
/// Shared by the session-level (`--holder-pid`) and per-exec
/// (`--deny-*`) fence sites so the recipe for "what gets fenced"
/// — and the diagnostic that says so — has one copy.
#[cfg(windows)]
fn open_holder_fences(
    holder: srt_win::state_db::HolderPid,
    label: &str,
) -> anyhow::Result<(srt_win::fence::DeleteFence, srt_win::fence::DeleteFence)> {
    use anyhow::Context;
    use srt_win::{fence, state_db};
    let plan = state_db::fence_plan_for_holder(holder)
        .with_context(|| {
            format!(
                "{label} fence plan: state-DB lookup for holder {}",
                holder.0
            )
        })?
        .unwrap_or_default();
    let nfb = plan.fallback_files.len();
    let f = fence::open_delete_fence(&plan.fallback_files)?;
    if nfb == 0 {
        eprintln!(
            "srt-win: {label}: handle fence: holder_pid={} → 0 \
             path(s) (parent stamps cover all)",
            holder.0,
        );
    } else {
        eprintln!(
            "srt-win: {label}: handle fence (fallback): \
             holder_pid={} → {nfb} parent-stamp-failed path(s) \
             fenced",
            holder.0,
        );
    }
    let mut dirs = plan.parents;
    if let Ok(sd) = state_db::state_dir() {
        dirs.push(sd.display().to_string());
    }
    let df = fence::open_best_effort(&dirs, label);
    Ok((f, df))
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(windows), allow(dead_code))]
struct AclStampInput {
    #[serde(default)]
    deny_read: Vec<String>,
    #[serde(default)]
    deny_write: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
#[cfg_attr(not(windows), allow(dead_code))]
struct AclGrantInput {
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
}

/// One per-path entry of `acl revoke --json` / `acl restore
/// --sandbox-user-sid --json`.
#[derive(serde::Serialize)]
#[cfg_attr(not(windows), allow(dead_code))]
struct AceReleaseEntry {
    path: String,
    status: &'static str,
}

#[derive(Subcommand)]
enum WfpCmd {
    /// Install (or refresh) the machine-wide persistent WFP filters
    /// keyed on the group SID. Idempotent. Self-elevates via UAC if
    /// not already admin.
    Install {
        #[command(flatten)]
        group: GroupRef,
        /// Sublayer GUID. Default is the compile-time constant; pass
        /// when integrating with externally-managed WFP state.
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Loopback port range the sandboxed child may reach
        /// (`LOW-HIGH`, inclusive; default 60080-60089). The host
        /// http/socks proxies bind inside this range on Windows.
        #[arg(long, value_name = "LOW-HIGH")]
        proxy_port_range: Option<String>,
    },
    /// Print WFP fence state as JSON: `{state, filters,
    /// port_range?, hint?}`. Live BFE enumeration only — admin-gated
    /// by BFE; a non-elevated caller gets `state:"cannot-read"`
    /// (exit 0) with a hint pointing at `wfp verify`. Filters are
    /// identified by their `providerData` tag, so only
    /// `--sublayer-guid` is relevant.
    Status {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Behavioral egress-block probe: spawn the runner as the
    /// sandbox user and attempt a direct TCP connect to
    /// `--target`. The WFP block-user filter fires at
    /// `ALE_AUTH_CONNECT` — before any packet leaves — so an
    /// active fence yields WSAEACCES immediately.
    /// Prints `{"egress_probe":"blocked"|"connected"|"unreachable",
    /// "target":…}` and exits **0** (blocked = fence active),
    /// **3** (connected = fence MISSING), **2** (unreachable =
    /// timeout/no-route; treat as failure), or **15** when the
    /// sandbox user is not provisioned. Any other code (including
    /// 1, the runner's own anyhow `Err` path) maps to
    /// `egress_probe:"error"`. Does not require elevation. This
    /// is the non-elevated readiness check the host's
    /// `initialize()` runs; `wfp status` is the elevated
    /// ground-truth enum.
    Verify {
        /// Probe target (`host:port`). The host binds a local
        /// listener on an ephemeral loopback port OUTSIDE the WFP
        /// loopback-permit range and passes it here, so the
        /// fence-inactive case is deterministic without depending
        /// on any external host.
        #[arg(long)]
        target: String,
    },
    /// Remove every srt-win-tagged WFP filter under the sublayer.
    /// Self-elevates via UAC if not already admin.
    Uninstall {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
}

#[cfg(windows)]
fn main() {
    if let Err(e) = run() {
        eprintln!("srt-win: error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{Context, anyhow};
    use serde_json::json;
    use srt_win::{sid, wfp};

    let cli = Cli::parse();

    // Validate a caller-supplied SID string up front so a typo
    // surfaces as "invalid --<flag>" rather than an SDDL parse
    // error three calls deep. Returns the CANONICAL `S-1-…` form
    // (round-tripped through ConvertSidToStringSidW) so SDDL
    // shorthands like `BA` or lower-case `s-1-…` collapse to a
    // single comparable representation; downstream
    // `eq_ignore_ascii_case("S-1-5-32-544")` dedup checks rely on
    // that.
    let canonicalize_sid = |flag: &str, s: &str| -> anyhow::Result<String> {
        let p =
            sid::LocalPsid::from_string(s).with_context(|| format!("invalid --{flag} '{s}'"))?;
        sid::psid_to_string(p.as_psid()).with_context(|| format!("canonicalize --{flag} '{s}'"))
    };
    let resolve_group_sid = |g: &GroupRef| -> anyhow::Result<String> {
        if let Some(s) = &g.group_sid {
            return canonicalize_sid("group-sid", s);
        }
        sid::lookup_account_sid(&g.name).with_context(|| format!("resolve group '{}'", g.name))
    };
    let resolve_sublayer = |s: &Option<String>| -> anyhow::Result<windows::core::GUID> {
        match s {
            Some(g) => wfp::parse_guid(g),
            None => Ok(wfp::DEFAULT_SUBLAYER_GUID),
        }
    };

    match cli.cmd {
        // ─── install / uninstall (convenience) ─────────────────────
        Cmd::Install {
            group,
            user_sid,
            sublayer_guid,
            proxy_port_range,
            force,
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let range = match &proxy_port_range {
                Some(s) => wfp::parse_port_range(s)
                    .with_context(|| format!("invalid --proxy-port-range '{s}'"))?,
                None => wfp::DEFAULT_PROXY_PORT_RANGE,
            };
            // Idempotency / conflict pre-check. With a DIFFERENT
            // port-range and no --force, refuse (exit 13) so an
            // unintended config drift surfaces instead of silently
            // overwriting. With the SAME range, only return early
            // when the install is COMPLETE — i.e. the sandbox
            // user is provisioned, the marker is current, and the
            // user-SID filter set is present. A pre-separate-user
            // install (or one that exited 14 after WFP) falls
            // through and the (idempotent) steps below complete
            // it. A pre-existing install whose tags lack a
            // port_range (legacy) is treated as "different" and
            // requires --force.
            if !force
                && let Ok(st) = wfp::filter_status(&sl)
                && st.state == "installed"
            {
                let want = [range.0, range.1];
                if st.port_range == Some(want) {
                    use srt_win::{install, user};
                    let us = user::status()?;
                    let mv = install::read_setup()
                        .ok()
                        .flatten()
                        .map(|s| s.marker_version);
                    if us.exists
                        && us.in_sandbox_group
                        && mv == Some(install::SETUP_VERSION)
                        && st.user_filters > 0
                    {
                        eprintln!(
                            "srt-win: already installed (sublayer={sl:?}, \
                             port_range={}-{}, filters={}); no changes",
                            range.0, range.1, st.filters,
                        );
                        return Ok(());
                    }
                    eprintln!(
                        "srt-win: partial install detected \
                         (user_provisioned={}, marker_version={:?}, \
                         user_filters={}) — completing",
                        us.exists, mv, st.user_filters,
                    );
                    // Fall through; group/WFP/user steps are all
                    // idempotent.
                }
                if st.port_range != Some(want) {
                    let have = st
                        .port_range
                        .map(|[l, h]| format!("{l}-{h}"))
                        .unwrap_or_else(|| "<unknown>".into());
                    eprintln!(
                        "srt-win: error: already installed under \
                         sublayer {sl:?} with port_range={have}; \
                         pass --force to replace, or run `srt-win \
                         uninstall` first."
                    );
                    std::process::exit(13);
                }
            }
            // With --group-sid the group is externally managed;
            // just canonicalize. With --name (or the default),
            // create the local group, add the user, then resolve
            // the SID. Failures here exit 11.
            let group_step = || -> anyhow::Result<(String, String)> {
                if let Some(s) = &group.group_sid {
                    let g = canonicalize_sid("group-sid", s)?;
                    Ok((g.clone(), g))
                } else {
                    let user = match &user_sid {
                        Some(s) => canonicalize_sid("user-sid", s)?,
                        None => sid::current_user_sid().context("resolve current user")?,
                    };
                    wfp::ensure_group(&group.name, &user)?;
                    let g = sid::lookup_account_sid(&group.name)?;
                    Ok((group.name.clone(), g))
                }
            };
            let (label, gsid) = match group_step() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("srt-win: error: group step: {e:#}");
                    std::process::exit(11);
                }
            };
            if let Err(e) = wfp::install_filters(&sl, &gsid, range) {
                eprintln!("srt-win: error: WFP install: {e:#}");
                std::process::exit(12);
            }
            // Sandbox user account + credential file + setup
            // marker + user-SID-keyed WFP filters. Additive: the
            // discriminator-group path above is unchanged; both
            // filter sets coexist in the same sublayer. Failures
            // here exit 14 so the caller can distinguish "group/
            // WFP fine, user provisioning failed" from the legacy
            // 11/12 codes.
            let user_step = || -> anyhow::Result<srt_win::user::ProvisionedUser> {
                use srt_win::{install, user};
                let pu = user::provision().context("provision sandbox user")?;
                install::write_setup(&pu, &gsid)
                    .context("write sandbox credential + setup marker to state DB")?;
                wfp::install_user_filters(&sl, &pu.sid, range)
                    .context("install user-SID WFP filters")?;
                Ok(pu)
            };
            let pu = match user_step() {
                Ok(pu) => pu,
                Err(e) => {
                    eprintln!("srt-win: error: sandbox user step: {e:#}");
                    std::process::exit(14);
                }
            };
            eprintln!(
                "srt-win: installed (group={label} sid={gsid}, sublayer={sl:?}, \
                 proxy_port_range={}-{}, filters={}+{})",
                range.0,
                range.1,
                wfp::GROUP_FILTER_COUNT,
                wfp::USER_FILTER_COUNT,
            );
            eprintln!(
                "srt-win: sandbox user '{}' provisioned (sid={}, \
                 group={} sid={})",
                pu.username,
                pu.sid,
                srt_win::user::SANDBOX_GROUP,
                pu.group_sid,
            );
            eprintln!(
                "srt-win: NOTE — log out and back in before running \
                 `srt-win exec` (the group SID enters TokenGroups at \
                 logon; your network is unaffected meanwhile)."
            );
        }
        Cmd::Uninstall {
            sublayer_guid,
            keep_user,
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = wfp::uninstall_filters(&sl)?;
            let user_note = if keep_user {
                "Sandbox user kept (--keep-user)."
            } else {
                use srt_win::{install, user};
                install::clear_setup().context("clear credential + setup marker")?;
                user::deprovision().context("deprovision sandbox user")?;
                "Sandbox user, credential, and setup marker removed."
            };
            eprintln!(
                "srt-win: uninstalled ({n} filter(s) removed). \
                 Group is left intact — run `srt-win group delete` \
                 to remove it. {user_note}"
            );
        }

        // ─── user ──────────────────────────────────────────────────
        Cmd::User {
            sub: UserCmd::Status,
        } => {
            use srt_win::{install, user};
            let st = user::status()?;
            let setup = install::read_setup().ok().flatten();
            let ca = install::read_ca_cert()?;
            let ca = ca.as_ref();
            println!(
                "{}",
                json!({
                    "user": st,
                    "cred_present": setup.is_some(),
                    "marker_version": setup.as_ref().map(|s| s.marker_version),
                    "marker_user_sid": setup.as_ref()
                        .map(|s| s.sandbox_user_sid.as_str()),
                    // The calling (real) user's SID — the trustee for
                    // `acl stamp` under the separate-user model.
                    "real_user_sid": srt_win::sid::current_user_sid()?,
                    "ca_cert_thumb": ca.map(|c| c.thumb()).transpose()?,
                    "ca_cert_pem": ca.map(|c| c.to_pem()).transpose()?,
                })
            );
        }
        Cmd::User {
            sub: UserCmd::ReadCred,
        } => {
            let cred = srt_win::install::read_cred()?;
            // Password only, no trailing whitespace, so a caller
            // can capture stdout verbatim.
            print!("{}", cred.pw);
        }
        Cmd::User {
            sub: UserCmd::TrustCa { path },
        } => {
            use srt_win::install;
            let der = read_ca_der(&path)?;
            let cred = install::read_cred()?;
            let sb_sid = install::read_setup()?
                .ok_or_else(|| anyhow!("sandbox user not provisioned"))?
                .sandbox_user_sid;
            install::trust_ca(&der, &cred, &sb_sid)?;
            eprintln!(
                "srt-win: CA installed into sandbox-user Root \
                 (thumb={})",
                der.thumb()?,
            );
        }

        // ─── group ─────────────────────────────────────────────────
        Cmd::Group {
            sub: GroupCmd::Create { group, user_sid },
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            if group.group_sid.is_some() {
                return Err(anyhow!(
                    "`group create` needs --name; --group-sid is for \
                     referencing an existing group"
                ));
            }
            let user = match &user_sid {
                Some(s) => canonicalize_sid("user-sid", s)?,
                None => sid::current_user_sid().context("resolve current user")?,
            };
            wfp::ensure_group(&group.name, &user)?;
            let gsid = sid::lookup_account_sid(&group.name)?;
            eprintln!(
                "srt-win: group '{}' present (sid={gsid}); user {user} added",
                group.name
            );
            eprintln!(
                "srt-win: NOTE — the group SID enters TokenGroups at logon. \
                 Log out and back in before running `srt-win exec`."
            );
        }
        Cmd::Group {
            sub: GroupCmd::Status { group },
        } => {
            // Resolve SID first; if that fails the group is absent.
            let gsid = match &group.group_sid {
                Some(s) => {
                    // --group-sid bypasses the name lookup, so do a
                    // reverse lookup to distinguish "exists but not on
                    // this token yet" from "no such account at all".
                    // Tolerate transient lookup failure (domain
                    // unreachable) by falling through to the token
                    // check.
                    match sid::sid_account_exists(s) {
                        Ok(sid::SidExistence::Unmapped) => {
                            println!("{}", json!({"state": "absent"}));
                            return Ok(());
                        }
                        Ok(_) => {}
                        Err(e) => {
                            // Malformed SID string.
                            println!("{}", json!({"state": "absent", "error": e.to_string()}));
                            return Ok(());
                        }
                    }
                    s.clone()
                }
                None => match sid::lookup_account_sid(&group.name) {
                    Ok(s) => s,
                    Err(_) => {
                        println!("{}", json!({"state": "absent"}));
                        return Ok(());
                    }
                },
            };
            let out = match sid::group_state_for_self(&gsid)? {
                sid::GroupState::Enabled => {
                    json!({"state": "ready", "sid": gsid})
                }
                sid::GroupState::Absent => {
                    json!({"state": "created-not-on-token", "sid": gsid})
                }
                sid::GroupState::DenyOnly => json!({
                    "state": "created-not-on-token",
                    "sid": gsid,
                    "warning": "group is deny-only in this token — running \
                                inside a sandbox child?"
                }),
                sid::GroupState::Present => json!({
                    "state": "created-not-on-token",
                    "sid": gsid,
                    "warning": "group present but neither enabled nor \
                                deny-only (unexpected)"
                }),
            };
            println!("{out}");
        }
        Cmd::Group {
            sub: GroupCmd::Delete { group },
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            if group.group_sid.is_some() {
                return Err(anyhow!("`group delete` needs --name; cannot delete by SID"));
            }
            wfp::delete_group(&group.name)?;
            eprintln!("srt-win: group '{}' deleted (if it existed)", group.name);
        }

        // ─── wfp ───────────────────────────────────────────────────
        Cmd::Wfp {
            sub:
                WfpCmd::Install {
                    group,
                    sublayer_guid,
                    proxy_port_range,
                },
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let gsid = resolve_group_sid(&group)?;
            let sl = resolve_sublayer(&sublayer_guid)?;
            let range = match &proxy_port_range {
                Some(s) => wfp::parse_port_range(s)
                    .with_context(|| format!("invalid --proxy-port-range '{s}'"))?,
                None => wfp::DEFAULT_PROXY_PORT_RANGE,
            };
            wfp::install_filters(&sl, &gsid, range)?;
            eprintln!(
                "srt-win: WFP filters installed (group_sid={gsid}, \
                 sublayer={sl:?}, proxy_port_range={}-{})",
                range.0, range.1,
            );
        }
        Cmd::Wfp {
            sub: WfpCmd::Status { sublayer_guid },
        } => {
            let sl = resolve_sublayer(&sublayer_guid)?;
            let st = wfp::filter_status(&sl)?;
            println!("{}", serde_json::to_string(&st)?);
        }
        Cmd::Wfp {
            sub: WfpCmd::Verify { target },
        } => {
            use srt_win::{install, logon, runner};
            // The WFP BLOCK fires at ALE_AUTH_CONNECT before any
            // packet leaves, so an active fence gives WSAEACCES
            // (~0ms, exit 0); a MISSING fence lets the connect
            // succeed (exit 3). The host passes a local loopback
            // listener bound outside the WFP permit range so
            // fence-missing is distinguishable from fence-active
            // without depending on any external host.
            let r = install::read_cred().and_then(|c| {
                let s = install::read_setup()?
                    .ok_or_else(|| anyhow!("sandbox user not provisioned"))?;
                Ok((s.sandbox_user_sid, c))
            });
            let (sb_sid, cred) = match r {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("srt-win: error: wfp verify: {e:#}");
                    std::process::exit(15);
                }
            };
            let code = logon::spawn_runner(
                &cred.user,
                &cred.pw,
                &sb_sid,
                None,
                &runner::RunnerCmd::ProbeEgress {
                    target: target.clone(),
                },
            )
            .context("spawn runner for egress probe")?;
            let probe = match code {
                0 => "blocked",
                3 => "connected",
                2 => "unreachable",
                // 1 is the runner's own anyhow `Err` path
                // (`main()` → `eprintln!` + `exit(1)`); anything
                // else is an unmapped runner state. Neither is a
                // valid probe outcome.
                _ => "error",
            };
            println!(
                "{}",
                json!({
                    "egress_probe": probe,
                    "target": target,
                    "runner_exit": code,
                })
            );
            // `process::exit`'s rt::cleanup flushes stdout, but be
            // explicit — this is the only arm that prints to stdout
            // and then `process::exit`s instead of returning Ok(()).
            let _ = std::io::Write::flush(&mut std::io::stdout());
            std::process::exit(code as i32);
        }
        Cmd::Wfp {
            sub: WfpCmd::Uninstall { sublayer_guid },
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = wfp::uninstall_filters(&sl)?;
            eprintln!("srt-win: removed {n} WFP filter(s)");
        }

        // ─── acl ───────────────────────────────────────────────────
        Cmd::Acl {
            sub:
                AclCmd::Stamp {
                    group,
                    holder_pid,
                    sandbox_user_sid: Some(sb),
                },
        } => {
            // Separate-user model: deny is an additive DENY ACE
            // for the sandbox user (plus parent-FDC DENY) — same
            // lifecycle as `acl grant`, no PROTECTED rewrite.
            use srt_win::{acl, state_db};
            let gsid = resolve_group_sid(&group)?;
            let holder = state_db::HolderPid(holder_pid);
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).context("read stdin")?;
            let input: AclStampInput = serde_json::from_str(&buf)
                .context("parse stdin JSON {denyRead:[…], denyWrite:[…]}")?;
            let (targets, bad_inputs) = canonicalize_ace_targets(
                "deny",
                &[
                    (&input.deny_read, acl::SbAce::Deny(acl::DenyMask::ReadDeny)),
                    (
                        &input.deny_write,
                        acl::SbAce::Deny(acl::DenyMask::WriteDeny),
                    ),
                ],
            )?;
            for (p, e) in &bad_inputs {
                eprintln!("srt-win: skipped: '{p}': {e}");
            }
            let ((witnesses, failed), report) =
                state_db::with_init_lock(&gsid, holder, None, false, |db| {
                    db.apply_aces(&sb, &targets)
                })?;
            let fresh = witnesses.iter().filter(|w| !w.already).count();
            eprintln!(
                "srt-win: acl stamp (deny-ace) — {} target(s) → {} \
                 ACE(s) ({} fresh{}{}); recovery pruned {} dead \
                 broker(s), revoked {} orphan ACE(s)",
                targets.len(),
                witnesses.len(),
                fresh,
                if !bad_inputs.is_empty() {
                    format!(", {} skipped", bad_inputs.len())
                } else {
                    String::new()
                },
                if failed > 0 {
                    format!(", {failed} FAILED — rolled back")
                } else {
                    String::new()
                },
                report.dead_brokers,
                report.aces_revoked,
            );
            if failed > 0 {
                return Err(anyhow!(
                    "{failed} of {} path(s) could not be stamped; \
                     batch rolled back",
                    targets.len(),
                ));
            }
            if !bad_inputs.is_empty() {
                eprintln!(
                    "srt-win: {} input path(s) skipped (see above); \
                     exiting 2 (partial)",
                    bad_inputs.len()
                );
                std::process::exit(2);
            }
        }
        Cmd::Acl {
            sub:
                AclCmd::Stamp {
                    group,
                    holder_pid,
                    sandbox_user_sid: None,
                },
        } => {
            use srt_win::state_db;
            let gsid = resolve_group_sid(&group)?;
            let holder = state_db::HolderPid(holder_pid);
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).context("read stdin")?;
            let input: AclStampInput = serde_json::from_str(&buf)
                .context("parse stdin JSON {denyRead:[…], denyWrite:[…]}")?;
            // Canonicalize and reject globs BEFORE taking the mutex
            // so a bad input doesn't hold the lock. Soft
            // canonicalize failures are collected per-path and the
            // batch continues — but exit is non-zero so the host
            // never treats a partial stamp as success.
            let (targets, bad_inputs) =
                canonicalize_deny_targets(&input.deny_read, &input.deny_write)?;
            for (p, e) in &bad_inputs {
                eprintln!("srt-win: skipped: '{p}': {e}");
            }
            let dacls = srt_win::acl::PrebuiltDacls::for_current_user(&gsid)?;
            // Session-level: cross-broker escalation is intentional
            // → refuse_escalation = false.
            let ((witnesses, failed), report) =
                state_db::with_init_lock(&gsid, holder, Some(&dacls), false, |db| {
                    db.stamp_targets(&targets, &dacls, false)
                })?;
            // Summary (incl. crash-recovery report) printed on
            // success AND on per-path failure — the report is
            // diagnostic signal that distinguishes "stamp failed
            // but recovery cleaned N orphans" from "DB pristine".
            let tally = StampTally::from_witnesses(&witnesses);
            eprintln!(
                "srt-win: acl stamp — {} path(s) ({} newly stamped, \
                 {} escalated, {} already held, {} parent-stamp \
                 fallback{}{}{}); recovery pruned {} dead broker(s), \
                 restored {} orphan(s)",
                targets.len(),
                tally.fresh,
                tally.restamped,
                tally.already,
                tally.fence,
                if tally.lost > 0 {
                    format!(", {} original_sd_lost", tally.lost)
                } else {
                    String::new()
                },
                if !bad_inputs.is_empty() {
                    format!(", {} skipped", bad_inputs.len())
                } else {
                    String::new()
                },
                if failed > 0 {
                    format!(", {failed} FAILED — rolled back")
                } else {
                    String::new()
                },
                report.dead_brokers,
                report.restored,
            );
            if failed > 0 {
                // All-or-nothing: `stamp_targets` already rolled
                // this batch back. Exit non-zero AFTER the summary.
                return Err(anyhow!(
                    "{failed} of {} path(s) could not be stamped; \
                     batch rolled back",
                    targets.len(),
                ));
            }
            if !bad_inputs.is_empty() {
                // Exit 2 = partial: the resolvable inputs WERE
                // stamped (so the sandbox is safe to run for
                // those), but at least one input was skipped. The
                // host must surface this rather than treat it as
                // success.
                eprintln!(
                    "srt-win: {} input path(s) skipped (see above); \
                     exiting 2 (partial)",
                    bad_inputs.len()
                );
                std::process::exit(2);
            }
        }
        Cmd::Acl {
            sub:
                AclCmd::Grant {
                    group,
                    holder_pid,
                    sandbox_user_sid,
                },
        } => {
            use srt_win::{acl, state_db};
            let gsid = resolve_group_sid(&group)?;
            let holder = state_db::HolderPid(holder_pid);
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).context("read stdin")?;
            let input: AclGrantInput =
                serde_json::from_str(&buf).context("parse stdin JSON {read:[…], write:[…]}")?;
            let (targets, bad_inputs) = canonicalize_ace_targets(
                "grant",
                &[
                    (&input.read, acl::SbAce::Grant(acl::GrantMask::ReadOnly)),
                    (&input.write, acl::SbAce::Grant(acl::GrantMask::Modify)),
                ],
            )?;
            for (p, e) in &bad_inputs {
                eprintln!("srt-win: skipped: '{p}': {e}");
            }
            let ((witnesses, failed), report) =
                state_db::with_init_lock(&gsid, holder, None, false, |db| {
                    db.apply_aces(&sandbox_user_sid, &targets)
                })?;
            let fresh = witnesses.iter().filter(|w| !w.already).count();
            eprintln!(
                "srt-win: acl grant — {} path(s) ({} fresh, {} \
                 already held{}{}); recovery pruned {} dead \
                 broker(s), revoked {} orphan ACE(s)",
                targets.len(),
                fresh,
                witnesses.len() - fresh,
                if !bad_inputs.is_empty() {
                    format!(", {} skipped", bad_inputs.len())
                } else {
                    String::new()
                },
                if failed > 0 {
                    format!(", {failed} FAILED — rolled back")
                } else {
                    String::new()
                },
                report.dead_brokers,
                report.aces_revoked,
            );
            if failed > 0 {
                return Err(anyhow!(
                    "{failed} of {} path(s) could not be granted; \
                     batch rolled back",
                    targets.len(),
                ));
            }
            if !bad_inputs.is_empty() {
                eprintln!(
                    "srt-win: {} input path(s) skipped (see above); \
                     exiting 2 (partial)",
                    bad_inputs.len()
                );
                std::process::exit(2);
            }
        }
        Cmd::Acl {
            sub:
                AclCmd::Revoke {
                    group,
                    holder_pid,
                    sandbox_user_sid,
                    json,
                },
        } => {
            use srt_win::state_db;
            let gsid = resolve_group_sid(&group)?;
            let holder = state_db::HolderPid(holder_pid);
            let ((entries, failed), report) =
                state_db::with_init_lock(&gsid, holder, None, false, |db| {
                    db.release_aces(&sandbox_user_sid, state_db::KIND_GRANT)
                })?;
            eprintln!(
                "srt-win: acl revoke — {} path(s){}; recovery \
                 revoked {} orphan grant(s)",
                entries.len(),
                if failed > 0 {
                    format!(", {failed} FAILED (ACE left in place)")
                } else {
                    String::new()
                },
                report.aces_revoked,
            );
            if json {
                let out: Vec<AceReleaseEntry> = entries
                    .iter()
                    .map(|(p, r)| AceReleaseEntry {
                        path: p.clone(),
                        status: r.as_str(),
                    })
                    .collect();
                serde_json::to_writer(std::io::stdout(), &out)
                    .context("write --json revoke result")?;
                println!();
            }
            if failed > 0 {
                return Err(anyhow!("acl revoke: {failed} path(s) could not be revoked"));
            }
        }
        Cmd::Acl {
            sub:
                AclCmd::Restore {
                    group,
                    holder_pid,
                    sandbox_user_sid: Some(sb),
                    json,
                },
        } => {
            // Separate-user model: restore = release the holder's
            // DENY ACEs (target + parent-FDC) via REVOKE_ACCESS.
            use srt_win::state_db;
            let gsid = resolve_group_sid(&group)?;
            let holder = state_db::HolderPid(holder_pid);
            let ((entries, failed), report) =
                state_db::with_init_lock(&gsid, holder, None, false, |db| {
                    db.release_aces(&sb, state_db::KIND_DENY)
                })?;
            eprintln!(
                "srt-win: acl restore (deny-ace) — {} ACE(s){}; \
                 recovery revoked {} orphan ACE(s)",
                entries.len(),
                if failed > 0 {
                    format!(", {failed} FAILED (ACE left in place)")
                } else {
                    String::new()
                },
                report.aces_revoked,
            );
            if json {
                let out: Vec<AceReleaseEntry> = entries
                    .iter()
                    .map(|(p, r)| AceReleaseEntry {
                        path: p.clone(),
                        status: r.as_str(),
                    })
                    .collect();
                let result = RestoreResult {
                    paths: vec![],
                    parents: vec![],
                    aces: out,
                };
                serde_json::to_writer(std::io::stdout(), &result)
                    .context("write --json restore result")?;
                println!();
            }
            if failed > 0 {
                return Err(anyhow!(
                    "acl restore: {failed} path(s) could not be \
                     restored (ACE left, fail-closed)"
                ));
            }
        }
        Cmd::Acl {
            sub:
                AclCmd::Restore {
                    group,
                    holder_pid,
                    sandbox_user_sid: None,
                    json,
                },
        } => {
            use srt_win::state_db;
            let gsid = resolve_group_sid(&group)?;
            let holder = state_db::HolderPid(holder_pid);
            let dacls = srt_win::acl::PrebuiltDacls::for_current_user(&gsid)?;
            let (out, report) =
                state_db::with_init_lock(&gsid, holder, Some(&dacls), false, |db| {
                    db.restore_all(&dacls)
                })?;
            let state_db::RestoreAllOutcomes {
                entries: file_outs,
                parent_outs,
                failed,
            } = out;
            let entries: Vec<RestoreEntry> =
                file_outs.iter().map(|(s, o)| restore_entry(s, o)).collect();
            let restored = entries.iter().filter(|e| e.status == "restored").count();
            let left = entries.len() - restored;
            // Parent left-stamped count is the union of
            // crash-recovery's pass and THIS restore's parent
            // outcomes (previously only the former was reported,
            // so a non-JSON caller saw `0 parent dir(s) left
            // stamped` while a parent was still on disk).
            let parents_left = report.parents_left as usize
                + parent_outs
                    .iter()
                    .filter(|(_, o)| {
                        !matches!(
                            o,
                            state_db::ParentRestoreOutcome::Restored
                                | state_db::ParentRestoreOutcome::AlreadyOriginal
                                | state_db::ParentRestoreOutcome::StillHeld
                        )
                    })
                    .count();
            eprintln!(
                "srt-win: acl restore — {} restored, {} left \
                 (relocated/missing/changed/tampered){}{}",
                restored,
                left,
                if failed > 0 {
                    format!(
                        "; {failed} FAILED (left stamped, fail-closed \
                         — see WARNING(s) above)"
                    )
                } else {
                    String::new()
                },
                if parents_left > 0 {
                    format!("; {} parent dir(s) left stamped", parents_left)
                } else {
                    String::new()
                },
            );
            if json {
                // Parents reported by crash-recovery + by this
                // restore arm, merged.
                let mut all_parents = report.parent_entries.clone();
                all_parents.extend(parent_outs);
                let result = RestoreResult {
                    paths: entries,
                    parents: parent_entries_from(&all_parents),
                    aces: vec![],
                };
                serde_json::to_writer(std::io::stdout(), &result)
                    .context("write --json restore result")?;
                println!();
            }
            if failed > 0 {
                // Per-path catch-and-continue (the batch finished),
                // but the exit code must reflect that at least one
                // path is still carrying the broker-only DACL.
                return Err(anyhow!(
                    "acl restore: {failed} path(s) could not be \
                     restored (left stamped, fail-closed)"
                ));
            }
        }
        Cmd::Acl {
            sub: AclCmd::Recover { group, force, json },
        } => {
            use srt_win::state_db;
            let gsid = resolve_group_sid(&group)?;
            let dacls = srt_win::acl::PrebuiltDacls::for_current_user(&gsid)?;
            // recover only runs crash-recovery (holder-agnostic); the
            // holder PID is irrelevant, pass our own.
            let ((), report) = state_db::with_init_lock(
                &gsid,
                state_db::HolderPid(std::process::id()),
                Some(&dacls),
                force,
                |_db| Ok(()),
            )?;
            eprintln!(
                "srt-win: acl recover — pruned {} dead broker(s), \
                 restored {} orphan(s), {} relocated, {} missing, \
                 left {} (changed since stamp{})",
                report.dead_brokers,
                report.restored,
                report.relocated,
                report.missing,
                report.left_changed,
                if force { "; --force applied" } else { "" },
            );
            if json {
                let result = RestoreResult {
                    paths: report
                        .entries
                        .iter()
                        .map(|(s, o)| restore_entry(s, o))
                        .collect(),
                    parents: parent_entries_from(&report.parent_entries),
                    aces: vec![],
                };
                serde_json::to_writer(std::io::stdout(), &result)
                    .context("write --json recover result")?;
                println!();
            }
        }

        // ─── runner ────────────────────────────────────────────────
        Cmd::Runner => {
            let code = srt_win::runner::run()?;
            std::process::exit(code as i32);
        }

        // ─── exec ──────────────────────────────────────────────────
        Cmd::Exec {
            group,
            skip_group_check,
            holder_pid,
            deny_read,
            deny_write,
            as_sandbox_user,
            env,
            target,
        } => {
            use srt_win::{acl, launch, state_db};
            // No WFP pre-flight here: BFE enumeration is
            // admin-gated, so a non-elevated broker can't read it.
            // The fence is verified BEHAVIORALLY by `srt-win wfp
            // verify` at the host's `initialize()` (it spawns the
            // runner as the sandbox user and expects WSAEACCES on a
            // direct connect). Standalone `srt-win exec` callers
            // should run `srt-win wfp verify` once per session.
            //
            // `target` is `required, num_args=1..` so non-empty.
            let exe = std::path::PathBuf::from(&target[0]);
            let args = &target[1..];

            // Delete/rename fence — FALLBACK only. The primary
            // delete/rename protection is the parent-directory
            // allow-list stamp (`acl stamp` strips the user's
            // FILE_DELETE_CHILD on each protected file's parent).
            // The fence is held only on files whose parent could
            // NOT be stamped (`parent_stamp_failed = 1` — no
            // WRITE_DAC on the parent, or no parent). For that
            // subset the fence is LOAD-BEARING: if any such path
            // can't be opened (after a short retry) the deny
            // guarantee would be incomplete and exec must not run —
            // `?` propagates. With --holder-pid omitted, exec has
            // no state-DB dependency. Logged on the no-flag and
            // success paths; on failure the error names the cause
            // directly.
            let delete_fence = match holder_pid {
                None => {
                    eprintln!("srt-win: handle fence: skipped (no --holder-pid)");
                    None
                }
                Some(pid) => Some(open_holder_fences(state_db::HolderPid(pid), "dir")?),
            };

            // Credential read happens BEFORE the per-exec stamp so
            // the exit-15 fast-fail (not provisioned / stale cred)
            // can `process::exit` without a guard to drop. After
            // this point every exit routes through `?` (Drop runs)
            // or the explicit drop chain at the bottom.
            let sandbox_cred = if as_sandbox_user {
                use srt_win::install;
                let r = install::read_cred().and_then(|c| {
                    let s = install::read_setup()?
                        .ok_or_else(|| anyhow!("sandbox user not provisioned"))?;
                    Ok((s.sandbox_user_sid, c))
                });
                match r {
                    Ok(v) => Some(v),
                    Err(e) => {
                        eprintln!("srt-win: error: --as-sandbox-user: {e:#}");
                        std::process::exit(15);
                    }
                }
            } else {
                None
            };

            // Per-exec file deny — `--deny-read`/`--deny-write`. The
            // session-level stamp (under `--holder-pid`) is applied
            // once at the host's `initialize()`; these flags add
            // PER-EXEC paths, stamped under THIS exec process's
            // own PID — a DISTINCT holder from the session — and
            // restored when the guard drops. That makes per-exec
            // stamp/restore literally the same lifecycle as
            // session `acl stamp` / `acl restore`, just under a
            // different holder: paths the session also holds see
            // refcount>0 → `StillHeld` (no DACL change); per-exec-
            // only paths restore. Any stamp error (dir, glob,
            // canon-fail, classify, tampered, refuse-escalation)
            // FAILS the exec rather than running the child with an
            // incomplete deny set.
            let per_exec_guard = if deny_read.is_empty() && deny_write.is_empty() {
                None
            } else if let Some((sb_sid, _)) = &sandbox_cred {
                // Separate-user model: per-exec deny is the same
                // additive DENY-ACE path as session `acl stamp
                // --sandbox-user-sid`, under THIS exec process's
                // own PID as holder. Release downgrades the mask
                // from the remaining holders' MAX(want_mask), so
                // the same-user `refuse_escalation` guard is not
                // needed.
                let own = state_db::HolderPid(std::process::id());
                let sb = sb_sid.clone();
                let (targets, bad) = canonicalize_ace_targets(
                    "deny",
                    &[
                        (&deny_read, acl::SbAce::Deny(acl::DenyMask::ReadDeny)),
                        (&deny_write, acl::SbAce::Deny(acl::DenyMask::WriteDeny)),
                    ],
                )
                .context("per-exec --deny-*")?;
                if let Some((p, e)) = bad.first() {
                    return Err(anyhow!("per-exec --deny-*: '{p}': {e}"));
                }
                let n = targets.len();
                let ((_w, failed), _r) = state_db::with_init_lock(&sb, own, None, false, |db| {
                    db.apply_aces(&sb, &targets)
                })
                .context("per-exec deny-ace")?;
                if failed > 0 {
                    return Err(anyhow!(
                        "per-exec deny: {failed} of {n} path(s) \
                         could not be stamped; rolled back"
                    ));
                }
                let guard = PerExecRestore::SandboxUser {
                    holder: own,
                    sandbox_sid: sb,
                };
                eprintln!(
                    "srt-win: per-exec deny (deny-ace): \
                     holder_pid={} → {n} target(s)",
                    own.0,
                );
                Some(guard)
            } else {
                let gsid = resolve_group_sid(&group)?;
                let dacls = acl::PrebuiltDacls::for_current_user(&gsid)?;
                let own = state_db::HolderPid(std::process::id());
                // Owned copy for the Drop guard — taken now so
                // guard construction below is a pure move with
                // no allocation between stamp-commit and
                // guard-armed.
                let gsid_for_guard = gsid.clone();
                // Canonicalize first (no mutex held). Same
                // hard-error policy as `acl stamp` for dir/glob;
                // canon-fail (nonexistent / transient) is also a
                // hard error here. The host passes RAW paths
                // (no glob expand, no existsSync filter) and
                // this is the first existence/type check —
                // per-exec is "deny THIS one command", so a
                // missing/typo'd path is a caller error the exec
                // must surface, not silently drop and run the
                // child with the file readable.
                let (targets, bad) = canonicalize_deny_targets(&deny_read, &deny_write)
                    .context("per-exec --deny-*")?;
                if let Some((p, e)) = bad.first() {
                    return Err(anyhow!("per-exec --deny-*: '{p}': {e}"));
                }
                let n = targets.len();
                // refuse_escalation = true: a per-exec stamp must
                // not strict-up a path another holder (or a
                // hardlink alias of one) has — the per-exec
                // restore would see refcount>0 and leave the
                // stricter mask in place past this exec.
                let ((_witnesses, failed), _r) =
                    state_db::with_init_lock(&gsid, own, Some(&dacls), false, |db| {
                        db.stamp_targets(&targets, &dacls, true)
                    })
                    .context("per-exec stamp")?;
                if failed > 0 {
                    // `stamp_targets` rolled back this batch.
                    // `own` is a fresh holder with no prior batch,
                    // so every witness was holder_added=true and
                    // rollback released them all + dropped the
                    // brokers row — DB is exactly as found.
                    return Err(anyhow!(
                        "per-exec stamp: {failed} of {n} path(s) \
                         could not be stamped; rolled back"
                    ));
                }
                // Stamp committed. Construct the guard
                // IMMEDIATELY — before the diagnostic, with no
                // allocation in between (gsid was cloned before
                // the stamp) — so there is no window where a
                // panic or a `?` inserted by a future maintainer
                // can leak the stamp. From here ANY exit routes
                // through the guard's Drop → `restore_all(own)`.
                let guard = PerExecRestore::SameUser {
                    gsid: gsid_for_guard,
                    holder: own,
                    dacls,
                };
                eprintln!(
                    "srt-win: per-exec deny: holder_pid={} → {n} \
                     path(s) stamped",
                    own.0,
                );
                Some(guard)
            };

            // Per-exec fence — queries the plan for `own` only
            // (the session's holder is fenced separately above),
            // so this sees exactly this exec's rows. SandboxUser
            // does not use the handle fence (the parent-FDC DENY
            // ACE is the delete/rename gate; `apply_aces` writes
            // no `acl_snapshots` rows, so the plan is empty).
            let _per_exec_fences = match &per_exec_guard {
                Some(PerExecRestore::SameUser { holder, .. }) => {
                    Some(open_holder_fences(*holder, "per-exec dir")?)
                }
                Some(PerExecRestore::SandboxUser { .. }) | None => None,
            };

            let code = if let Some((sb_sid, cred)) = sandbox_cred {
                // Two-hop launch.
                use srt_win::{logon, runner};
                // Self-protect the BROKER before the logon. The
                // discriminator is the REAL USER's SID (broker is the
                // real user; child is `srt-sandbox`) — NOT the group
                // SID, which is the `SameUser` discriminator. The
                // runner self-protects too; this covers the
                // broker→child hop. Best-effort.
                let real_user = srt_win::sid::current_user_sid()?;
                if let Err(e) = srt_win::self_protect::install_broker_dacl(Some(&real_user)) {
                    eprintln!("srt-win: WARNING: install_broker_dacl: {e:#}");
                }
                // env_overlay = exactly what the caller passed via
                // `--env`. The broker does not enumerate its own
                // environment; the caller (whose proxy/CA-var
                // builder is the single source) supplies the full
                // overlay explicitly.
                let env_overlay: Vec<(String, String)> = env
                    .iter()
                    .map(|kv| {
                        kv.split_once('=')
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .ok_or_else(|| {
                                anyhow!(
                                    "--env value '{kv}' has no '=' \
                                     (expected KEY=VALUE)"
                                )
                            })
                    })
                    .collect::<anyhow::Result<_>>()?;
                eprintln!(
                    "srt-win: --as-sandbox-user: launching runner as \
                     '{}' (overlay={} var(s))",
                    cred.user,
                    env_overlay.len(),
                );
                let cwd = std::env::current_dir()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from));
                logon::spawn_runner(
                    &cred.user,
                    &cred.pw,
                    &sb_sid,
                    cwd.as_deref(),
                    &runner::RunnerCmd::Exec(runner::RunnerSpec {
                        argv: target.clone(),
                        env_overlay,
                    }),
                )?
                // `cred` drops here → `SandboxCred::Drop` zeroes the
                // password.
            } else {
                launch::run_lockdown(
                    &exe,
                    args,
                    &launch::LaunchMode::SameUser {
                        group_sid: resolve_group_sid(&group)?,
                        skip_group_check,
                    },
                )?
            };

            // Lift fences first (so restore re-takes the mutex
            // with no handles open on stamped parents), then run
            // the per-exec restore via the guard's Drop, then the
            // session fence. process::exit skips destructors, so
            // every Drop must be explicit BEFORE it.
            drop(_per_exec_fences);
            drop(per_exec_guard);
            drop(delete_fence);
            std::process::exit(code as i32);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_elevated() -> anyhow::Result<bool> {
    use anyhow::Context;
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).context("OpenProcessToken")?;
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let r = GetTokenInformation(
            tok,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        let _ = CloseHandle(tok);
        r.context("GetTokenInformation(TokenElevation)")?;
        Ok(elev.TokenIsElevated != 0)
    }
}

/// Hard elevation gate: returns an error (no UAC relaunch) when not
/// admin. The granular admin mutators self-elevate via
/// [`maybe_self_elevate`], so this currently has no caller — it's
/// retained as the non-interactive counterpart for code paths that
/// must NOT pop a UAC prompt, hence `allow(dead_code)`.
#[cfg(windows)]
#[allow(dead_code)]
fn require_elevated() -> anyhow::Result<()> {
    if is_elevated()? {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "this command requires elevation — run from an \
             administrator prompt"
        ))
    }
}

/// If not already elevated, re-launch ourselves with the same
/// argv via `ShellExecuteExW(verb="runas")` — one UAC prompt —
/// wait for the elevated child, and return its exit code. If
/// already elevated, returns `Ok(None)` and the caller proceeds
/// in-process. If the user cancels the UAC dialog
/// (`ERROR_CANCELLED`), exits with code **10** so the caller's
/// exit-code contract holds without the caller needing a
/// separate match.
///
/// The elevated child runs in its own (hidden) console, so its
/// stdout/stderr are NOT relayed to the parent. For
/// `install`/`uninstall` that's acceptable: the exit code is the
/// contract; the convenience commands' stderr is informational
/// only. The granular `group create|delete` and `wfp
/// install|uninstall` admin mutators call this too; their stderr is
/// likewise informational. Read-only subcommands (`group status`,
/// `wfp status`, `exec`) run as the broker and never self-elevate.
#[cfg(windows)]
fn maybe_self_elevate() -> anyhow::Result<Option<i32>> {
    use anyhow::Context;
    use srt_win::launch::quote_arg;
    use srt_win::util::wstr;
    use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, GetLastError};
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows::Win32::UI::Shell::{
        SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::PCWSTR;

    if is_elevated()? {
        return Ok(None);
    }

    let exe = std::env::current_exe().context("current_exe")?;
    let exe_str = exe.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "current_exe path '{}' is not representable as UTF-8 \
             (contains unpaired surrogates); cannot self-elevate",
            exe.display()
        )
    })?;
    let exe_w = wstr(exe_str);
    // Rebuild the original argv (minus argv[0]) using
    // CommandLineToArgvW-compatible quoting so the elevated
    // child parses identically.
    let params: String = std::env::args()
        .skip(1)
        .map(|a| quote_arg(&a))
        .collect::<Vec<_>>()
        .join(" ");
    let params_w = wstr(&params);
    let verb_w = wstr("runas");

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: sei is fully initialized; the wide-string buffers
    // outlive the call.
    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok.is_err() {
        let err = unsafe { GetLastError() };
        if err == ERROR_CANCELLED {
            eprintln!("srt-win: UAC prompt cancelled by user");
            std::process::exit(10);
        }
        return Err(anyhow::anyhow!(
            "ShellExecuteExW(runas): {} ({}",
            std::io::Error::from_raw_os_error(err.0 as i32),
            err.0,
        ));
    }
    let h = sei.hProcess;
    if h.is_invalid() {
        return Err(anyhow::anyhow!(
            "ShellExecuteExW returned no process handle"
        ));
    }
    let wait = unsafe { WaitForSingleObject(h, INFINITE) };
    if wait == windows::Win32::Foundation::WAIT_FAILED {
        let err = std::io::Error::last_os_error();
        unsafe {
            let _ = CloseHandle(h);
        }
        return Err(anyhow::anyhow!(
            "WaitForSingleObject(elevated child): {err}"
        ));
    }
    let mut code: u32 = 1;
    unsafe {
        GetExitCodeProcess(h, &mut code).context("GetExitCodeProcess(elevated child)")?;
        let _ = CloseHandle(h);
    }
    // 259 (STILL_ACTIVE) after a successful wait is a real exit
    // code (the wait already proved the process exited), not the
    // still-running sentinel.
    Ok(Some(code as i32))
}

#[cfg(not(windows))]
fn main() {
    // The clap-derived structs above keep `clap` referenced; just
    // print the platform error.
    let _ = <Cli as clap::CommandFactory>::command();
    eprintln!("srt-win: Windows only");
    std::process::exit(2);
}
