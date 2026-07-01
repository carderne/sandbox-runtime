//! Cross-broker state DB for `srt-win acl` — refcount stamped paths
//! and store original SDs so the LAST broker to release a path can
//! restore it.
//!
//! Lives at `%LOCALAPPDATA%\sandbox-runtime\state.db` (rusqlite,
//! WAL). The directory is ACL-stamped broker-only `(OI)(CI)` on
//! every open so the sandbox child cannot tamper with the
//! refcount or wipe snapshot rows.
//!
//! ## Disk-is-truth invariant
//!
//! A row is a **restore record** (`original_sd`, `file_id`) +
//! enumeration index + refcount edge. It NEVER asserts on-disk
//! state. A path counts as protected iff [`Locked::ensure_stamped`]
//! has, in this process under the init-mutex, READ the live DACL
//! and converged it to the broker allow-list. Every row primitive
//! that records "this file is stamped" is therefore module-private
//! — the only way for `main.rs` to assert protection is to receive
//! a sealed [`StampWitness`] from `ensure_stamped`.
//!
//! The restore record's INTEGRITY is anchored on disk via the
//! hash-ACE marker (see `acl.rs`): the broker stamp DACL carries
//! one `S-1-0-…` deny-`READ_CONTROL` ACE encoding
//! `SHA-256(original_sd || file_id)`, which the child cannot forge
//! or strip (no `WRITE_DAC`). Restore recomputes the hash from the
//! row and refuses to write back an `original_sd` that does not
//! match the on-disk marker. A poisoned DB row therefore degrades
//! to a loud fail-closed (`original_sd_tampered`), never to
//! attacker-chosen permissions.
//!
//! ## Locking and crash safety
//!
//! Every `acl stamp|restore|recover` runs under a single named
//! mutex `Local\sandbox-runtime-acl-init` (broker-only DACL). The
//! mutex — NOT a DB transaction — serializes whole operations
//! across brokers; `WAIT_ABANDONED` tells us the previous holder
//! died mid-op (crash-recovery already runs unconditionally).
//!
//! There is deliberately NO single enclosing transaction. Each
//! path's (FS mutation + row change) commits independently so a
//! failure on path Y can't revert path X. The one ordering rule is
//! "the row that preserves `original_sd` outlives the FS mutation":
//! upsert FIRST, then `SetNamedSecurityInfoW`. A crash between
//! leaves a row whose file is still `Unstamped`
//! ([`acl::classify_sd`]), so the next `ensure_stamped` re-derives
//! `original_sd = cur` and the upsert overwrites correctly.

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    CreateMutexExW, GetCurrentProcess, GetProcessTimes, INFINITE, MUTEX_ALL_ACCESS, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, ReleaseMutex, WaitForSingleObject,
};

use crate::acl::{self, AclMask, CapturedSd, MarkerHash, PrebuiltDacls, SbAce, StampClass};
use crate::path_id;
use crate::util::{pcwstr, wstr};

/// Holder PID — the LONG-LIVED process that owns a set of stamps
/// (the Node host in production), NOT the ephemeral `srt-win acl`
/// CLI process. Newtype to avoid confusing it with arbitrary PIDs
/// at call sites; the SQLite `brokers.pid` column stores the bare
/// `u32`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HolderPid(pub u32);

impl std::str::FromStr for HolderPid {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>().map(HolderPid)
    }
}

/// `Local\` = per–Terminal-Services-session namespace. Brokers for
/// the SAME user in DIFFERENT TS sessions share the state DB
/// (`%LOCALAPPDATA%`) but NOT this mutex — they would not exclude
/// each other. `Global\` would, but creating it requires
/// `SeCreateGlobalPrivilege`, which an unelevated broker may lack.
/// The cross-session same-user case is rare enough that we accept
/// the limitation for v1; revisit if a real use case appears.
const MUTEX_NAME: &str = r"Local\sandbox-runtime-acl-init";
const SCHEMA_VERSION: i64 = 5;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS brokers (
  pid                 INTEGER PRIMARY KEY,
  process_create_time INTEGER NOT NULL,
  started_at          INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS holders (
  canonical_path TEXT    NOT NULL,
  pid            INTEGER NOT NULL REFERENCES brokers(pid) ON DELETE CASCADE,
  PRIMARY KEY (canonical_path, pid)
);
CREATE TABLE IF NOT EXISTS acl_snapshots (
  canonical_path TEXT    PRIMARY KEY,
  -- The captured pre-stamp DACL+owner+group blob. NULL only when
  -- the row was reconstructed for an already-stamped file whose
  -- original was lost (DB wiped while stamps live on disk):
  -- restore reports `original_sd_lost` and leaves the file
  -- broker-only rather than guess.
  original_sd    BLOB,
  -- 24-byte stable identity captured at stamp time: 8-byte volume
  -- serial + 16-byte FILE_ID_128. Survives rename. Restore validates
  -- (path, file_id) and FAILS-CLOSED on mismatch (leaves the stamp).
  file_id        BLOB    NOT NULL,
  -- Immediate parent directory's canonical path. NULL only when
  -- the file is at a volume root (no parent).
  parent_path    TEXT,
  -- 1 when the per-exec handle fence must cover this file
  -- (parent unstampable, no parent, OR NumberOfLinks > 1 so an
  -- alternate name may live under an unstamped dir). Recomputed
  -- by ensure_stamped on every call — the DB column is the
  -- enumeration index for the fence-fallback query, never an
  -- assertion that the parent is on-disk-stamped.
  parent_stamp_failed INTEGER NOT NULL DEFAULT 1,
  -- 1 for directory targets (the stamp's ALLOW ACEs carry
  -- (OI)(CI) so the broker-only DACL inherits to the subtree).
  is_dir         INTEGER NOT NULL DEFAULT 0
);
-- One row per parent directory that carries the FDC-removing
-- allow-list. Refcounted by the number of acl_snapshots rows
-- pointing at it (parent_path = canonical_parent_path); restored
-- + dropped when that count falls to zero.
CREATE TABLE IF NOT EXISTS parent_stamps (
  canonical_parent_path TEXT PRIMARY KEY,
  original_sd           BLOB,
  file_id               BLOB
);
CREATE INDEX IF NOT EXISTS holders_by_pid ON holders (pid);
CREATE INDEX IF NOT EXISTS snapshots_by_parent
  ON acl_snapshots (parent_path);
-- Additive explicit ACEs for the sandbox user (separate-user
-- model). kind ∈ {'grant','deny','deny_fdc'}: `acl grant` writes
-- ALLOW rows, `acl stamp --sandbox-user-sid` writes DENY rows on
-- the target plus a `deny_fdc` row on the parent. Unlike
-- acl_snapshots this stores no original_sd — restore is
-- `REVOKE_ACCESS` for the SID, not a full-SD restore. One row per
-- (path, kind); a path may carry one grant AND one deny (the
-- recompose chokepoint applies both). Refcounted via ace_holders.
CREATE TABLE IF NOT EXISTS working_aces (
  canonical_path TEXT NOT NULL,
  kind           TEXT NOT NULL,
  file_id        BLOB NOT NULL,
  -- The effective mask currently on disk: the MAX across live
  -- holders' want_mask (recomputed on every holder add/drop).
  mask           TEXT NOT NULL,
  PRIMARY KEY (canonical_path, kind)
);
CREATE TABLE IF NOT EXISTS ace_holders (
  canonical_path TEXT    NOT NULL,
  kind           TEXT    NOT NULL,
  pid            INTEGER NOT NULL REFERENCES brokers(pid) ON DELETE CASCADE,
  -- THIS holder's requested mask. The on-disk ACE is the MAX
  -- across live holders; release recomputes it so a holder that
  -- escalated the mask doesn't leave it escalated past its exit.
  want_mask      TEXT    NOT NULL,
  PRIMARY KEY (canonical_path, kind, pid)
);
CREATE INDEX IF NOT EXISTS ace_holders_by_pid ON ace_holders (pid);
-- Install-time setup record: the sandbox user's DPAPI-encrypted
-- credential plus the setup marker. One row per provisioned
-- sandbox user (currently exactly one). Additive table — no
-- schema-version bump.
CREATE TABLE IF NOT EXISTS sandbox_user (
  username        TEXT    PRIMARY KEY,
  user_sid        TEXT    NOT NULL,
  group_sid       TEXT    NOT NULL,
  cred            BLOB    NOT NULL,
  marker_version  INTEGER NOT NULL,
  created_at_unix INTEGER NOT NULL,
  -- DER-encoded MITM CA certificate (`srt-win user trust-ca`).
  -- NULL when no CA was installed. Persisted so `user status` can
  -- surface the thumbprint + PEM to the host's tlsTerminate setup
  -- without it having to re-read the original file.
  ca_cert         BLOB
);
"#;

/// One stored restore record. No `mask`/`stamped_sd` — both are
/// derivable via [`acl::classify_sd`], and reading them from a
/// possibly-poisoned row was the verify-before-accept gap.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub canonical_path: String,
    /// `None` ⇔ DB wiped while the file was stamped. Restore
    /// reports `original_sd_lost` and leaves the stamp.
    pub original_sd: Option<CapturedSd>,
    pub file_id: path_id::FileId,
    pub(crate) parent_path: Option<String>,
    pub is_dir: bool,
}

/// One stamped parent directory (the FDC-removing allow-list).
#[derive(Debug, Clone)]
struct ParentStamp {
    original_sd: Option<CapturedSd>,
    file_id: Option<path_id::FileId>,
}

/// Sealed proof that [`Locked::ensure_stamped`] read the live DACL
/// and converged `canon` to the broker stamp at `effective_mask`
/// under the init-mutex. Construction is module-private so the
/// only way to obtain one is via `ensure_stamped`.
#[must_use = "a StampWitness records protection; drop only after \
              tallying"]
// `_sealed: ()` is an INTRA-crate seal (main.rs must not construct
// this); `#[non_exhaustive]` only blocks OTHER crates, so the
// clippy suggestion would weaken the invariant.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug)]
pub struct StampWitness {
    pub canon: String,
    pub effective_mask: AclMask,
    pub action: StampAction,
    pub needs_handle_fence: bool,
    /// File was stamped on disk but no row existed (DB wiped).
    pub original_lost: bool,
    /// True for directory targets (the stamp's ALLOW ACEs carry
    /// `(OI)(CI)` so the broker-only DACL inherits to the whole
    /// subtree).
    pub is_dir: bool,
    /// `add_holder` inserted a NEW (canon, holder_pid) row. False
    /// when this holder already held `canon` from a prior batch —
    /// rollback must NOT `release_one` such a witness or it tears
    /// down the prior batch's hold.
    pub holder_added: bool,
    _sealed: (),
}

/// What `ensure_stamped` did to the file's DACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampAction {
    Fresh,
    ReStamped,
    /// Already at `effective_mask` with a corroborated marker.
    AlreadyStamped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentState {
    Stamped,
    /// File routes to the handle-fence fallback.
    Unstampable,
}

/// Outcome of restoring a parent directory's allow-list stamp.
/// Mirrors [`RestoreOutcome`] for the directory case so the
/// parent-restore path has the same fidelity guarantees as file
/// restore (cur-vs-stamped check, identity gate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentRestoreOutcome {
    /// Wrote `original_sd` back and deleted the row.
    Restored,
    /// Directory already at `original_sd`; dropped the stale row.
    AlreadyOriginal,
    /// One or more child snapshots still reference this parent.
    /// Not yet eligible for restore.
    StillHeld,
    /// Current DACL ≠ stamped (third-party edit) and not
    /// `--force`; row kept, directory left as-is.
    LeftChanged,
    /// `file_id` mismatch — the directory at this path is not
    /// the one we stamped (deleted+recreated). Row kept, dir
    /// untouched. Distinct from `Failed` because there is no
    /// error; the conservative choice is to leave it alone.
    Missing,
    /// `restore_sd` (or the SD/identity capture) failed; row
    /// kept for a later attempt.
    Failed(String),
}

impl ParentRestoreOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Restored => "restored",
            Self::AlreadyOriginal => "alreadyOriginal",
            Self::StillHeld => "stillHeld",
            Self::LeftChanged => "leftChanged",
            Self::Missing => "missing",
            Self::Failed(_) => "leftStamped",
        }
    }
}

/// Outcome of a crash-recovery pass.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub dead_brokers: u32,
    pub restored: u32,
    pub left_changed: u32,
    /// Snapshots whose `(path, file_id)` no longer match — the
    /// stamped file was moved (located elsewhere by ID) or is
    /// gone. Row KEPT (fail-closed); reported, not restored.
    pub relocated: u32,
    pub missing: u32,
    /// Parent directories whose allow-list was restored on this
    /// pass (`parent_refcount` reached zero AND `restore_sd`
    /// succeeded).
    pub parents_restored: u32,
    /// Parent directories whose allow-list could NOT be restored
    /// (refcount zero but `restore_sd` failed); the
    /// `parent_stamps` row is kept and the next pass retries.
    pub parents_left: u32,
    /// Orphaned `working_aces` rows whose ACE was revoked.
    pub aces_revoked: u32,
    /// Per-orphan detail — the structured-result output is
    /// derived from this.
    pub entries: Vec<(Snapshot, RestoreOutcome)>,
    /// Per-parent restore detail (path, outcome).
    pub parent_entries: Vec<(String, ParentRestoreOutcome)>,
}

/// RAII guard for the init mutex. Releases on drop. The mutex
/// HANDLE itself is closed too — `CreateMutexExW` returns a fresh
/// handle every call (with `ERROR_ALREADY_EXISTS` set if the kernel
/// object already existed), so each `acquire` owns its own handle.
struct InitMutex {
    h: HANDLE,
}
impl Drop for InitMutex {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.h);
            let _ = CloseHandle(self.h);
        }
    }
}

impl InitMutex {
    /// Create-or-open and acquire the init mutex. The mutex carries
    /// a broker-only DACL so a sandbox child cannot open it (and
    /// therefore cannot stall stamps by sitting on the lock).
    fn acquire(group_sid: &str) -> Result<Self> {
        let sa =
            acl::build_init_mutex_sa(group_sid).context("build init-mutex SECURITY_ATTRIBUTES")?;
        let name = wstr(MUTEX_NAME);
        // Don't request CREATE_MUTEX_INITIAL_OWNER — if another
        // broker already created the mutex this call opens it,
        // and INITIAL_OWNER would silently NOT acquire in that
        // case. A separate Wait gives a uniform code path and
        // surfaces WAIT_ABANDONED.
        let h = unsafe {
            CreateMutexExW(
                Some(sa.as_ptr()),
                pcwstr(&name),
                0, // dwFlags — no CREATE_MUTEX_INITIAL_OWNER
                MUTEX_ALL_ACCESS.0,
            )
        }
        .with_context(|| format!("CreateMutexExW({MUTEX_NAME})"))?;
        // `sa` can drop now — the kernel object owns its SD.

        let r = unsafe { WaitForSingleObject(h, INFINITE) };
        match r {
            WAIT_OBJECT_0 => {}
            WAIT_ABANDONED => {
                // Previous holder died while owning the mutex. We
                // now own it. Crash-recovery (which the caller will
                // run next) handles the cleanup; nothing extra here.
                eprintln!(
                    "srt-win: init-mutex WAIT_ABANDONED — previous \
                     `srt-win acl` died mid-operation; running recovery"
                );
            }
            other => {
                let err = std::io::Error::last_os_error();
                unsafe {
                    let _ = CloseHandle(h);
                }
                bail!(
                    "WaitForSingleObject({MUTEX_NAME}): unexpected {other:?} \
                     ({err})"
                );
            }
        }
        Ok(Self { h })
    }
}

/// Open (creating if needed) the state DB at the default location.
/// Stamps the parent directory broker-only on EVERY open.
pub fn open_db(group_sid: &str) -> Result<Connection> {
    let dir = state_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create_dir_all {}", dir.display()))?;
    // Stamp the directory `(OI)(CI)` broker-only so the sandbox
    // child cannot tamper with state.db / -wal / -shm. Done on
    // EVERY open, not just first creation: if the dir already
    // existed (older srt-win, unclean prior run, or a same-user
    // child that pre-seeded it) a first-creation-only stamp would
    // leave the child with write access. `SetNamedSecurityInfoW` is
    // idempotent, so re-stamping an already-correct dir is a no-op.
    // Best-effort: if it fails we proceed (the `%LOCALAPPDATA%`
    // default DACL already excludes OTHER users; this defends
    // against the SAME-USER child) and warn so the test harness can
    // assert. We own this directory, so a user-applied custom DACL
    // on it is NOT preserved — it is rewritten on every open by
    // design.
    let dir_str = dir.to_str().ok_or_else(|| {
        anyhow!(
            "state-DB directory path '{}' is not representable as \
             UTF-8 (contains unpaired surrogates); not supported",
            dir.display()
        )
    })?;
    // Include the sandbox-users DENY when the install has
    // provisioned that group. The credential file in this
    // directory is machine-scope DPAPI — readable-by-sandbox =
    // decryptable-by-sandbox — so the DENY is load-bearing once
    // the separate-user runner exists. The lookup distinguishes
    // "group genuinely absent" (install never run / older install
    // → DENY skipped, broker-only allow set still excludes the
    // sandbox user) from a transient SAM/LSA failure — the latter
    // is surfaced rather than silently dropping a security ACE.
    let deny_sid = match crate::sid::lookup_account_sid(crate::user::SANDBOX_GROUP) {
        Ok(s) => Some(s),
        Err(e) => {
            match crate::sid::sid_account_exists("S-1-5-32-545") {
                // BUILTIN\Users always maps; if it does, SAM is up
                // and the sandbox group is genuinely absent.
                Ok(crate::sid::SidExistence::Mapped) => None,
                _ => {
                    eprintln!(
                        "srt-win: WARNING: cannot resolve \
                         '{}' to add the state-dir DENY ACE \
                         ({e:#}); the broker-only allow set \
                         still excludes the sandbox user, but \
                         the explicit DENY is omitted for this \
                         stamp",
                        crate::user::SANDBOX_GROUP,
                    );
                    None
                }
            }
        }
    };
    if let Err(e) = acl::stamp_dir_inheriting(dir_str, group_sid, deny_sid.as_deref()) {
        eprintln!(
            "srt-win: WARNING: failed to stamp state-DB dir {} \
             broker-only: {e:#}",
            dir.display()
        );
    }
    open_db_at(&dir.join("state.db"))
}

/// Per-exec fence inputs for `holder_pid` from a SINGLE WAL
/// snapshot. Read-only ([`open_db_ro`] — no init mutex, no
/// dir-stamp, no schema apply); returns `None` when no `acl
/// stamp` has run yet (state.db absent or schemaless).
///
/// One open + one explicit read transaction so both queries see
/// the same `parent_stamp_failed` bits: a concurrent
/// `ensure_stamped`'s step-4 upsert (which forces the bit to 1
/// until step 7 reconciles) committed between two independent
/// reads would otherwise drop a path from BOTH the file-fence
/// list (`bit=0` at read 1) AND the parent dir-fence list
/// (`bit=1` at read 2). The load-bearing file fence is
/// inherently fail-safe under that race (the transient is
/// `bit=1` → over-fence); the snapshot-consistency keeps the
/// best-effort dir fence from being dropped.
#[derive(Debug, Default)]
pub struct FencePlan {
    /// Files whose parent directory could NOT be stamped
    /// (`parent_stamp_failed = 1`) — the load-bearing per-exec
    /// no-`FILE_SHARE_DELETE` handle fence.
    pub fallback_files: Vec<String>,
    /// Stamped parent directories (`parent_stamp_failed = 0`).
    /// The per-exec dir fence opens a no-`FILE_SHARE_DELETE`
    /// handle on each so a child cannot rename the parent dir
    /// itself (rename is authorized by the GRANDPARENT's
    /// `FILE_DELETE_CHILD`, which we don't stamp).
    pub parents: Vec<String>,
}

pub fn fence_plan_for_holder(holder_pid: HolderPid) -> Result<Option<FencePlan>> {
    let Some(conn) = open_db_ro()? else {
        return Ok(None);
    };
    Ok(Some(fence_plan_on(&conn, holder_pid)?))
}

/// Filter on `release_aces` for the deny-ACE lifecycle.
pub const KIND_DENY: &[&str] = &["deny", "deny_fdc"];
/// Filter on `release_aces` for the grant lifecycle.
pub const KIND_GRANT: &[&str] = &["grant"];

fn fence_plan_on(conn: &Connection, holder_pid: HolderPid) -> Result<FencePlan> {
    // Explicit read txn = single WAL snapshot for both SELECTs.
    // `BEGIN` on a read-only connection takes a read lock that
    // pins the WAL frame until `COMMIT`.
    conn.execute_batch("BEGIN").context("begin fence-plan tx")?;
    let pid = holder_pid.0 as i64;
    let r = (|| -> Result<FencePlan> {
        Ok(FencePlan {
            fallback_files: query_vec(
                conn,
                "SELECT s.canonical_path \
                 FROM holders h \
                 JOIN acl_snapshots s \
                   ON h.canonical_path = s.canonical_path \
                 WHERE h.pid = ?1 AND s.parent_stamp_failed = 1",
                params![pid],
                |r| r.get(0),
            )?,
            parents: query_vec(
                conn,
                "SELECT DISTINCT s.parent_path \
                 FROM holders h \
                 JOIN acl_snapshots s \
                   ON h.canonical_path = s.canonical_path \
                 WHERE h.pid = ?1 \
                   AND s.parent_path IS NOT NULL \
                   AND s.parent_stamp_failed = 0",
                params![pid],
                |r| r.get(0),
            )?,
        })
    })();
    conn.execute_batch("COMMIT")
        .context("commit fence-plan tx")?;
    r
}

/// `prepare → query_map → collect` with one error context. Shared
/// by every "list of T from one query" site so error plumbing is
/// edited once.
fn query_vec<T, P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    p: P,
    row: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut s = conn
        .prepare(sql)
        .with_context(|| format!("prepare: {sql}"))?;
    let it = s
        .query_map(p, row)
        .with_context(|| format!("query: {sql}"))?;
    let mut v = Vec::new();
    for r in it {
        v.push(r.with_context(|| format!("row: {sql}"))?);
    }
    Ok(v)
}

/// Read-only open of the state DB at the default location. Returns
/// `None` if `state.db` doesn't exist yet. No mutex, no
/// `create_dir_all`, no dir-stamp, no schema apply — for `srt-win
/// exec`'s holder-paths read on the per-Bash-call hot path.
pub fn open_db_ro() -> Result<Option<Connection>> {
    let path = state_dir()?.join("state.db");
    match path.try_exists() {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(e) => bail!(
            "cannot determine state-DB presence at {}: {e}; \
             refusing to skip the handle fence",
            path.display()
        ),
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("sqlite open RO {}", path.display()))?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    // open_db_at can crash between Connection::open (which creates
    // the file) and execute_batch(SCHEMA_SQL), leaving a valid
    // SQLite file with no schema. That state means "no stamps yet"
    // — return None so the caller treats it like a missing DB
    // instead of failing on `no such table: holders`. (A truly
    // CORRUPT DB is intentionally fail-closed: if we can't
    // enumerate the holder's stamps we can't prove the fence is
    // complete.)
    let has_schema: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master \
             WHERE type='table' AND name='holders' LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()
        .context("probe schema")?
        .unwrap_or(false);
    if !has_schema {
        return Ok(None);
    }
    // Stale schema → fail closed. `Ok(None)` here would mean
    // `fence_plan_for_holder()` returns an empty plan and the child
    // runs unfenced; bailing surfaces an actionable hint everywhere
    // (`user status`, `exec`'s holder-fence) and install's
    // `read_setup().ok()` still falls through to re-provision.
    let ver: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap_or(0);
    if ver != 0 && ver != SCHEMA_VERSION {
        bail!(
            "state DB at schema v{ver}, expected v{SCHEMA_VERSION}; \
             re-run `srt-win install` to migrate"
        );
    }
    Ok(Some(conn))
}

fn query_holder_paths(conn: &Connection, pid: HolderPid) -> Result<Vec<String>> {
    query_vec(
        conn,
        "SELECT canonical_path FROM holders WHERE pid = ?1",
        params![pid.0 as i64],
        |r| r.get(0),
    )
}

/// Open at an arbitrary path. Tests use `:memory:` via
/// `open_db_at(Path::new(":memory:"))`.
pub fn open_db_at(path: &std::path::Path) -> Result<Connection> {
    // Schema mismatch → rename + recreate. No ALTER/DROP migration:
    // the old DB is preserved (debugging/recovery) at
    // state.db.v<old>.<ts>.bak alongside `path`, and a fresh DB is
    // created at the expected schema. `acl recover` sweeps orphaned
    // ACEs by trustee SID without the old rows. The `sandbox_user`
    // row (cred + ca_cert) is in the renamed-away DB → the hint
    // says re-run install + trust-ca. The .bak inherits the
    // PROTECTED broker-only DACL from the state dir (stamped by
    // [`open_db`]); no per-file stamp needed. Chokepoint here so
    // direct callers (`clear_setup`, `trust_ca`) don't silently
    // bump `user_version` on a stale DB.
    if path.exists() {
        let probe = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY);
        if let Ok(c) = probe {
            let ver: i64 = c
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap_or(0);
            drop(c);
            if ver != 0 && ver != SCHEMA_VERSION {
                let dir = path
                    .parent()
                    .ok_or_else(|| anyhow!("state DB path '{}' has no parent", path.display()))?;
                let stem = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("state.db");
                let ts = unix_now();
                let bak = dir.join(format!("{stem}.v{ver}.{ts}.bak"));
                std::fs::rename(path, &bak).map_err(|e| {
                    // SQLite's win32 VFS opens with no
                    // FILE_SHARE_DELETE; another live broker holds
                    // the file → rename fails 32 here where DROP
                    // TABLE under WAL would have succeeded.
                    if e.raw_os_error() == Some(32) {
                        anyhow!(
                            "rename incompatible state DB {} → {}: {e} \
                             — the DB is open in another process \
                             (likely a running srt-win/broker); close \
                             it and retry",
                            path.display(),
                            bak.display()
                        )
                    } else {
                        anyhow::Error::new(e).context(format!(
                            "rename incompatible state DB {} → {}",
                            path.display(),
                            bak.display()
                        ))
                    }
                })?;
                // WAL sidecars too (best-effort — they hold no cred,
                // only journal pages of it).
                for ext in ["-wal", "-shm"] {
                    let p = dir.join(format!("{stem}{ext}"));
                    let to = dir.join(format!("{stem}.v{ver}.{ts}.bak{ext}"));
                    let _ = std::fs::rename(&p, &to);
                }
                eprintln!(
                    "srt-win: state DB at schema v{ver} found, expected \
                     v{SCHEMA_VERSION}; renamed to {} and created fresh. \
                     Re-run `srt-win install` (and `srt-win user \
                     trust-ca <pem>` if you use TLS termination) to \
                     re-provision; run `srt-win acl recover` to clear \
                     orphaned ACEs.",
                    bak.display(),
                );
            }
        }
    }
    let conn = Connection::open(path).with_context(|| format!("sqlite open {}", path.display()))?;
    // WAL = concurrent readers + single writer + crash safety.
    // `synchronous=NORMAL` is the recommended companion for WAL and
    // is durable across power loss. busy_timeout is belt-and-braces
    // — the named mutex already serializes whole operations across
    // brokers, but a brief contention inside one process (tests)
    // shouldn't error.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.execute_batch(SCHEMA_SQL).context("apply schema")?;
    // Additive column on `sandbox_user` (table predates it).
    // `CREATE TABLE IF NOT EXISTS` doesn't add columns, so probe
    // `pragma_table_info` and ALTER when absent.
    let has_ca = conn
        .query_row(
            "SELECT 1 FROM pragma_table_info('sandbox_user') \
             WHERE name = 'ca_cert'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !has_ca {
        conn.execute("ALTER TABLE sandbox_user ADD COLUMN ca_cert BLOB", [])
            .context("ALTER sandbox_user.ca_cert")?;
    }
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(conn)
}

/// One row of the `sandbox_user` table — the install-time setup
/// record: the sandbox user's DPAPI-encrypted credential plus the
/// setup marker. Written by `srt-win install`, read by the
/// non-elevated broker. The `ca_cert` column is read/written
/// separately ([`read_ca_cert`] / [`set_ca_cert`]) so this struct
/// carries exactly what [`write_setup_info`] owns.
#[derive(Debug, Clone)]
pub struct SetupInfo {
    pub sandbox_user: String,
    pub sandbox_user_sid: String,
    pub sandbox_group_sid: String,
    /// DPAPI ciphertext of the sandbox user's password.
    pub cred: Vec<u8>,
    pub marker_version: u32,
    pub created_at_unix: u64,
}

/// Write the setup record. `ON CONFLICT … DO UPDATE` (NOT
/// `INSERT OR REPLACE`) so a re-install preserves any column this
/// function doesn't own — currently `ca_cert`, whose only writer
/// is [`set_ca_cert`]. Install is sequential under self-elevation,
/// so the caller doesn't need [`with_init_lock`].
pub fn write_setup_info(conn: &Connection, info: &SetupInfo) -> Result<()> {
    conn.execute(
        "INSERT INTO sandbox_user \
           (username, user_sid, group_sid, cred, marker_version, \
            created_at_unix) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(username) DO UPDATE SET \
           user_sid        = excluded.user_sid, \
           group_sid       = excluded.group_sid, \
           cred            = excluded.cred, \
           marker_version  = excluded.marker_version, \
           created_at_unix = excluded.created_at_unix",
        params![
            info.sandbox_user,
            info.sandbox_user_sid,
            info.sandbox_group_sid,
            info.cred,
            info.marker_version,
            info.created_at_unix as i64,
        ],
    )
    .context("UPSERT sandbox_user")?;
    Ok(())
}

/// Hydrate the setup record. `Ok(None)` when no install has run
/// (no row, or the `sandbox_user` table itself absent —
/// [`open_db_ro`] doesn't apply schema). Currently exactly one
/// sandbox user is provisioned, so this reads the single row.
pub fn read_setup_info(conn: &Connection) -> Result<Option<SetupInfo>> {
    match conn
        .query_row(
            "SELECT username, user_sid, group_sid, cred, \
                    marker_version, created_at_unix \
             FROM sandbox_user LIMIT 1",
            [],
            |r| {
                Ok(SetupInfo {
                    sandbox_user: r.get(0)?,
                    sandbox_user_sid: r.get(1)?,
                    sandbox_group_sid: r.get(2)?,
                    cred: r.get(3)?,
                    marker_version: r.get(4)?,
                    created_at_unix: r.get::<_, i64>(5)? as u64,
                })
            },
        )
        .optional()
    {
        Ok(v) => Ok(v),
        Err(e) if missing_sandbox_user_table(&e) => Ok(None),
        Err(e) => Err(anyhow!("SELECT sandbox_user: {e}")),
    }
}

/// Read just the `ca_cert` column from the (single) row. `Ok(None)`
/// when no install has run, no CA was recorded, or the table/column
/// is absent.
pub fn read_ca_cert(conn: &Connection) -> Result<Option<crate::cert_store::CertDer>> {
    match conn
        .query_row("SELECT ca_cert FROM sandbox_user LIMIT 1", [], |r| r.get(0))
        .optional()
    {
        Ok(v) => Ok(v.flatten()),
        Err(e) if missing_sandbox_user_table(&e) => Ok(None),
        Err(e) => Err(anyhow!("SELECT sandbox_user.ca_cert: {e}")),
    }
}

/// Overwrite just the `ca_cert` column on the (single) existing
/// row. `srt-win user trust-ca` uses this to record a CA without
/// re-provisioning. Fails when no install has run yet.
pub fn set_ca_cert(conn: &Connection, der: &crate::cert_store::CertDer) -> Result<()> {
    let n = conn
        .execute("UPDATE sandbox_user SET ca_cert = ?1", params![der])
        .context("UPDATE sandbox_user.ca_cert")?;
    if n == 0 {
        bail!("no sandbox-user row to attach CA to — run `srt-win install`");
    }
    Ok(())
}

/// `DELETE FROM sandbox_user` — uninstall clears the credential
/// and marker in one go.
pub fn clear_setup_info(conn: &Connection) -> Result<()> {
    match conn.execute("DELETE FROM sandbox_user", []) {
        Ok(_) => Ok(()),
        Err(e) if missing_sandbox_user_table(&e) => Ok(()),
        Err(e) => Err(anyhow!("clear_setup_info: {e}")),
    }
}

fn missing_sandbox_user_table(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(_, Some(m))
            if m.contains("no such table") && m.contains("sandbox_user")
    )
}

/// `%LOCALAPPDATA%\sandbox-runtime`. Errors if `LOCALAPPDATA` is
/// unset, empty, or yields a non-absolute path — a relative state
/// dir would put the broker-only-stamped DB in the CWD and break
/// cross-broker refcounting/recovery.
pub fn state_dir() -> Result<PathBuf> {
    state_dir_from(std::env::var_os("LOCALAPPDATA"))
}

fn state_dir_from(local_app_data: Option<std::ffi::OsString>) -> Result<PathBuf> {
    let base = local_app_data
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("LOCALAPPDATA not set or empty"))?;
    let dir = base.join("sandbox-runtime");
    if !dir.is_absolute() {
        bail!(
            "state-DB directory '{}' is not absolute \
             (LOCALAPPDATA='{}'); refusing relative state path",
            dir.display(),
            base.display()
        );
    }
    Ok(dir)
}

/// Run `f` under the init mutex with the DB open. Crash recovery is
/// run first. `f` receives a `Locked` view whose mutating methods
/// each autocommit (single-statement) or use their own short
/// transaction — there is NO single enclosing transaction.
///
/// See module doc for the no-enclosing-tx and ordering rationale.
pub fn with_init_lock<R>(
    group_sid: &str,
    holder_pid: HolderPid,
    dacls: Option<&PrebuiltDacls>,
    force_recover: bool,
    f: impl FnOnce(&mut Locked) -> Result<R>,
) -> Result<(R, RecoveryReport)> {
    let _mutex = InitMutex::acquire(group_sid)?;
    let conn = open_db(group_sid)?;
    let report = crash_recovery(&conn, dacls, force_recover)?;
    let mut locked = Locked {
        conn,
        holder_pid,
        applied_parents: HashSet::new(),
    };
    let out = f(&mut locked)?;
    Ok((out, report))
}

/// Result of a holder's full release pass. Parent restores are a
/// side-effect of file restores (one parent may serve many files
/// and is restored once when its last child's refcount drops).
/// `failed` counts per-path errors swallowed by `release_one`'s
/// catch-and-continue (logged as WARNING) so the caller can exit
/// non-zero without aborting mid-batch.
pub struct RestoreAllOutcomes {
    pub entries: Vec<(Snapshot, RestoreOutcome)>,
    pub parent_outs: Vec<(String, ParentRestoreOutcome)>,
    pub failed: usize,
}

/// View inside `with_init_lock`. Owns the `Connection`; each method
/// commits independently (rusqlite autocommits a lone `execute`).
///
/// `holder_pid` is the LONG-LIVED owner of the stamps — typically
/// the Node host (sandbox-runtime) process, NOT this ephemeral
/// `srt-win acl` process. The CLI exits immediately; keying holders
/// on its PID would let the next acl op's crash-recovery reap it and
/// tear the stamp down. Keying on the caller-supplied holder PID
/// means a stamp persists until that process exits (or explicitly
/// restores), and refcount / crash-recovery track the real session.
pub struct Locked {
    conn: Connection,
    holder_pid: HolderPid,
    /// Parents already converged in this batch — N siblings under
    /// the same directory cost one parent reconcile, not N.
    applied_parents: HashSet<String>,
}

impl Locked {
    /// The single chokepoint for "make `canon` protected at (at
    /// least) `want_mask`": read the live DACL, classify,
    /// corroborate the row against the on-disk marker, record-first
    /// upsert, converge file + parent, derive the fence bit, add
    /// the holder. Returns a sealed [`StampWitness`].
    ///
    /// Fails (no witness, no holder) on `marker_stripped`,
    /// `original_sd_tampered`, or any disk-read error on `canon`.
    ///
    /// `refuse_escalation`: when set, escalating the on-disk mask
    /// (e.g. WriteDeny → ReadDeny) while ANOTHER holder pid holds
    /// `canon` is a hard error. Per-exec `--deny-*` sets this so a
    /// short-lived exec cannot leave a session-held file stuck at
    /// a stricter mask after restore (`release_one` sees
    /// refcount>0 and never re-stamps). Session-level `acl stamp`
    /// passes `false` — cross-broker escalation is intentional
    /// there. The check lives here (post-canonicalize, holders
    /// table visible) because no string-level guard upstream can
    /// see canonical identity or concurrent holders.
    pub fn ensure_stamped(
        &mut self,
        canon: &str,
        want_mask: AclMask,
        is_dir: bool,
        dacls: &PrebuiltDacls,
        refuse_escalation: bool,
    ) -> Result<StampWitness> {
        // 1. Disk first.
        let cur = acl::capture_sd(canon).with_context(|| format!("capture SD for '{canon}'"))?;
        let (cur_id, links) = path_id::capture_id_and_links(canon)
            .with_context(|| format!("capture file_id+links '{canon}'"))?;
        let parent = path_id::canonical_parent_of(canon);

        // 2. Classify.
        let class = acl::classify_sd(&cur, &dacls.calib)
            .with_context(|| format!("classify SD for '{canon}'"))?;

        // 3. Row as original_sd hint, corroborated against the
        //    on-disk marker. The accepted on-disk shape is `File`
        //    for a file target and `DirTarget` for a directory; any
        //    other marker-bearing class is shape drift (e.g. a
        //    parent-shape DACL on a file, or a file-shape DACL on a
        //    dir — neither is something we ever write).
        let prior = self.get_snapshot(canon)?;
        let mut original_lost = false;
        let on_disk = match class {
            StampClass::File(m, h) if !is_dir => Some((m, h)),
            StampClass::DirTarget(m, h) if is_dir => Some((m, h)),
            StampClass::Unstamped => None,
            _ => bail!(
                "'{canon}': on-disk DACL is a derivative of a broker \
                 stamp (marker stripped, shape drifted, or foreign \
                 group/user SID); refusing to capture it as \
                 original_sd (stamped_unrecognized, fail-closed). \
                 `acl recover --force` will write the recorded \
                 original back if you trust the DB row."
            ),
        };
        let (original_sd, eff, on_disk_mask, marker): (
            Option<CapturedSd>,
            AclMask,
            Option<AclMask>,
            MarkerHash,
        ) = match on_disk {
            None => {
                let h = acl::compute_marker_hash(&cur, &cur_id);
                (Some(cur), want_mask, None, h)
            }
            Some((m, h)) => match prior.as_ref() {
                Some(p) if p.file_id == cur_id => match &p.original_sd {
                    Some(orig) if acl::compute_marker_hash(orig, &p.file_id) == h => {
                        (Some(orig.clone()), want_mask.max(m), Some(m), h)
                    }
                    Some(_) => bail!(
                        "'{canon}': DB row's original_sd does not match \
                         the on-disk hash-ACE marker (original_sd_tampered, \
                         fail-closed)"
                    ),
                    None => {
                        original_lost = true;
                        (None, want_mask.max(m), Some(m), h)
                    }
                },
                Some(_) => bail!(
                    "'{canon}': DB row's file_id does not match the \
                     on-disk file (original_sd_tampered, fail-closed)"
                ),
                None => {
                    // DB wiped (not forged — child can't write the
                    // marker). Preserve marker from disk so a
                    // re-stamp keeps it stable.
                    eprintln!(
                        "srt-win: '{canon}': stamped on disk but no DB \
                         row — DB was wiped; original_sd is \
                         unrecoverable (original_sd_lost)"
                    );
                    original_lost = true;
                    (None, want_mask.max(m), Some(m), h)
                }
            },
        };

        // 3b. Refuse-escalation gate (see fn doc).
        //
        //     Hardlink: NTFS hardlinks share one security
        //     descriptor across distinct canonical paths, but
        //     holders/snapshots are PATH-keyed. A per-exec stamp
        //     under one alias is invisible to a holder of another
        //     — `release_one` on the alias sees remaining=0 and
        //     restores the SHARED DACL while the other holder's
        //     child is still running, regardless of mask. So
        //     `links != 1` (captured in step 1) is an
        //     UNCONDITIONAL refuse for per-exec, independent of
        //     `on_disk_mask`/`eff`. Session-level `acl stamp`
        //     keeps the existing route-to-handle-fence behaviour
        //     (step 7) instead.
        if refuse_escalation && !is_dir && links != 1 {
            bail!(
                "per-exec deny refused: '{canon}' has {links} \
                 hardlink(s); holder rows are path-keyed, so a \
                 concurrent exec on an alias would prematurely \
                 restore the shared DACL"
            );
        }
        if refuse_escalation
            && let Some(m) = on_disk_mask
            && eff != m
        {
            let others = self.other_holders(canon)?;
            if others > 0 {
                bail!(
                    "per-exec deny would escalate '{canon}' from \
                     {m:?} to {eff:?} while held by {others} other \
                     broker(s); refusing (the per-exec restore \
                     cannot de-escalate a still-held file, so the \
                     stricter mask would persist past this exec)"
                );
            }
        }

        // 4. Record-first upsert (fence bit defaults to 1; step 7
        //    reconciles).
        self.upsert_snapshot(
            canon,
            original_sd.as_ref(),
            &cur_id,
            parent.as_deref(),
            is_dir,
        )?;

        // 5. Converge the target.
        let action = if on_disk_mask == Some(eff) {
            StampAction::AlreadyStamped
        } else {
            acl::stamp_target_apply(canon, dacls, eff, is_dir, &marker)
                .with_context(|| format!("stamp '{canon}' ({eff:?}, marker)"))?;
            if on_disk_mask.is_some() {
                StampAction::ReStamped
            } else {
                StampAction::Fresh
            }
        };

        // 6. Converge the parent (same-user model). The
        //    separate-user model never reaches here — it goes
        //    through `apply_aces` (DENY ACE on the file +
        //    `(D;OICI;FDC)` on the parent) instead of the PROTECTED
        //    rewrite.
        let pstate = self.ensure_parent_stamped(parent.as_deref(), dacls)?;

        // 7. Fence bit = links≠1 (alternate names may be under
        //    unstamped parents) OR parent unstampable. Directory
        //    NumberOfLinks counts subdirs (`.` + `..`), not
        //    hardlinks (NTFS doesn't support dir hardlinks), so
        //    dirs never trip the multi-link route.
        let multi_link = !is_dir && links != 1;
        if multi_link {
            eprintln!(
                "srt-win: '{canon}' has {links} hardlink(s); routing \
                 to per-exec fence (alternate names may be in \
                 unstamped dirs)"
            );
        }
        let needs_fence = multi_link || pstate == ParentState::Unstampable;
        self.conn
            .prepare_cached(
                "UPDATE acl_snapshots SET parent_stamp_failed = ?2 \
                 WHERE canonical_path = ?1",
            )?
            .execute(params![canon, needs_fence as i64])
            .context("UPDATE parent_stamp_failed (self)")?;
        if pstate == ParentState::Unstampable
            && let Some(p) = parent.as_deref()
        {
            // Sibling fan-out is =1 only — never clears a sibling's
            // hardlink-forced bit.
            self.conn
                .prepare_cached(
                    "UPDATE acl_snapshots SET parent_stamp_failed = 1 \
                     WHERE parent_path = ?1",
                )?
                .execute(params![p])
                .context("UPDATE parent_stamp_failed (siblings)")?;
        }

        let holder_added = self.add_holder(canon)?;
        Ok(StampWitness {
            canon: canon.to_string(),
            effective_mask: eff,
            action,
            needs_handle_fence: needs_fence,
            original_lost,
            is_dir,
            holder_added,
            _sealed: (),
        })
    }

    /// Count holders of `canon` OTHER than `self.holder_pid`.
    fn other_holders(&self, canon: &str) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT count(*) FROM holders \
                 WHERE canonical_path = ?1 AND pid != ?2",
                params![canon, self.holder_pid.0 as i64],
                |r| r.get(0),
            )
            .context("count other holders")
    }

    /// Converge `parent` to the allow-list + marker. Disk-first;
    /// memoized per batch. Any failure (no `WRITE_DAC`, capture
    /// error, no parent) is `Unstampable` — never aborts the file
    /// stamp (the file's broker-only DACL already gives the content
    /// guarantee; the handle fence covers delete/rename).
    fn ensure_parent_stamped(
        &mut self,
        parent: Option<&str>,
        dacls: &PrebuiltDacls,
    ) -> Result<ParentState> {
        let Some(parent) = parent else {
            return Ok(ParentState::Unstampable);
        };
        if self.applied_parents.contains(parent) {
            return Ok(ParentState::Stamped);
        }
        // Capture error → Unstampable (fail-closed; never accept a
        // stale row when we can't read the live DACL).
        let (cur, cur_id) = match (acl::capture_sd(parent), path_id::capture_file_id(parent)) {
            (Ok(sd), Ok(id)) => (sd, id),
            (e_sd, e_id) => {
                eprintln!(
                    "srt-win: parent '{parent}': capture failed \
                     (sd={:?}, id={:?}); routing children to the \
                     per-exec handle fence",
                    e_sd.err(),
                    e_id.err()
                );
                return Ok(ParentState::Unstampable);
            }
        };
        let class = acl::classify_sd(&cur, &dacls.calib)?;
        let prior = self.get_parent_stamp(parent)?;
        let (original_sd, marker, already): (Option<CapturedSd>, MarkerHash, bool) = match class {
            StampClass::ParentAllowList(h) => match prior {
                Some(p) => match &p.original_sd {
                    Some(orig)
                        if p.file_id == Some(cur_id)
                            && acl::compute_marker_hash(orig, &cur_id) == h =>
                    {
                        (Some(orig.clone()), h, true)
                    }
                    // Row already records original_sd_lost (a prior
                    // session hit the prior=None branch). The on-disk
                    // marker is genuine (child can't write it) and
                    // file_id matches — accept; don't flip a stamped
                    // parent to Unstampable on the second session.
                    None if p.file_id == Some(cur_id) => (None, h, true),
                    _ => {
                        eprintln!(
                            "srt-win: parent '{parent}': row does not \
                             corroborate on-disk marker; routing to \
                             handle fence (fail-closed)"
                        );
                        return Ok(ParentState::Unstampable);
                    }
                },
                None => {
                    eprintln!(
                        "srt-win: parent '{parent}': stamped on disk but \
                         no DB row — original_sd_lost"
                    );
                    (None, h, true)
                }
            },
            // A dir-target stamp on the parent IS an FDC-removing
            // DACL (stricter than the allow-list — the user has no
            // FDC there at all), so a file under a stamped dir
            // needs no separate parent_stamps row.
            StampClass::DirTarget(_, _) => {
                self.applied_parents.insert(parent.to_string());
                return Ok(ParentState::Stamped);
            }
            // Any marker-bearing class on a DIRECTORY that isn't
            // ParentAllowList(_) is shape drift (a file-shape
            // DACL on a dir is something we never write). Same
            // fail-closed route as StampedUnrecognized.
            StampClass::StampedUnrecognized | StampClass::File(_, _) => {
                eprintln!(
                    "srt-win: parent '{parent}': broker-stamp derivative \
                     (stamped_unrecognized); routing children to handle \
                     fence (fail-closed)"
                );
                return Ok(ParentState::Unstampable);
            }
            StampClass::Unstamped => {
                let h = acl::compute_marker_hash(&cur, &cur_id);
                (Some(cur), h, false)
            }
        };
        self.conn
            .prepare_cached(
                "INSERT INTO parent_stamps \
                 (canonical_parent_path, original_sd, file_id) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(canonical_parent_path) DO UPDATE SET \
                   original_sd = excluded.original_sd, \
                   file_id     = excluded.file_id",
            )?
            .execute(params![
                parent,
                original_sd.as_ref().map(CapturedSd::as_bytes),
                cur_id.as_bytes().as_slice(),
            ])
            .context("UPSERT parent_stamps")?;
        if !already && let Err(e) = acl::apply_parent_allow_list(parent, dacls, &marker) {
            eprintln!(
                "srt-win: parent '{parent}': apply allow-list failed \
                 ({e:#}); routing children to handle fence"
            );
            // Roll back so the next batch retries (and restore
            // doesn't write back an SD that was never replaced).
            self.conn
                .execute(
                    "DELETE FROM parent_stamps \
                     WHERE canonical_parent_path = ?1",
                    params![parent],
                )
                .context("DELETE parent_stamps (rollback)")?;
            return Ok(ParentState::Unstampable);
        }
        self.applied_parents.insert(parent.to_string());
        Ok(ParentState::Stamped)
    }

    /// Insert (or refresh) the holder's `brokers` row. The stored
    /// `process_create_time` is the HOLDER's, so crash-recovery
    /// checks whether the holder — not this short-lived CLI — is
    /// still alive.
    ///
    /// UPSERT, not `INSERT OR REPLACE`: with `foreign_keys=ON` and
    /// `holders.pid REFERENCES brokers ON DELETE CASCADE`, REPLACE is
    /// a DELETE (cascading away every holder row for this pid) plus a
    /// fresh INSERT — so a holder's *second* `acl stamp` would
    /// silently drop its first stamp's holds, and the next
    /// crash-recovery would restore those files while the holder's
    /// child is still running. `ON CONFLICT DO UPDATE` updates in
    /// place and leaves child rows intact.
    pub fn register_broker(&self) -> Result<()> {
        let ct = pid_create_time(self.holder_pid.0)
            .with_context(|| format!("read create-time of holder pid {}", self.holder_pid.0))?;
        let now = unix_now();
        self.conn
            .execute(
                "INSERT INTO brokers (pid, process_create_time, started_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(pid) DO UPDATE SET \
                   process_create_time = excluded.process_create_time, \
                   started_at          = excluded.started_at",
                params![self.holder_pid.0 as i64, ct, now],
            )
            .context("INSERT brokers")?;
        Ok(())
    }

    /// Remove the holder's `brokers` row. CASCADE drops its
    /// `holders` rows.
    pub fn unregister_broker(&self) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM brokers WHERE pid = ?1",
                params![self.holder_pid.0 as i64],
            )
            .context("DELETE brokers")?;
        Ok(())
    }

    /// Record the holder against `canonical_path`. Idempotent
    /// (`INSERT OR IGNORE`); returns whether a new row was
    /// inserted (`false` = this holder already held it from a
    /// prior batch). Module-private: a holder row is only valid
    /// as the last step of [`ensure_stamped`].
    fn add_holder(&self, canonical_path: &str) -> Result<bool> {
        let n = self
            .conn
            .prepare_cached(
                "INSERT OR IGNORE INTO holders (canonical_path, pid) \
                 VALUES (?1, ?2)",
            )?
            .execute(params![canonical_path, self.holder_pid.0 as i64])
            .context("INSERT holders")?;
        Ok(n > 0)
    }

    /// Remove the holder from `canonical_path`. Returns `true` if the
    /// path's refcount has dropped to zero (caller should restore).
    /// Delete + recount run in one short tx so the returned count
    /// reflects the delete atomically (the mutex already excludes
    /// other writers, but this keeps the read consistent if the
    /// delete partially applied).
    pub fn remove_holder(&self, canonical_path: &str) -> Result<bool> {
        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin remove_holder tx")?;
        tx.execute(
            "DELETE FROM holders WHERE canonical_path = ?1 AND pid = ?2",
            params![canonical_path, self.holder_pid.0 as i64],
        )
        .context("DELETE holders (one)")?;
        let remaining: i64 = tx
            .query_row(
                "SELECT count(*) FROM holders WHERE canonical_path = ?1",
                params![canonical_path],
                |r| r.get(0),
            )
            .context("count remaining holders")?;
        tx.commit().context("commit remove_holder")?;
        Ok(remaining == 0)
    }

    /// All paths currently held by the holder.
    pub fn my_holds(&self) -> Result<Vec<String>> {
        query_holder_paths(&self.conn, self.holder_pid)
    }

    /// Look up a restore record. The row is a HINT — it never
    /// asserts on-disk state; corroborate against the marker.
    pub fn get_snapshot(&self, canonical_path: &str) -> Result<Option<Snapshot>> {
        self.conn
            .prepare_cached(SNAPSHOT_SELECT_BY_PATH)?
            .query_row(params![canonical_path], snapshot_from_row)
            .optional()
            .context("SELECT acl_snapshots")
    }

    fn upsert_snapshot(
        &self,
        canon: &str,
        original_sd: Option<&CapturedSd>,
        file_id: &path_id::FileId,
        parent_path: Option<&str>,
        is_dir: bool,
    ) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO acl_snapshots \
                 (canonical_path, original_sd, file_id, parent_path, \
                  parent_stamp_failed, is_dir) \
                 VALUES (?1, ?2, ?3, ?4, 1, ?5) \
                 ON CONFLICT(canonical_path) DO UPDATE SET \
                   original_sd         = excluded.original_sd, \
                   file_id             = excluded.file_id, \
                   parent_path         = excluded.parent_path, \
                   parent_stamp_failed = 1, \
                   is_dir              = excluded.is_dir",
            )?
            .execute(params![
                canon,
                original_sd.map(CapturedSd::as_bytes),
                file_id.as_bytes().as_slice(),
                parent_path,
                is_dir as i64,
            ])
            .context("UPSERT acl_snapshots")?;
        Ok(())
    }

    fn get_parent_stamp(&self, canonical_parent_path: &str) -> Result<Option<ParentStamp>> {
        self.conn
            .prepare_cached(
                "SELECT original_sd, file_id \
                 FROM parent_stamps WHERE canonical_parent_path = ?1",
            )?
            .query_row(params![canonical_parent_path], parent_stamp_from_row)
            .optional()
            .context("SELECT parent_stamps")
    }

    /// Restore-or-drop a zero-refcount snapshot. Shared by the
    /// `acl restore` arm and crash-recovery so the two cannot
    /// diverge in their case analysis (see [`try_restore_snapshot`]).
    pub fn try_restore(
        &self,
        snap: &Snapshot,
        dacls: &PrebuiltDacls,
        force: bool,
        parent_out: &mut Vec<(String, ParentRestoreOutcome)>,
    ) -> Result<RestoreOutcome> {
        try_restore_snapshot(&self.conn, snap, dacls, force, parent_out)
    }

    /// Stamp `targets` under `self.holder_pid`: register this
    /// holder, then [`Self::ensure_stamped`] each path. Per-path
    /// errors are logged and collected (the loop continues so
    /// every failure is reported); on ANY failure the holds added
    /// **by this call** are rolled back and
    /// `(witnesses, failed)` is returned — when `failed > 0` the
    /// witnesses are INFORMATIONAL (for the caller's per-category
    /// tally) and every newly-added hold has already been
    /// released. Never `Err` for per-path failures — only the
    /// up-front `register_broker` propagates — so the caller's
    /// `with_init_lock` always returns the crash-recovery report.
    ///
    /// Rollback is scoped to this batch's NEWLY-ADDED holds
    /// (`witness.holder_added`), NOT `my_holds()` and NOT every
    /// witness. The filter is only meaningful for `acl stamp`'s
    /// re-stamp case (`refuse_escalation=false`): a session host
    /// may already hold paths from a prior `acl stamp` under the
    /// SAME holder pid; a failed re-stamp must leave those intact
    /// (the (canon, pid) row is shared, no per-call refcount —
    /// dropping the filter would let a second batch that includes
    /// one bad path tear down the first batch's overlapping deny
    /// stamps). For per-exec `--deny-*`
    /// (`refuse_escalation=true`) the holder is the exec
    /// process's own PID with no prior batch, so every witness
    /// has `holder_added=true` and the filter is a no-op. After
    /// rollback, if the holder has no remaining holds the brokers
    /// row is dropped too — a per-exec stamp failure then leaves
    /// the DB exactly as it found it (no noisy dead-broker reap
    /// on the next op).
    ///
    /// Shared by `acl stamp` and per-exec `--deny-*` so the two
    /// cannot diverge in their stamp-or-rollback semantics.
    pub fn stamp_targets(
        &mut self,
        targets: &[(String, AclMask, bool)],
        dacls: &PrebuiltDacls,
        refuse_escalation: bool,
    ) -> Result<(Vec<StampWitness>, usize)> {
        self.register_broker()?;
        let mut witnesses = Vec::with_capacity(targets.len());
        let mut failed = 0usize;
        for (canon, mask, is_dir) in targets {
            // No per-arm policy: every path goes through the same
            // disk-first chokepoint. The sealed StampWitness makes
            // a "trust the row, skip the disk check" branch
            // unspellable.
            match self.ensure_stamped(canon, *mask, *is_dir, dacls, refuse_escalation) {
                Ok(w) => witnesses.push(w),
                Err(e) => {
                    eprintln!("srt-win: '{canon}': {e:#}");
                    failed += 1;
                }
            }
        }
        if failed > 0 {
            let mut parent_outs = Vec::new();
            let added: Vec<_> = witnesses.iter().filter(|w| w.holder_added).collect();
            let release_failed = added
                .iter()
                .filter(|w| {
                    matches!(
                        self.release_one(&w.canon, dacls, &mut parent_outs),
                        ReleaseOutcome::Failed,
                    )
                })
                .count();
            // The "{N} of {M} could not be stamped; rolled back"
            // line is the CALLER's to print (with `acl stamp` vs
            // per-exec context). This block only surfaces what
            // the caller cannot see: a rollback that did not
            // fully undo (release_one is catch-and-continue).
            if release_failed > 0 {
                eprintln!(
                    "srt-win: WARNING: rollback could not undo \
                     {release_failed} of this batch's {} \
                     newly-added hold(s); those file(s) stay \
                     stamped (fail-closed) until `acl recover`",
                    added.len(),
                );
            }
            if self.my_holds().map(|h| h.is_empty()).unwrap_or(false) {
                let _ = self.unregister_broker();
            }
            // Witnesses returned for the caller's per-category
            // tally ("9 newly stamped, …, 1 FAILED — rolled
            // back"); when `failed > 0` they are INFORMATIONAL
            // ONLY — every newly-added hold has already been
            // released above.
            return Ok((witnesses, failed));
        }
        Ok((witnesses, 0))
    }

    /// Release one hold of `self.holder_pid` on `canon`; if the
    /// refcount drops to zero, restore via [`Self::try_restore`].
    /// Per-path catch-and-continue: every failure is logged and
    /// fail-closed (file stays stamped); never returns `Err`.
    ///
    /// The single per-path release body — [`Self::restore_all`]
    /// loops it over `my_holds()`, [`Self::stamp_targets`]'s
    /// rollback loops it over this batch's witnesses. Callers
    /// count `Failed` themselves (no out-param plumbing).
    fn release_one(
        &self,
        canon: &str,
        dacls: &PrebuiltDacls,
        parent_outs: &mut Vec<(String, ParentRestoreOutcome)>,
    ) -> ReleaseOutcome {
        let now_zero = match self.remove_holder(canon) {
            Ok(z) => z,
            Err(e) => {
                eprintln!(
                    "srt-win: WARNING: remove_holder '{canon}': \
                     {e:#}; leaving stamped (fail-closed)"
                );
                return ReleaseOutcome::Failed;
            }
        };
        if !now_zero {
            // Another holder still has it — released our claim,
            // file stays stamped. Not reported (the LAST holder
            // to release does).
            return ReleaseOutcome::StillHeld;
        }
        let snap = match self.get_snapshot(canon) {
            Ok(Some(s)) => s,
            Ok(None) => {
                // Holder row already removed; with no snapshot
                // there is nothing to restore and nothing for
                // crash-recovery to reap. Warn-only — counting
                // this as `Failed` would make callers promise a
                // later reap that cannot happen.
                eprintln!(
                    "srt-win: WARNING: '{canon}' had a holder row \
                     but no snapshot — nothing to restore"
                );
                return ReleaseOutcome::NoSnapshot;
            }
            Err(e) => {
                eprintln!(
                    "srt-win: WARNING: get_snapshot '{canon}': \
                     {e:#}; leaving stamped (fail-closed)"
                );
                return ReleaseOutcome::Failed;
            }
        };
        match self.try_restore(&snap, dacls, false, parent_outs) {
            Ok(out) => ReleaseOutcome::Restored(snap, out),
            Err(e) => {
                eprintln!(
                    "srt-win: WARNING: restore '{}': {e:#}; \
                     leaving stamped (fail-closed)",
                    snap.canonical_path
                );
                ReleaseOutcome::Failed
            }
        }
    }

    /// Release every hold of `self.holder_pid` (via
    /// [`Self::release_one`] over `my_holds()`) and unregister the
    /// broker. Per-path catch-and-continue. Only the up-front
    /// `my_holds` / final `unregister_broker` errors propagate.
    ///
    /// Shared by `acl restore` and per-exec `--deny-*` teardown.
    pub fn restore_all(&self, dacls: &PrebuiltDacls) -> Result<RestoreAllOutcomes> {
        let holds = self.my_holds()?;
        let mut entries = Vec::new();
        let mut parent_outs = Vec::new();
        let mut failed = 0usize;
        for canon in &holds {
            match self.release_one(canon, dacls, &mut parent_outs) {
                ReleaseOutcome::Restored(s, o) => entries.push((s, o)),
                ReleaseOutcome::Failed => failed += 1,
                ReleaseOutcome::StillHeld | ReleaseOutcome::NoSnapshot => {}
            }
        }
        self.unregister_broker()?;
        Ok(RestoreAllOutcomes {
            entries,
            parent_outs,
            failed,
        })
    }

    /// `register_broker` → run `f` → on `failed > 0` roll back this
    /// batch's newly-added holder rows (via `release_one_ace`) and
    /// drop the brokers row if the holder is now empty. Shared by
    /// [`Self::apply_aces`] and the per-exec deny path so the two
    /// cannot diverge in their stamp-or-rollback semantics. Only the
    /// up-front `register_broker` propagates.
    fn with_broker_registration(
        &self,
        sandbox_sid: &str,
        f: impl FnOnce(&Self) -> Result<(Vec<AceWitness>, usize)>,
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.register_broker()?;
        let (witnesses, failed) = f(self)?;
        if failed > 0 {
            for w in witnesses.iter().filter(|w| w.holder_added) {
                if let Err(e) = self.release_one_ace(&w.canon, w.ace.kind(), sandbox_sid) {
                    eprintln!(
                        "srt-win: WARNING: rollback {} '{}': {e:#}; \
                         ACE left in place",
                        w.ace.kind(),
                        w.canon
                    );
                }
            }
            if self
                .my_ace_holds(None)
                .map(|h| h.is_empty())
                .unwrap_or(false)
                && self.my_holds().map(|h| h.is_empty()).unwrap_or(false)
            {
                let _ = self.unregister_broker();
            }
        }
        Ok((witnesses, failed))
    }

    /// Apply additive sandbox-user ACEs on each `(canon, ace)` and
    /// record `self.holder_pid` as a holder. Refcounted: a path
    /// already held by another holder gets its on-disk ACE
    /// re-converged (idempotent) and a holder row added; release
    /// recomputes the effective mask from the remaining holders.
    ///
    /// `Deny` targets implicitly add a `(parent, DenyFdc)` entry so
    /// the sandbox user cannot `del`/`ren` the file via parent-FDC
    /// even when the parent carries an inherited
    /// `BUILTIN\Users:(F)`. Multiple denied siblings under one
    /// parent share the parent's `deny_fdc` row (PK
    /// `(path, kind, pid)` dedupes within one holder; refcount
    /// handles cross-holder).
    ///
    /// All-or-nothing per batch (via [`Self::with_broker_registration`]).
    pub fn apply_aces(
        &self,
        sandbox_sid: &str,
        targets: &[(String, SbAce)],
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.with_broker_registration(sandbox_sid, |db| {
            let mut witnesses = Vec::with_capacity(targets.len());
            let mut failed = 0usize;
            let mut one = |canon: &str, ace: SbAce| match db.ensure_ace(canon, ace, sandbox_sid) {
                Ok(w) => witnesses.push(w),
                Err(e) => {
                    eprintln!("srt-win: {} '{canon}': {e:#}", ace.kind());
                    failed += 1;
                }
            };
            for (canon, ace) in targets {
                one(canon, *ace);
                if matches!(ace, SbAce::Deny(_))
                    && let Some(p) = path_id::canonical_parent_of(canon)
                {
                    one(&p, SbAce::DenyFdc);
                }
            }
            Ok((witnesses, failed))
        })
    }

    /// Disk-first single-ACE converge. Record-first upsert (holder
    /// row plus `working_aces` row) then [`recompose_at`] so a
    /// crash between leaves a row whose ACE hasn't been written —
    /// the next call re-derives and reapplies.
    fn ensure_ace(&self, canon: &str, want: SbAce, sandbox_sid: &str) -> Result<AceWitness> {
        let cur_id = path_id::capture_file_id(canon)
            .with_context(|| format!("capture file_id '{canon}'"))?;
        let prior: Option<Vec<u8>> = self
            .conn
            .prepare_cached(
                "SELECT file_id FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
            )?
            .query_row(params![canon, want.kind()], |r| r.get(0))
            .optional()
            .context("SELECT working_aces")?;
        if let Some(fid) = &prior
            && path_id::FileId::from_bytes(fid)? != cur_id
        {
            bail!(
                "'{canon}': file_id changed since prior {} — path \
                 was substituted (refusing)",
                want.kind()
            );
        }
        // Holder row first (`want_mask` is THIS holder's request,
        // independent of what other holders want — `effective_ace`
        // computes the MAX). REPLACE so a re-apply at a different
        // mask updates this holder's want.
        let holder_added = self
            .conn
            .prepare_cached(
                "INSERT INTO ace_holders \
                 (canonical_path, kind, pid, want_mask) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(canonical_path, kind, pid) \
                 DO UPDATE SET want_mask = excluded.want_mask",
            )?
            .execute(params![
                canon,
                want.kind(),
                self.holder_pid.0 as i64,
                want.as_str()
            ])
            .context("UPSERT ace_holders")?
            > 0
            && prior.is_none();
        let eff = self.effective_ace(canon, want.kind())?.unwrap_or(want);
        self.conn
            .prepare_cached(
                "INSERT INTO working_aces \
                 (canonical_path, kind, file_id, mask) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(canonical_path, kind) DO UPDATE SET \
                   file_id = excluded.file_id, \
                   mask    = excluded.mask",
            )?
            .execute(params![
                canon,
                want.kind(),
                cur_id.as_bytes().as_slice(),
                eff.as_str()
            ])
            .context("UPSERT working_aces")?;
        recompose_at(&self.conn, canon, sandbox_sid)?;
        Ok(AceWitness {
            canon: canon.to_string(),
            ace: eff,
            already: prior.is_some(),
            holder_added,
            _sealed: (),
        })
    }

    /// `MAX(want_mask)` across live holders of `(canon, kind)`.
    fn effective_ace(&self, canon: &str, kind: &str) -> Result<Option<SbAce>> {
        let masks: Vec<String> = query_vec(
            &self.conn,
            "SELECT want_mask FROM ace_holders \
             WHERE canonical_path = ?1 AND kind = ?2",
            params![canon, kind],
            |r| r.get(0),
        )?;
        masks
            .iter()
            .map(|m| SbAce::parse(kind, m))
            .reduce(|a, b| Ok(a?.max(b?)))
            .transpose()
    }

    /// Release one `(canon, kind)` hold; recompute the effective ACE
    /// from the remaining holders (downgrade if this holder was the
    /// one that escalated it; revoke when zero remain).
    /// Identity-validated: if the path now resolves to a different
    /// `file_id`, the row is dropped and the ACE on the foreign
    /// object is NOT touched — except for `Grant`, where we
    /// best-effort `locate_by_file_id` and revoke at the moved path
    /// so the sandbox user does not keep stale access.
    fn release_one_ace(&self, canon: &str, kind: &str, sandbox_sid: &str) -> Result<AceRelease> {
        self.conn
            .prepare_cached(
                "DELETE FROM ace_holders WHERE canonical_path = ?1 \
                 AND kind = ?2 AND pid = ?3",
            )?
            .execute(params![canon, kind, self.holder_pid.0 as i64])
            .context("DELETE ace_holders (self)")?;
        let row: Option<(Vec<u8>, String)> = self
            .conn
            .prepare_cached(
                "SELECT file_id, mask FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
            )?
            .query_row(params![canon, kind], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let Some((fid, stored)) = row else {
            return Ok(AceRelease::NoRow);
        };
        let new_eff = self.effective_ace(canon, kind)?;
        // Row update first (record-first), then converge disk.
        match new_eff {
            Some(e) => self
                .conn
                .execute(
                    "UPDATE working_aces SET mask = ?3 \
                     WHERE canonical_path = ?1 AND kind = ?2",
                    params![canon, kind, e.as_str()],
                )
                .context("UPDATE working_aces (downgrade)")?,
            None => self
                .conn
                .execute(
                    "DELETE FROM working_aces \
                     WHERE canonical_path = ?1 AND kind = ?2",
                    params![canon, kind],
                )
                .context("DELETE working_aces")?,
        };
        let want_id = path_id::FileId::from_bytes(&fid)?;
        match identity_gate(canon, want_id) {
            IdGate::Match => {
                recompose_at(&self.conn, canon, sandbox_sid)?;
                Ok(match new_eff {
                    Some(e) if e.as_str() == stored => AceRelease::StillHeld,
                    Some(_) => AceRelease::Downgraded,
                    None => AceRelease::Revoked,
                })
            }
            IdGate::Mismatch if kind == "grant" => {
                // The granted object moved. The ALLOW ACE travels
                // with the inode → the sandbox user still has
                // access at the new path. Chase by file_id and
                // revoke there (then re-converge if the new path
                // happens to be tracked too). DENY/FDC are left in
                // place on the moved inode (fail-closed).
                Ok(match path_id::locate_by_file_id(&want_id) {
                    Some(at) => {
                        eprintln!(
                            "srt-win: grant '{canon}': file_id moved \
                             to '{at}'; revoking there"
                        );
                        recompose_at(&self.conn, &at, sandbox_sid)?;
                        AceRelease::Relocated { moved_to: at }
                    }
                    None => {
                        eprintln!(
                            "srt-win: grant '{canon}': file_id not \
                             found on volume; dropping row"
                        );
                        AceRelease::Missing
                    }
                })
            }
            IdGate::Mismatch => {
                eprintln!(
                    "srt-win: {kind} '{canon}': file_id mismatch — \
                     path substituted; not touching ACE on the \
                     foreign object (fail-closed)"
                );
                Ok(AceRelease::Mismatch)
            }
            IdGate::Unreadable => {
                eprintln!(
                    "srt-win: {kind} '{canon}': open failed; \
                     dropping row"
                );
                Ok(AceRelease::Missing)
            }
        }
    }

    /// `(canon, kind)` rows held by this holder, optionally filtered
    /// to one set of kinds.
    fn my_ace_holds(&self, kinds: Option<&[&str]>) -> Result<Vec<(String, String)>> {
        let all: Vec<(String, String)> = query_vec(
            &self.conn,
            "SELECT canonical_path, kind FROM ace_holders \
             WHERE pid = ?1",
            params![self.holder_pid.0 as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(all
            .into_iter()
            .filter(|(_, k)| kinds.is_none_or(|ks| ks.contains(&k.as_str())))
            .collect())
    }

    /// Release every ACE hold of `self.holder_pid` for the given
    /// `kinds` (`["grant"]` for `acl revoke`;
    /// `["deny","deny_fdc"]` for `acl restore --sandbox-user-sid`)
    /// and unregister if no holds of any kind remain. Per-path
    /// catch-and-continue.
    pub fn release_aces(
        &self,
        sandbox_sid: &str,
        kinds: &[&str],
    ) -> Result<(Vec<(String, AceRelease)>, usize)> {
        let holds = self.my_ace_holds(Some(kinds))?;
        let mut out = Vec::with_capacity(holds.len());
        let mut failed = 0usize;
        for (canon, kind) in &holds {
            match self.release_one_ace(canon, kind, sandbox_sid) {
                Ok(r) => out.push((canon.clone(), r)),
                Err(e) => {
                    eprintln!(
                        "srt-win: WARNING: release {kind} '{canon}': \
                         {e:#}; ACE left in place"
                    );
                    failed += 1;
                }
            }
        }
        if self
            .my_ace_holds(None)
            .map(|h| h.is_empty())
            .unwrap_or(false)
            && self.my_holds().map(|h| h.is_empty()).unwrap_or(false)
        {
            self.unregister_broker()?;
        }
        Ok((out, failed))
    }
}

/// Read all `working_aces` rows for `canon` and converge the on-disk
/// ACEs for `sandbox_sid` to exactly that set. The single chokepoint
/// for sandbox-user ACE state — every add/drop/crash-recover routes
/// here so a path with both a grant AND a deny (or a parent that is
/// both granted and `deny_fdc`'d) is handled consistently.
fn recompose_at(conn: &Connection, canon: &str, sandbox_sid: &str) -> Result<()> {
    let rows: Vec<(String, String)> = query_vec(
        conn,
        "SELECT kind, mask FROM working_aces \
         WHERE canonical_path = ?1",
        params![canon],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut set = acl::SbAceSet::default();
    for (k, m) in &rows {
        match SbAce::parse(k, m)? {
            SbAce::Grant(g) => set.grant = Some(g),
            SbAce::Deny(d) => set.deny = Some(d),
            SbAce::DenyFdc => set.deny_fdc = true,
        }
    }
    acl::apply_sandbox_aces(canon, sandbox_sid, set)
        .with_context(|| format!("recompose '{canon}' ({set:?})"))
}

/// Sealed proof that [`Locked::apply_aces`] converged `canon` to
/// carry `ace` for the sandbox user.
#[must_use]
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug)]
pub struct AceWitness {
    pub canon: String,
    pub ace: SbAce,
    /// A row already existed (another holder, or a re-apply).
    pub already: bool,
    pub holder_added: bool,
    _sealed: (),
}

/// Per-path outcome of [`Locked::release_aces`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AceRelease {
    /// ACE removed (last holder); row deleted.
    Revoked,
    /// Other holders remain at the SAME effective mask; ACE
    /// untouched.
    StillHeld,
    /// Other holders remain at a NARROWER mask; ACE re-applied at
    /// the new MAX(want_mask).
    Downgraded,
    /// `file_id` mismatch; for `grant` the ACE was revoked at the
    /// relocated path. Row deleted.
    Relocated { moved_to: String },
    /// `file_id` mismatch — row deleted, ACE on the foreign object
    /// not touched.
    Mismatch,
    /// Path no longer opens — row deleted.
    Missing,
    /// Holder row removed but no `working_aces` row found.
    NoRow,
}

impl AceRelease {
    pub fn as_str(&self) -> &'static str {
        match self {
            AceRelease::Revoked => "revoked",
            AceRelease::StillHeld => "stillHeld",
            AceRelease::Downgraded => "downgraded",
            AceRelease::Relocated { .. } => "relocated",
            AceRelease::Mismatch => "mismatch",
            AceRelease::Missing => "missing",
            AceRelease::NoRow => "noRow",
        }
    }
}

/// Per-path result of [`Locked::release_one`]. `Failed` means the
/// file was left stamped (fail-closed) and a WARNING was logged;
/// callers count it. `NoSnapshot` is warn-only (holder row already
/// removed, nothing left to reap).
enum ReleaseOutcome {
    Restored(Snapshot, RestoreOutcome),
    StillHeld,
    NoSnapshot,
    Failed,
}

const SNAPSHOT_SELECT_BY_PATH: &str = "SELECT canonical_path, original_sd, file_id, parent_path, is_dir \
     FROM acl_snapshots WHERE canonical_path = ?1";

fn snapshot_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Snapshot> {
    Ok(Snapshot {
        canonical_path: r.get(0)?,
        original_sd: r.get::<_, Option<Vec<u8>>>(1)?.map(CapturedSd::from),
        file_id: path_id::FileId::from_bytes(&r.get::<_, Vec<u8>>(2)?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Blob, e.into())
        })?,
        parent_path: r.get(3)?,
        is_dir: r.get::<_, i64>(4)? != 0,
    })
}

/// Prune dead brokers and restore any snapshots they orphaned.
/// `force` overrides the restore ladder's fail-closed gates
/// (writes `original_sd` back even when `classify_sd` does not
/// recognise the on-disk SD as our stamp).
///
/// Per-path commit: the dead-broker prune is one short tx (pure DB,
/// CASCADE); then each orphan's (restore_sd FS mutation + snapshot
/// row delete) is committed independently, so a failure restoring
/// path Y leaves path X's restore+delete durable.
fn crash_recovery(
    conn: &Connection,
    dacls: Option<&PrebuiltDacls>,
    force: bool,
) -> Result<RecoveryReport> {
    let mut report = RecoveryReport::default();

    // 1. Find dead brokers.
    let dead: Vec<i64> = query_vec(
        conn,
        "SELECT pid, process_create_time FROM brokers",
        [],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    )?
    .into_iter()
    .filter(|&(pid, ct)| !is_process_alive(pid as u32, ct))
    .map(|(pid, _)| pid)
    .collect();
    // 2. Delete dead brokers in one short tx; CASCADE drops their
    //    holder rows. (No-op if none — but still cheap.)
    if !dead.is_empty() {
        report.dead_brokers = dead.len() as u32;
        let tx = conn
            .unchecked_transaction()
            .context("begin prune-dead tx")?;
        for pid_i in &dead {
            tx.execute("DELETE FROM brokers WHERE pid = ?1", params![pid_i])
                .context("DELETE dead broker")?;
        }
        tx.commit().context("commit prune-dead")?;
    }
    // Even with no dead brokers there can be orphaned snapshots
    // (a broker that unregistered but crashed before restoring), so
    // always run step 3.

    // 3a. Orphaned sandbox-user ACEs: any working_aces row with
    //     zero ace_holders is one whose holder died (CASCADE
    //     dropped the holder row above). Re-converge the path —
    //     `recompose_at` reads the (possibly remaining) rows and
    //     applies exactly that, so a path with one orphaned kind
    //     and one still-held kind keeps the held one. Sandbox SID
    //     comes from `read_setup_info` — when no sandbox user is
    //     provisioned, there are no `working_aces` rows to orphan.
    if let Some(sb) = read_setup_info(conn)?.map(|s| s.sandbox_user_sid) {
        let orphan_aces: Vec<(String, String, Vec<u8>)> = query_vec(
            conn,
            "SELECT g.canonical_path, g.kind, g.file_id \
             FROM working_aces g \
             LEFT JOIN ace_holders h \
               ON h.canonical_path = g.canonical_path \
              AND h.kind = g.kind \
             WHERE h.canonical_path IS NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        for (canon, kind, fid) in orphan_aces {
            conn.execute(
                "DELETE FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
                params![&canon, &kind],
            )
            .context("DELETE working_aces (orphan)")?;
            let want = path_id::FileId::from_bytes(&fid)?;
            match identity_gate(&canon, want) {
                IdGate::Match => {
                    if let Err(e) = recompose_at(conn, &canon, &sb) {
                        eprintln!(
                            "srt-win: orphaned {kind} '{canon}': \
                             recompose failed ({e:#})"
                        );
                        continue;
                    }
                }
                IdGate::Mismatch if kind == "grant" => {
                    if let Some(at) = path_id::locate_by_file_id(&want) {
                        let _ = recompose_at(conn, &at, &sb);
                    }
                }
                _ => {} // gone/substituted — nothing on disk to do
            }
            report.aces_revoked += 1;
        }
    }

    // 3. Any snapshot with zero holders is orphaned → restore, each
    //    path committed independently. Restore needs the
    //    calibration to classify the on-disk DACL; without it
    //    (e.g. an `acl stamp` that didn't pass one — never happens
    //    today) we leave orphans for the next pass.
    let Some(dacls) = dacls else {
        return Ok(report);
    };
    let orphans: Vec<Snapshot> = query_vec(
        conn,
        "SELECT s.canonical_path, s.original_sd, s.file_id, \
                s.parent_path, s.is_dir \
         FROM acl_snapshots s \
         LEFT JOIN holders h ON h.canonical_path = s.canonical_path \
         WHERE h.canonical_path IS NULL",
        [],
        snapshot_from_row,
    )?;
    for snap in orphans {
        // Each path is processed independently; a failure on
        // one does not abort the batch (the host raises after
        // reading the full structured result, never mid-batch).
        let out = match try_restore_snapshot(conn, &snap, dacls, force, &mut report.parent_entries)
        {
            Ok(o) => o,
            Err(e) => {
                eprintln!(
                    "srt-win: '{}': restore failed at the DB layer \
                     ({e:#}); leaving snapshot row",
                    snap.canonical_path
                );
                RestoreOutcome::LeftUnreadable
            }
        };
        match &out {
            RestoreOutcome::Restored | RestoreOutcome::AlreadyOriginal => {
                report.restored += 1;
            }
            RestoreOutcome::Relocated { .. } => report.relocated += 1,
            RestoreOutcome::Missing => report.missing += 1,
            RestoreOutcome::LeftChanged
            | RestoreOutcome::LeftUnreadable
            | RestoreOutcome::Tampered
            | RestoreOutcome::OriginalLost
            | RestoreOutcome::StampedUnrecognized => {
                report.left_changed += 1;
            }
        }
        report.entries.push((snap, out));
    }

    // 4. Parent-orphan scan: any `parent_stamps` row with no
    //    remaining child snapshot is one whose `restore_sd` failed
    //    on a previous pass (the row was kept "for a later
    //    attempt"). Retry now. This is the only place the retry
    //    happens — without it a stuck parent would only be
    //    reattempted when a NEW file in that directory is
    //    stamped+restored.
    let parent_orphans: Vec<String> = query_vec(
        conn,
        "SELECT p.canonical_parent_path \
         FROM parent_stamps p \
         WHERE NOT EXISTS (SELECT 1 FROM acl_snapshots s \
                           WHERE s.parent_path = p.canonical_parent_path)",
        [],
        |r| r.get(0),
    )?;
    for parent in parent_orphans {
        match try_restore_parent_validated(conn, &parent, dacls, force)? {
            Some(
                out @ (ParentRestoreOutcome::Restored | ParentRestoreOutcome::AlreadyOriginal),
            ) => {
                report.parents_restored += 1;
                report.parent_entries.push((parent, out));
            }
            Some(out) => {
                report.parents_left += 1;
                report.parent_entries.push((parent, out));
            }
            None => {} // row gone between scan and call — fine
        }
    }
    Ok(report)
}

/// What `try_restore_snapshot` did with one zero-refcount snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// Wrote `original_sd` back and deleted the row.
    Restored,
    /// File already at `original_sd`; dropped the stale row.
    AlreadyOriginal,
    /// `(path, file_id)` mismatch: the protected file is no longer
    /// at the recorded path (the path is gone or now resolves to a
    /// DIFFERENT inode), but it was found elsewhere on the volume
    /// by `file_id`. Row KEPT, stamp LEFT in place (fail-closed):
    /// the broker-only DACL travels with the inode, so the file
    /// stays read-denied wherever it was moved. We do NOT restore
    /// by inode — chasing the file by ID to remove its stamp would
    /// re-expose a relocated secret.
    Relocated { moved_to: String },
    /// `(path, file_id)` mismatch and the file could not be
    /// located by ID (deleted, or moved off-volume). Row KEPT
    /// (orphan tracking) — the host surfaces this for the user to
    /// resolve (move the file back, or admin-side reset).
    Missing,
    /// On-disk DACL is `Unstamped` and ≠ `original_sd` (third-party
    /// edit) and not `--force`; row kept, file left as-is.
    LeftChanged,
    /// Can't read the current SD (file exists, identity matches)
    /// — row kept (`--force` retries the write blind).
    LeftUnreadable,
    /// On-disk marker ≠ `SHA-256(row.original_sd || row.file_id)`.
    /// Possible DB poisoning; stamp LEFT (`--force` overrides).
    Tampered,
    /// `original_sd` is NULL (DB wiped). Stamp LEFT (`--force`
    /// drops the row).
    OriginalLost,
    /// Broker-stamp derivative on disk (marker stripped or shape
    /// drifted). Stamp LEFT (`--force` overrides).
    StampedUnrecognized,
}

/// Restore-or-drop one zero-refcount snapshot. Shared by
/// crash-recovery and the `acl restore` arm so the case analysis
/// cannot diverge.
///
/// **Identity-validated and path-anchored.** We restore ONLY when
/// `canonical_path` still resolves to the same `file_id` we
/// captured at stamp time. If the path is gone, or now points at
/// a different inode, the protected file was relocated or
/// substituted: leave the stamp (it travels with the inode, so
/// the data stays broker-only wherever it went), keep the row as
/// the anomaly record, and best-effort locate the moved file by
/// ID for reporting. We never restore by inode — chasing the file
/// by ID to remove its stamp would re-expose a relocated secret.
///
/// FS mutation FIRST, then delete the row, only on success: if
/// `restore_sd` fails we keep the row (recoverable); if the
/// row-delete fails after a successful restore, the next pass hits
/// Case A (cur == original) and drops the row then.
fn try_restore_snapshot(
    conn: &Connection,
    snap: &Snapshot,
    dacls: &PrebuiltDacls,
    force: bool,
    parent_out: &mut Vec<(String, ParentRestoreOutcome)>,
) -> Result<RestoreOutcome> {
    // Identity gate. Open the path and read its current
    // FILE_ID_INFO. path gone (ERROR_FILE/PATH_NOT_FOUND) →
    // mismatch; path → DIFFERENT file_id → mismatch; path → SAME
    // file_id → proceed to the SD case analysis. Any OTHER open
    // error is `LeftUnreadable` — row kept, retryable; NOT a
    // mismatch.
    //
    // On mismatch: row KEPT, stamp LEFT (fail-closed). Locate the
    // file by ID (reporting only; never to restore at).
    match identity_gate(&snap.canonical_path, snap.file_id) {
        IdGate::Match => {}
        IdGate::Unreadable => return Ok(RestoreOutcome::LeftUnreadable),
        IdGate::Mismatch => {
            return Ok(match path_id::locate_by_file_id(&snap.file_id) {
                Some(at) => {
                    eprintln!(
                        "srt-win: '{}': file_id mismatch — protected \
                         file is now at '{at}'; leaving stamp \
                         (fail-closed) and snapshot row",
                        snap.canonical_path
                    );
                    RestoreOutcome::Relocated { moved_to: at }
                }
                None => {
                    eprintln!(
                        "srt-win: '{}': file_id mismatch — protected \
                         file not found on volume; leaving snapshot \
                         row (fail-closed)",
                        snap.canonical_path
                    );
                    RestoreOutcome::Missing
                }
            });
        }
    }

    let v = verify_and_restore(
        &snap.canonical_path,
        snap.original_sd.as_ref(),
        snap.file_id,
        if snap.is_dir {
            RestoreKind::Dir
        } else {
            RestoreKind::File
        },
        &dacls.calib,
        force,
    )?;

    // Drop the snapshot row, then — if this was the LAST snapshot
    // pointing at the parent — restore the parent directory's
    // original DACL too.
    if v.row_done() {
        conn.execute(
            "DELETE FROM acl_snapshots WHERE canonical_path = ?1",
            params![snap.canonical_path],
        )
        .context("DELETE snapshot")?;
        if let Some(parent) = snap.parent_path.as_deref()
            && let Some(po) = try_restore_parent_validated(conn, parent, dacls, force)?
        {
            parent_out.push((parent.to_string(), po));
        }
    }
    Ok(match v {
        RestoreVerdict::Restored => RestoreOutcome::Restored,
        RestoreVerdict::AlreadyOriginal => RestoreOutcome::AlreadyOriginal,
        RestoreVerdict::LeftChanged => RestoreOutcome::LeftChanged,
        RestoreVerdict::LeftUnreadable | RestoreVerdict::RestoreFailed(_) => {
            RestoreOutcome::LeftUnreadable
        }
        RestoreVerdict::Tampered => RestoreOutcome::Tampered,
        RestoreVerdict::OriginalLost { .. } => RestoreOutcome::OriginalLost,
        RestoreVerdict::StampedUnrecognized => RestoreOutcome::StampedUnrecognized,
    })
}

/// Whether the file (`File`) or directory (`Parent`) restore
/// path is calling. `verify_and_restore` accepts the matching
/// [`StampClass`] as "ours" and routes the other shape to the
/// `Unstamped` arm.
#[derive(Copy, Clone, PartialEq, Eq)]
enum RestoreKind {
    File,
    Dir,
    Parent,
}

/// Shared disk-is-truth restore ladder: capture → classify →
/// corroborate against the on-disk marker → restore_sd. The hash
/// check happens BEFORE any `SetNamedSecurityInfoW` so a poisoned
/// `original_sd` is never written without `--force`. `--force` is
/// the explicit escape hatch (the user asserts "I trust the row")
/// and is the only CLI path to clear a `Tampered` /
/// `StampedUnrecognized` / `OriginalLost` orphan.
///
/// Lives in ONE place so a future tightening of the hash-verify
/// or `--force` semantics cannot land in the file path but not
/// the parent path.
#[derive(Debug)]
enum RestoreVerdict {
    /// `restore_sd` succeeded; row should be dropped.
    Restored,
    /// `cur == original_sd`; row should be dropped (no FS write).
    AlreadyOriginal,
    LeftChanged,
    LeftUnreadable,
    Tampered,
    /// Stamped on disk, `original_sd` is NULL. `force_dropped`
    /// when `--force` cleared the row anyway (so the user can
    /// `icacls /reset`).
    OriginalLost {
        force_dropped: bool,
    },
    StampedUnrecognized,
    RestoreFailed(String),
}

impl RestoreVerdict {
    /// True iff the caller should DELETE the row.
    fn row_done(&self) -> bool {
        matches!(
            self,
            Self::Restored
                | Self::AlreadyOriginal
                | Self::OriginalLost {
                    force_dropped: true
                }
        )
    }
}

fn verify_and_restore(
    path: &str,
    original_sd: Option<&CapturedSd>,
    file_id: path_id::FileId,
    kind: RestoreKind,
    calib: &acl::StampCalibration,
    force: bool,
) -> Result<RestoreVerdict> {
    let do_write = |orig: &CapturedSd| -> RestoreVerdict {
        match acl::restore_sd(path, orig) {
            Ok(()) => RestoreVerdict::Restored,
            Err(e) => {
                eprintln!(
                    "srt-win: '{path}': restore failed: {e:#}; \
                     leaving row"
                );
                RestoreVerdict::RestoreFailed(format!("{e:#}"))
            }
        }
    };
    // `--force` override: write `original_sd` back UNVERIFIED, or
    // (when there is none) drop the row so the user can `icacls
    // /reset`. Loud either way.
    let force_out = |what: &str| -> RestoreVerdict {
        match original_sd {
            Some(orig) => {
                eprintln!(
                    "srt-win: WARNING: '{path}': --force overriding \
                     {what}; writing recorded original_sd back \
                     UNVERIFIED"
                );
                do_write(orig)
            }
            None => {
                eprintln!(
                    "srt-win: '{path}': --force with no recorded \
                     original ({what}); dropping row (reset the \
                     DACL manually, e.g. `icacls /reset`)"
                );
                RestoreVerdict::OriginalLost {
                    force_dropped: true,
                }
            }
        }
    };

    let cur = match acl::capture_sd(path) {
        Ok(c) => c,
        Err(e) if force => {
            eprintln!(
                "srt-win: '{path}': cannot read current SD ({e:#}); \
                 --force → restoring anyway"
            );
            return Ok(force_out("LeftUnreadable"));
        }
        Err(e) => {
            eprintln!(
                "srt-win: '{path}': cannot read current SD ({e:#}); \
                 leaving row (use `acl recover --force`)"
            );
            return Ok(RestoreVerdict::LeftUnreadable);
        }
    };
    let class = acl::classify_sd(&cur, calib)?;

    // "Ours" = the stamp shape this caller writes; the OTHER
    // marker-bearing shape (parent shape on a file or vice
    // versa) is shape drift → StampedUnrecognized, same as
    // ensure_stamped — the marker can't be corroborated against
    // this row.
    enum Ours {
        Match(MarkerHash),
        CrossShape,
        Foreign,
    }
    let ours = match (kind, &class) {
        (RestoreKind::File, StampClass::File(_, h))
        | (RestoreKind::Dir, StampClass::DirTarget(_, h))
        | (RestoreKind::Parent, StampClass::ParentAllowList(h)) => Ours::Match(*h),
        (_, StampClass::Unstamped) => Ours::Foreign,
        // Any other (kind, on-disk-shape) pair is shape drift —
        // a marker-bearing DACL that this caller never writes.
        _ => Ours::CrossShape,
    };

    Ok(match ours {
        Ours::CrossShape => {
            if force {
                force_out("StampedUnrecognized")
            } else {
                eprintln!(
                    "srt-win: '{path}': broker-stamp derivative on \
                     disk (marker stripped or shape drifted); cannot \
                     verify original_sd — leaving stamped \
                     (fail-closed; `acl recover --force` to override)"
                );
                RestoreVerdict::StampedUnrecognized
            }
        }
        // No broker shape on disk → treat as third-party state.
        Ours::Foreign => match original_sd {
            Some(orig) if cur.equiv(orig) => RestoreVerdict::AlreadyOriginal,
            Some(orig) if force => do_write(orig),
            Some(_) => {
                eprintln!(
                    "srt-win: '{path}': DACL changed since stamp; \
                     leaving as-is (row kept; `acl recover --force` \
                     to override)"
                );
                RestoreVerdict::LeftChanged
            }
            None => RestoreVerdict::AlreadyOriginal,
        },
        // Our stamp shape on disk → corroborate row against marker.
        Ours::Match(h) => match original_sd {
            None if force => force_out("OriginalLost"),
            None => {
                eprintln!(
                    "srt-win: '{path}': original_sd was lost (DB \
                     wiped); leaving stamped (`acl recover --force` \
                     will drop the row so you can `icacls /reset`)"
                );
                RestoreVerdict::OriginalLost {
                    force_dropped: false,
                }
            }
            Some(orig) if acl::compute_marker_hash(orig, &file_id) != h => {
                if force {
                    force_out("Tampered")
                } else {
                    eprintln!(
                        "srt-win: '{path}': DB row's original_sd does \
                         NOT match the on-disk hash-ACE marker — \
                         possible DB poisoning; leaving stamped \
                         (fail-closed; `acl recover --force` will \
                         write it back UNVERIFIED)"
                    );
                    RestoreVerdict::Tampered
                }
            }
            Some(orig) => do_write(orig),
        },
    })
}

enum IdGate {
    Match,
    Mismatch,
    Unreadable,
}

/// `(path, file_id)` identity check. `path` gone
/// (ERROR_FILE/PATH_NOT_FOUND) or different inode → `Mismatch`;
/// any other open error → `Unreadable` (retryable, not a
/// mismatch).
fn identity_gate(path: &str, expect: path_id::FileId) -> IdGate {
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
    match path_id::capture_file_id(path) {
        Ok(cur) if cur == expect => IdGate::Match,
        Ok(_) => IdGate::Mismatch,
        Err(e) => {
            let code = e.downcast_ref::<windows::core::Error>().map(|we| we.code());
            let gone = matches!(
                code,
                Some(c) if c == ERROR_FILE_NOT_FOUND.into()
                        || c == ERROR_PATH_NOT_FOUND.into()
            );
            if gone {
                IdGate::Mismatch
            } else {
                eprintln!(
                    "srt-win: '{path}': cannot read file_id ({e:#}); \
                     leaving row (use `acl recover --force`)"
                );
                IdGate::Unreadable
            }
        }
    }
}

fn parent_stamp_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ParentStamp> {
    Ok(ParentStamp {
        original_sd: r.get::<_, Option<Vec<u8>>>(0)?.map(CapturedSd::from),
        file_id: r
            .get::<_, Option<Vec<u8>>>(1)?
            .as_deref()
            .map(path_id::FileId::from_bytes)
            .transpose()
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Blob, e.into())
            })?,
    })
}

/// Restore a parent directory's original DACL **iff** no
/// remaining snapshots point at it. Called after a snapshot row
/// is deleted, and from crash-recovery's parent-orphan scan.
///
/// Same fidelity guarantees as the FILE restore path
/// ([`try_restore_snapshot`]):
///   - identity gate via `file_id` — refuses to write onto a
///     recreated (different-inode) directory at the same path;
///   - cur-vs-stamped check — refuses to clobber a third-party
///     edit to the directory's DACL (unless `--force`);
///   - already-original fast path drops the stale row without
///     a write.
///
/// Best-effort: a failure here is logged and the `parent_stamps`
/// row is kept so a later pass can retry — we do NOT propagate
/// the error to the caller's restore (the file restore already
/// succeeded; failing the whole batch over a stuck parent would
/// block other paths). Returns `None` when the parent was never
/// stamped (`parent_stamp_failed` case) or already restored.
fn try_restore_parent_validated(
    conn: &Connection,
    parent: &str,
    dacls: &PrebuiltDacls,
    force: bool,
) -> Result<Option<ParentRestoreOutcome>> {
    let remaining: i64 = conn
        .query_row(
            "SELECT count(*) FROM acl_snapshots WHERE parent_path = ?1",
            params![parent],
            |r| r.get(0),
        )
        .context("count remaining children of parent")?;
    if remaining > 0 {
        return Ok(Some(ParentRestoreOutcome::StillHeld));
    }
    let Some(p) = conn
        .query_row(
            "SELECT original_sd, file_id \
             FROM parent_stamps WHERE canonical_parent_path = ?1",
            params![parent],
            parent_stamp_from_row,
        )
        .optional()
        .context("SELECT parent_stamps")?
    else {
        // No row — parent was never stamped (parent_stamp_failed
        // case) or already restored. Nothing to do.
        return Ok(None);
    };
    // Identity gate. A directory deleted+recreated at the same
    // path has a different file_id — do NOT write the saved SD
    // onto somebody else's new directory.
    let stored_id = match p.file_id {
        Some(id) => id,
        // Pre-file_id legacy row: identity gate and marker
        // corroboration both need it; fail closed.
        None => {
            return Ok(Some(ParentRestoreOutcome::Failed(
                "no recorded file_id".into(),
            )));
        }
    };
    match identity_gate(parent, stored_id) {
        IdGate::Match => {}
        IdGate::Mismatch => {
            eprintln!(
                "srt-win: parent restore '{parent}': file_id \
                 mismatch (directory was deleted and recreated); \
                 leaving as-is and keeping parent_stamps row"
            );
            return Ok(Some(ParentRestoreOutcome::Missing));
        }
        IdGate::Unreadable => {
            return Ok(Some(ParentRestoreOutcome::Failed("capture file_id".into())));
        }
    }

    let v = verify_and_restore(
        parent,
        p.original_sd.as_ref(),
        stored_id,
        RestoreKind::Parent,
        &dacls.calib,
        force,
    )?;
    // Drop the row only when the directory's DACL was actually
    // returned to a non-broker state. `OriginalLost` (even under
    // `--force`) leaves the dir broker-stamped on disk — keeping
    // the row preserves the only pointer the user has to which
    // directories still need a manual `icacls /reset`.
    if matches!(
        v,
        RestoreVerdict::Restored | RestoreVerdict::AlreadyOriginal
    ) {
        conn.execute(
            "DELETE FROM parent_stamps WHERE canonical_parent_path = ?1",
            params![parent],
        )
        .context("DELETE parent_stamps after restore")?;
    }
    Ok(Some(match v {
        RestoreVerdict::Restored => ParentRestoreOutcome::Restored,
        RestoreVerdict::AlreadyOriginal => ParentRestoreOutcome::AlreadyOriginal,
        RestoreVerdict::LeftChanged => ParentRestoreOutcome::LeftChanged,
        RestoreVerdict::LeftUnreadable => ParentRestoreOutcome::Failed("capture SD".into()),
        RestoreVerdict::Tampered => ParentRestoreOutcome::Failed("original_sd_tampered".into()),
        RestoreVerdict::OriginalLost { .. } => {
            ParentRestoreOutcome::Failed("original_sd_lost".into())
        }
        RestoreVerdict::StampedUnrecognized => {
            ParentRestoreOutcome::Failed("stamped_unrecognized".into())
        }
        RestoreVerdict::RestoreFailed(e) => ParentRestoreOutcome::Failed(e),
    }))
}

/// True if `pid` refers to a live process whose CreationTime
/// matches `expected_create_filetime`. PID-recycle guard.
fn is_process_alive(pid: u32, expected_create_filetime: i64) -> bool {
    if pid == std::process::id() {
        // Don't reap ourselves even if the stored CreationTime is
        // somehow stale.
        return true;
    }
    // SYNCHRONIZE so the WaitForSingleObject(0) signaled-check works.
    let h = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    } {
        Ok(h) if !h.is_invalid() => h,
        // A spurious `Ok` with an invalid handle is "uncertain" —
        // treat as ALIVE, matching the conservative stance below
        // (better to leave a stale row than reap a live broker and
        // restore a file it still holds).
        Ok(_) => return true,
        // Treat as DEAD only on ERROR_INVALID_PARAMETER (87) — the
        // "no such PID" signal. Every other error (ACCESS_DENIED,
        // transient low-memory, etc.) is uncertain → ALIVE, so we
        // never reap (and restore a file still used by) a holder
        // that's actually running.
        Err(e) => {
            return (e.code().0 as u32 & 0xFFFF) != 87;
        }
    };
    let h = crate::util::OwnedHandle(h);
    match process_create_time(h.raw()) {
        Ok(ct) => {
            ct == expected_create_filetime
                // An exited process whose handle is still held
                // elsewhere remains openable with the same
                // CreationTime — without this check it reads as
                // alive forever and is never reaped. Only
                // WAIT_OBJECT_0 (= signaled = exited) is "dead";
                // WAIT_TIMEOUT and WAIT_FAILED are both "alive"
                // (uncertain → ALIVE, matching the conservative
                // stance everywhere else in this function).
                && unsafe { WaitForSingleObject(h.raw(), 0) }
                    != WAIT_OBJECT_0
        }
        // Transient GetProcessTimes failure → uncertain → ALIVE,
        // matching the conservative stance everywhere else (better
        // a stale row than a live holder reaped and its files
        // restored under it).
        Err(_) => true,
    }
}

/// Creation FILETIME (as i64) of an arbitrary PID. Opens the
/// process for limited query; special-cases self to avoid needing
/// OpenProcess rights on our own token.
fn pid_create_time(pid: u32) -> Result<i64> {
    if pid == std::process::id() {
        return process_create_time(unsafe { GetCurrentProcess() });
    }
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .with_context(|| format!("OpenProcess({pid}) for create-time"))?;
    if h.is_invalid() {
        bail!("OpenProcess({pid}) returned invalid handle");
    }
    let h = crate::util::OwnedHandle(h);
    process_create_time(h.raw())
}

/// FILETIME (100-ns since 1601-01-01) → i64 for storage.
fn process_create_time(h: HANDLE) -> Result<i64> {
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user)
            .context("GetProcessTimes")?;
    }
    Ok(((create.dwHighDateTime as i64) << 32) | (create.dwLowDateTime as i64))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_rejects_empty_or_relative() {
        use std::ffi::OsString;
        // Unset or empty → error (var_os returns Some("") for a
        // present-but-empty var, which the old code accepted).
        assert!(state_dir_from(None).is_err());
        assert!(state_dir_from(Some(OsString::from(""))).is_err());
        // Relative → error (would put the broker-only-stamped DB
        // in CWD).
        assert!(state_dir_from(Some(OsString::from("rel"))).is_err());
        // Absolute → ok.
        let ok = state_dir_from(Some(OsString::from(r"C:\Users\u\AppData\Local")));
        assert_eq!(
            ok.unwrap(),
            PathBuf::from(r"C:\Users\u\AppData\Local\sandbox-runtime")
        );
    }

    /// Open an in-memory DB and run `f` against a `Locked` view
    /// (autocommit, like production). Skips the named mutex + dir
    /// stamp (those are integration-tested via smoke-acl.ps1).
    fn with_mem_db<R>(f: impl FnOnce(&mut Locked) -> R) -> R {
        let conn = open_db_at(std::path::Path::new(":memory:")).unwrap();
        let mut db = Locked {
            conn,
            holder_pid: HolderPid(std::process::id()),
            applied_parents: HashSet::new(),
        };
        f(&mut db)
    }

    #[test]
    fn schema_applies_in_memory() {
        let conn = open_db_at(std::path::Path::new(":memory:")).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' \
                 AND name IN ('brokers','holders','acl_snapshots')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn refcount_two_holders() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            db.add_holder(r"\\?\C:\f").unwrap();
            // Simulate a second broker by inserting directly.
            db.conn
                .execute(
                    "INSERT INTO brokers \
                     (pid, process_create_time, started_at) \
                     VALUES (999999, 1, 1)",
                    [],
                )
                .unwrap();
            db.conn
                .execute(
                    "INSERT INTO holders (canonical_path, pid) \
                     VALUES (?1, 999999)",
                    params![r"\\?\C:\f"],
                )
                .unwrap();
            // Removing OUR hold leaves the other → not zero.
            assert!(!db.remove_holder(r"\\?\C:\f").unwrap());
            // Drop the other broker (CASCADE removes its holder).
            db.conn
                .execute("DELETE FROM brokers WHERE pid = 999999", [])
                .unwrap();
            let n: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM holders WHERE canonical_path = ?1",
                    params![r"\\?\C:\f"],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 0);
        });
    }

    #[test]
    fn snapshot_round_trip() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            let id = path_id::FileId {
                volume_serial: 0xdead,
                id128: [7u8; 16],
            };
            db.upsert_snapshot(
                r"\\?\C:\f",
                Some(&vec![1, 2, 3].into()),
                &id,
                Some(r"\\?\C:\d"),
                false,
            )
            .unwrap();
            let got = db.get_snapshot(r"\\?\C:\f").unwrap().unwrap();
            assert_eq!(
                got.original_sd.as_ref().map(CapturedSd::as_bytes),
                Some(&[1, 2, 3][..])
            );
            assert_eq!(got.file_id, id);
            assert_eq!(got.parent_path.as_deref(), Some(r"\\?\C:\d"));
            // Upsert overwrites (record-first semantics).
            db.upsert_snapshot(r"\\?\C:\f", None, &id, Some(r"\\?\C:\d"), false)
                .unwrap();
            let got = db.get_snapshot(r"\\?\C:\f").unwrap().unwrap();
            assert!(got.original_sd.is_none());
        });
    }

    /// Regression for the security finding: `register_broker` is an
    /// UPSERT (`ON CONFLICT DO UPDATE`), NOT `INSERT OR REPLACE` —
    /// the latter would CASCADE-delete this holder's existing
    /// `holders` rows on a second stamp.
    #[test]
    fn second_register_broker_keeps_existing_holds() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            db.add_holder(r"\\?\C:\a").unwrap();
            db.add_holder(r"\\?\C:\b").unwrap();
            assert_eq!(db.my_holds().unwrap().len(), 2);
            // Second stamp by the same holder.
            db.register_broker().unwrap();
            // Holds intact (would be 0 with INSERT OR REPLACE).
            assert_eq!(db.my_holds().unwrap().len(), 2);
        });
    }

    #[test]
    fn crash_recovery_reaps_dead_broker_keeps_missing_orphan() {
        // Insert a dead broker + its holder + a snapshot for a path
        // that does NOT exist. Recovery prunes the dead broker
        // (CASCADE drops the holder); `try_restore_snapshot` then
        // hits the identity gate (path gone → file_id mismatch),
        // reports Missing, and KEEPS the row (fail-closed —
        // orphan tracking; the host surfaces it for the user to
        // resolve). The row is NOT silently reaped.
        with_mem_db(|db| {
            db.conn
                .execute(
                    "INSERT INTO brokers \
                     (pid, process_create_time, started_at) \
                     VALUES (999999, 1, 1)",
                    [],
                )
                .unwrap();
            db.conn
                .execute(
                    "INSERT INTO holders (canonical_path, pid) \
                     VALUES (?1, 999999)",
                    params![r"\\?\C:\srt-win-no-such-file"],
                )
                .unwrap();
            db.conn
                .execute(
                    "INSERT INTO acl_snapshots \
                     (canonical_path, original_sd, file_id, \
                      parent_path, parent_stamp_failed) \
                     VALUES (?1, x'01', ?2, NULL, 0)",
                    params![r"\\?\C:\srt-win-no-such-file", [0u8; 24].as_slice(),],
                )
                .unwrap();
            // PID 999999 with create_time 1 is dead.
            let dacls = PrebuiltDacls::build(
                acl::SID_BUILTIN_ADMINS,
                &crate::sid::current_user_sid().unwrap(),
            )
            .unwrap();
            let rep = crash_recovery(&db.conn, Some(&dacls), false).unwrap();
            assert_eq!(rep.dead_brokers, 1);
            // Path gone → identity-gate mismatch → Missing
            // (locate_by_file_id on an all-zero file_id finds
            // nothing). Row KEPT (fail-closed).
            assert_eq!(rep.restored, 0);
            assert_eq!(rep.missing, 1);
            assert_eq!(rep.relocated, 0);
            assert_eq!(rep.left_changed, 0);
            // CASCADE dropped the holder; broker row gone; snapshot
            // row STAYS (orphan record).
            let h: i64 = db
                .conn
                .query_row("SELECT count(*) FROM holders", [], |r| r.get(0))
                .unwrap();
            assert_eq!(h, 0);
            let s: i64 = db
                .conn
                .query_row("SELECT count(*) FROM acl_snapshots", [], |r| r.get(0))
                .unwrap();
            assert_eq!(s, 1, "missing-file orphan row must be kept");
        });
    }

    /// `fence_plan_on`'s filters: only paths whose
    /// `parent_stamp_failed = 1` are returned. (Tested in-memory
    /// against the same SQL, since the real function goes through
    /// `open_db_ro` on the production DB path.)
    #[test]
    fn fence_fallback_filter() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            let id = path_id::FileId {
                volume_serial: 0,
                id128: [0; 16],
            };
            for (p, failed) in [(r"\\?\C:\d\ok", 0i64), (r"\\?\C:\d\fail", 1)] {
                db.conn
                    .execute(
                        "INSERT INTO acl_snapshots \
                         (canonical_path, original_sd, file_id, \
                          parent_path, parent_stamp_failed) \
                         VALUES (?1, x'01', ?2, ?3, ?4)",
                        params![p, id.as_bytes().as_slice(), r"\\?\C:\d", failed],
                    )
                    .unwrap();
                db.add_holder(p).unwrap();
            }
            let plan = fence_plan_on(&db.conn, db.holder_pid).unwrap();
            assert_eq!(plan.fallback_files, vec![r"\\?\C:\d\fail".to_string()]);
            assert_eq!(plan.parents, vec![r"\\?\C:\d".to_string()]);
            // Sibling fan-out (=1 only): UPDATE WHERE parent_path.
            db.conn
                .execute(
                    "UPDATE acl_snapshots SET parent_stamp_failed = 1 \
                     WHERE parent_path = ?1",
                    params![r"\\?\C:\d"],
                )
                .unwrap();
            let plan = fence_plan_on(&db.conn, db.holder_pid).unwrap();
            assert_eq!(plan.fallback_files.len(), 2);
            assert!(plan.parents.is_empty());
        });
    }

    #[test]
    fn aliveness_self_is_alive() {
        let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
        assert!(is_process_alive(std::process::id(), ct));
        // Same PID, wrong create time would normally be "recycled →
        // dead", but we special-case ourselves.
        assert!(is_process_alive(std::process::id(), ct + 1));
    }

    #[test]
    fn aliveness_bogus_pid_is_dead() {
        // PID 0x7FFF_FFFE is well above any plausible live PID.
        assert!(!is_process_alive(0x7FFF_FFFE, 0));
    }
}
