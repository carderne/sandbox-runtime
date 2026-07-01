//! ACL stamping for filesystem deny — `srt-win acl stamp|restore|recover`.
//!
//! `denyRead` / `denyWrite` paths get their DACL replaced with the
//! broker-only pattern (same shape as `self_protect.rs` applies to
//! the broker process, but file-flavoured):
//!
//! | mask        | ACEs (PROTECTED, in order)                          |
//! |-------------|-----------------------------------------------------|
//! | `ReadDeny`  | `<group>` FILE_ALL · SYSTEM FILE_ALL ·              |
//! |             | Admins FILE_ALL · OWNER_RIGHTS READ_CONTROL         |
//! | `WriteDeny` | as above + Everyone FILE_GENERIC_READ\|EXECUTE       |
//!
//! The OWNER_RIGHTS ACE is load-bearing — without it the sandbox
//! child (running as the same user that owns the file) would walk
//! through the DACL via the kernel's implicit owner
//! `READ_CONTROL|WRITE_DAC` grant. (READ_CONTROL not 0:
//! `SetNamedSecurityInfoW` silently drops a mask-0 ACE — see
//! [`Allow::OWNER_RIGHTS`].)
//!
//! Stamping captures the file's original SD (DACL+Owner+Group,
//! self-relative) so `restore` can put it back exactly. If every
//! ACE in the original was inherited, restore goes back to
//! "no explicit DACL, inheritance on" rather than persisting the
//! inherited ACEs as explicit ones.
//!
//! Globs are **rejected**. Directory targets get the same
//! broker-only ACE list with `(OI)(CI)` so the stamp inherits to
//! the whole subtree (the marker ACE stays non-inheriting).

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACE_HEADER, ACE_REVISION, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    AclSizeInformation, AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorLength,
    InitializeAcl, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
};
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

use crate::path_id::FileId;
use crate::sid::LocalPsid;
use crate::util::{OwnedSd, local_free, pcwstr, win32_ok, wstr};

/// Owner-Rights well-known SID. ANY ACE for this SID replaces
/// the kernel's implicit `READ_CONTROL|WRITE_DAC` grant to the
/// owner with exactly the ACE's mask.
pub const SID_OWNER_RIGHTS: &str = "S-1-3-4";
pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";
pub const SID_EVERYONE: &str = "S-1-1-0";

// ─── DACL builder primitives ────────────────────────────────────────
// The policy functions below declare ACE lists as `&[Allow]`; this
// section turns them into a self-owning ACL buffer. `Mask`'s field
// is private and `Allow::OWNER_RIGHTS` takes no mask, so neither a
// hex-typo (`0x0130_01bf` for `0x0013_01bf`) nor a mask-`0`
// `OWNER_RIGHTS` ACE (which `SetNamedSecurityInfoW` drops on write
// — a silent sandbox escape) is spellable from policy code.

/// Access mask. Construct via the named consts and
/// [`Mask::with`]/[`Mask::without`]; the inner `u32` is private so
/// hex literals at call sites are not possible.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Mask(u32);

impl Mask {
    // Standard rights.
    pub const DELETE: Self = Self(0x0001_0000);
    pub const READ_CONTROL: Self = Self(0x0002_0000);
    pub const WRITE_DAC: Self = Self(0x0004_0000);
    pub const SYNCHRONIZE: Self = Self(0x0010_0000);

    // Generic — resolved via the object's GENERIC_MAPPING.
    pub const GENERIC_ALL: Self = Self(0x1000_0000);

    // File/dir-specific.
    pub const FILE_DELETE_CHILD: Self = Self(0x0000_0040);
    pub const FILE_ALL: Self = Self(FILE_ALL_ACCESS.0);
    pub const FILE_WRITE_ATTRIBUTES: Self = Self(0x0000_0100);
    pub const FILE_GENERIC_READ: Self = Self(FILE_GENERIC_READ.0);
    pub const FILE_GENERIC_WRITE: Self =
        Self(windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0);
    pub const FILE_GENERIC_EXECUTE: Self = Self(FILE_GENERIC_EXECUTE.0);

    /// `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE` — the WriteDeny
    /// stamp's Everyone allowance.
    pub const FILE_READ_EXEC: Self = Self::FILE_GENERIC_READ.with(Self::FILE_GENERIC_EXECUTE);

    /// `FileSystemRights.Modify` MINUS `FILE_DELETE_CHILD`. Granted
    /// to the user SID on a stamped parent directory so the
    /// sandboxed child (which shares the user SID with the broker)
    /// can still create/write/read/delete non-protected siblings
    /// (`DELETE` is in there) but cannot delete or rename-over a
    /// child of the directory via the parent's
    /// `FILE_DELETE_CHILD` — and the protected file's broker-only
    /// DACL withholds file-level `DELETE`, so the child has no
    /// path to delete/rename it. The broker keeps both via
    /// `<group>:FILE_ALL`.
    pub const MODIFY_NO_FDC: Self = Self::FILE_GENERIC_READ
        .with(Self::FILE_GENERIC_WRITE)
        .with(Self::FILE_GENERIC_EXECUTE)
        .with(Self::DELETE)
        .without(Self::FILE_DELETE_CHILD);

    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn with(self, m: Self) -> Self {
        Self(self.0 | m.0)
    }
    pub const fn without(self, m: Self) -> Self {
        Self(self.0 & !m.0)
    }
}

impl std::ops::BitOr for Mask {
    type Output = Self;
    fn bitor(self, r: Self) -> Self {
        self.with(r)
    }
}

/// `(OI)(CI)` inheritance for directory-target ACEs.
pub const OICI: ACE_FLAGS = ACE_FLAGS(CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0);
/// No inheritance — the ACE applies to the object itself only.
pub const NO_INHERIT: ACE_FLAGS = ACE_FLAGS(0);

/// One row in an `&[Allow]` ACE list — `(SID, mask, inherit-flags)`.
/// The SID is a string so the policy function reads as an
/// SDDL-style table; [`build_allow_dacl`] does the
/// `ConvertStringSidToSidW` parsing once.
#[derive(Copy, Clone)]
pub struct Allow<'a>(pub &'a str, pub Mask, pub ACE_FLAGS);

impl Allow<'static> {
    /// The only `OWNER_RIGHTS` ACE this crate emits. Mask is fixed
    /// at `READ_CONTROL` — suppresses owner-implicit `WRITE_DAC`
    /// (so an owner-child cannot rewrite the DACL) while still
    /// letting the owner read it. **The mask must be non-zero**:
    /// `SetNamedSecurityInfoW` silently drops a mask-0 ALLOW ACE on
    /// write, so the conceptually-purer `OWNER_RIGHTS:0` never
    /// reaches disk. With this const + `Mask`'s private field, the
    /// mask-0 mistake is unspellable from policy code.
    pub const OWNER_RIGHTS: Self = Allow(SID_OWNER_RIGHTS, Mask::READ_CONTROL, NO_INHERIT);
    /// As [`Allow::OWNER_RIGHTS`] but `(OI)(CI)`-inheriting.
    pub const OWNER_RIGHTS_OICI: Self = Allow(SID_OWNER_RIGHTS, Mask::READ_CONTROL, OICI);
}

/// Self-owning ACL: `buf` holds the `ACL` header + ACEs.
/// `AddAccessAllowedAceEx` copies SID bytes inline into each ACE
/// (`SidStart` embeds the SID — see the size calc in
/// [`rebuild_acl`]), so once built `buf` is self-contained.
pub struct BuiltAcl {
    buf: Vec<u8>,
}

impl BuiltAcl {
    pub fn as_ptr(&self) -> *const ACL {
        self.buf.as_ptr() as *const ACL
    }

    /// Wrap this ACL in an absolute-format SD with `SE_DACL_PROTECTED`
    /// set, plus a `SECURITY_ATTRIBUTES` borrowing it — for
    /// `CreateMutexExW` and similar object-creation APIs that take
    /// a `*const SECURITY_ATTRIBUTES`. The returned [`OwnedSa`] owns
    /// the ACL, the SD, and the SA; pass [`OwnedSa::as_ptr`] and
    /// keep the [`OwnedSa`] alive until the call returns.
    ///
    /// No `O:`/`G:` (owner/group): an explicit owner SID at object
    /// creation goes through `SeAssignSecurity`, which rejects any
    /// owner that isn't the caller's user / an `SE_GROUP_OWNER`
    /// group / a `SeRestorePrivilege`-enabled token
    /// (`ERROR_INVALID_OWNER`); leaving them unset defaults
    /// owner/group to the caller, which is what we want.
    pub fn into_security_attributes(self) -> Result<OwnedSa> {
        let mut sd: Box<SECURITY_DESCRIPTOR> = Box::default();
        let psd = PSECURITY_DESCRIPTOR(&mut *sd as *mut _ as *mut c_void);
        unsafe {
            InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION)
                .context("InitializeSecurityDescriptor")?;
            SetSecurityDescriptorDacl(psd, true, Some(self.as_ptr()), false)
                .context("SetSecurityDescriptorDacl")?;
            SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                .context("SetSecurityDescriptorControl(PROTECTED)")?;
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd.0,
            bInheritHandle: false.into(),
        };
        Ok(OwnedSa {
            _acl: self,
            _sd: sd,
            sa,
        })
    }
}

/// A `SECURITY_ATTRIBUTES` with its backing SD and ACL. Heap-pins
/// the SD via `Box` so `sa.lpSecurityDescriptor` stays valid across
/// moves of the [`OwnedSa`] itself. Do not `Clone`.
pub struct OwnedSa {
    _acl: BuiltAcl,
    _sd: Box<SECURITY_DESCRIPTOR>,
    sa: SECURITY_ATTRIBUTES,
}

impl OwnedSa {
    pub fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &self.sa
    }
}

/// A de-duplicated, pre-parsed ALLOW ACE list. Build once per
/// batch (in [`PrebuiltDacls`]) so the per-file
/// `ConvertStringSidToSidW` cost for the constant
/// group/SYSTEM/Admins/OWNER_RIGHTS/Everyone/user SIDs is paid
/// once, not N times. Only the marker ACE varies per file.
pub struct ParsedAces {
    rows: Vec<(LocalPsid, Mask, ACE_FLAGS)>,
}

impl ParsedAces {
    /// Parse and case-insensitively de-dup (first wins). The
    /// `<group>` and `BUILTIN\Administrators` rows collapse when
    /// the group SID *is* Admins (CI test fence). All call sites
    /// pass identical masks for duplicate SIDs, so first-wins is
    /// equivalent to mask-merge.
    pub fn parse(aces: &[Allow<'_>]) -> Result<Self> {
        let mut keep: Vec<&Allow<'_>> = Vec::with_capacity(aces.len());
        for a in aces {
            if !keep.iter().any(|k| k.0.eq_ignore_ascii_case(a.0)) {
                keep.push(a);
            }
        }
        let mut rows = Vec::with_capacity(keep.len());
        for Allow(sid_str, m, fl) in keep {
            let sid = LocalPsid::from_string(sid_str)
                .with_context(|| format!("parse SID '{sid_str}'"))?;
            if unsafe { GetLengthSid(sid.as_psid()) } == 0 {
                bail!("GetLengthSid('{sid_str}') == 0");
            }
            rows.push((sid, *m, *fl));
        }
        Ok(Self { rows })
    }

    /// ALLOW ACEs + (when `Some`) one trailing marker
    /// `ACCESS_DENIED_ACE{S-1-0-h.., READ_CONTROL, flags=0}`.
    /// `classify_sd` matches the marker position-agnostically.
    pub fn build_with_marker(&self, marker: Option<&MarkerHash>) -> Result<BuiltAcl> {
        let marker_sid = marker
            .map(|h| LocalPsid::from_string(&marker_sid_string(h)))
            .transpose()
            .context("parse marker SID")?;
        let head: Vec<NewAce> = self
            .rows
            .iter()
            .map(|(s, m, fl)| NewAce::Allow(s.as_psid(), m.bits(), *fl))
            .collect();
        // READ_CONTROL not 0; NO_INHERIT — see hash-ACE note.
        let tail: Vec<NewAce> = marker_sid
            .iter()
            .map(|m| NewAce::Deny(m.as_psid(), Mask::READ_CONTROL.bits(), NO_INHERIT))
            .collect();
        rebuild_acl(ACL_REVISION, &head, &KeptAces::EMPTY, &tail)
        // `marker_sid` (and `self.rows`' LocalPsids) drop here; the
        // SID bytes are already inline in the returned ACL buffer.
    }
}

/// Build an ALLOW-only DACL from an ACE table. Convenience for
/// callers that build once and apply once (init-mutex, state-DB
/// dir, tests); the per-file stamp loop uses [`ParsedAces`]
/// directly so the SID parse is amortized.
pub fn build_allow_dacl(aces: &[Allow<'_>]) -> Result<BuiltAcl> {
    ParsedAces::parse(aces)?.build_with_marker(None)
}

// ─── Hash-ACE marker (disk-is-truth seal) ───────────────────────────
//
// Every broker stamp DACL carries ONE extra `ACCESS_DENIED_ACE`
// whose SID encodes `SHA-256(original_sd || file_id)` as
// `S-1-0-h0..h7` (Null SID Authority, 8×u32 sub-auths = 256 bits).
// The child has no `WRITE_DAC` on a stamped object so cannot forge
// or strip it; restore refuses to write back any `original_sd`
// whose hash doesn't match the on-disk marker.
//
// Mask is `READ_CONTROL`, **not 0** — `SetNamedSecurityInfoW` and
// .NET `CommonAcl` both silently drop mask-0 ACEs (see
// [`Allow::OWNER_RIGHTS`]). Inertness comes from the SID alone (no
// token ever holds an authority-0 8-subauth SID). Flags = 0 so a
// parent marker never inherits and pollutes a child's
// `classify_sd`.

/// 32-byte SHA-256 of `original_sd || file_id` — the value packed
/// into the marker SID's 8 sub-authorities.
pub type MarkerHash = [u8; 32];

const ACCESS_DENIED_ACE_TYPE: u8 = 1;
/// Fixed prefix of `ACCESS_ALLOWED_ACE` / `ACCESS_DENIED_ACE`
/// (Header 4 + Mask 4); `SidStart` is the first DWORD of the SID.
const ACE_FIXED: usize = 8;

/// `n` rounded up to a DWORD boundary — `InitializeAcl` requires the
/// ACL buffer length to be DWORD-aligned.
const fn dword_align(n: usize) -> usize {
    (n + 3) & !3
}

/// One ACE to add at the head/tail of a [`rebuild_acl`] output.
/// `PSID` borrows the caller's SID buffer; keep it alive across the
/// call.
pub(crate) enum NewAce {
    Allow(PSID, u32, ACE_FLAGS),
    Deny(PSID, u32, ACE_FLAGS),
}

impl NewAce {
    fn sid(&self) -> PSID {
        let (Self::Allow(s, ..) | Self::Deny(s, ..)) = self;
        *s
    }
}

/// Size + `InitializeAcl(rev)` + `head` ACEs + `kept` raw ACEs +
/// `tail` ACEs → [`BuiltAcl`]. The single ACL-construction
/// chokepoint: [`ParsedAces::build_with_marker`] (head + marker
/// tail, `rev = ACL_REVISION`), [`apply_sandbox_aces`] (head + kept,
/// `rev` from the source ACL via [`filter_aces`]),
/// [`build_explicit_only_acl`] (kept only), and
/// `winsta::recompose_dacl` (kept + tail) all thread through here.
///
/// `rev` MUST match the kept ACEs' source revision when `kept` is
/// non-empty (`AddAce` requires `ACL_REVISION_DS` when copying
/// object-type ACEs); pass [`KeptAces::src_rev`].
pub(crate) fn rebuild_acl(
    rev: ACE_REVISION,
    head: &[NewAce],
    kept: &KeptAces,
    tail: &[NewAce],
) -> Result<BuiltAcl> {
    let mut total = size_of::<ACL>() + kept.total_sz;
    for a in head.iter().chain(tail) {
        total += ACE_FIXED + unsafe { GetLengthSid(a.sid()) } as usize;
    }
    total = dword_align(total);
    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    unsafe { InitializeAcl(acl, total as u32, rev) }.context("InitializeAcl")?;
    let add = |a: &NewAce| match *a {
        NewAce::Allow(s, m, f) => unsafe { AddAccessAllowedAceEx(acl, rev, f, m, s) }
            .with_context(|| format!("AddAccessAllowedAceEx({m:#x})")),
        NewAce::Deny(s, m, f) => unsafe { AddAccessDeniedAceEx(acl, rev, f, m, s) }
            .with_context(|| format!("AddAccessDeniedAceEx({m:#x})")),
    };
    head.iter().try_for_each(&add)?;
    for (ace, sz) in &kept.aces {
        unsafe { AddAce(acl, rev, u32::MAX, *ace, *sz as u32) }.context("AddAce(keep)")?;
    }
    tail.iter().try_for_each(&add)?;
    Ok(BuiltAcl { buf })
}

/// `h` → string SID `S-1-0-h0-h1-…-h7` (Null SID Authority, 8
/// sub-authorities = 8×u32 LE = 256 bits). Round-trips through
/// `ConvertStringSidToSidW`/`ConvertSidToStringSidW` byte-exact.
pub fn marker_sid_string(h: &MarkerHash) -> String {
    let mut s = String::with_capacity(96);
    s.push_str("S-1-0");
    for i in 0..8 {
        let sub = u32::from_le_bytes([h[i * 4], h[i * 4 + 1], h[i * 4 + 2], h[i * 4 + 3]]);
        s.push('-');
        s.push_str(&sub.to_string());
    }
    s
}

/// `SHA-256(original_sd || file_id)`.
pub fn compute_marker_hash(original_sd: &CapturedSd, file_id: &FileId) -> MarkerHash {
    let mut h = Sha256::new();
    h.update(original_sd.as_bytes());
    h.update(file_id.as_bytes());
    h.finalize().into()
}

/// `SetNamedSecurityInfoW(SE_FILE_OBJECT, DACL | PROTECTED)` for
/// a file or directory. `label` is for the error context only.
pub fn set_file_dacl_protected(canonical_path: &str, dacl: &BuiltAcl, label: &str) -> Result<()> {
    write_file_dacl(canonical_path, dacl.as_ptr(), Protection::Protected).context(label.to_owned())
}

/// Whether [`write_file_dacl`] sets `PROTECTED_` (block inheritance
/// from the parent — used for the broker-only allow-list stamp and
/// state-DB dir) or `UNPROTECTED_DACL_SECURITY_INFORMATION`
/// (re-derive inherited ACEs from the parent — used by
/// [`apply_sandbox_aces`]).
pub(crate) enum Protection {
    Protected,
    Unprotected,
}

/// Write `acl` as `path`'s DACL via
/// `SetNamedSecurityInfoW(SE_FILE_OBJECT, DACL | <p>)`. Mirror of
/// [`read_file_dacl`].
pub(crate) fn write_file_dacl(path: &str, acl: *const ACL, p: Protection) -> Result<()> {
    let prot = match p {
        Protection::Protected => PROTECTED_DACL_SECURITY_INFORMATION,
        Protection::Unprotected => UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    let w = wstr(path);
    let r = unsafe {
        SetNamedSecurityInfoW(
            pcwstr(&w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | prot,
            None,
            None,
            Some(acl),
            None,
        )
    };
    win32_ok(r, &format!("SetNamedSecurityInfoW('{path}')"))
}

/// Stamp shape. `ReadDeny` makes the file broker-only for ALL
/// access via the file's DACL; `WriteDeny` leaves read/execute open
/// to Everyone with content writes (and `WRITE_DAC`) broker-only.
///
/// Note: delete/rename is governed by the PARENT directory's
/// `FILE_DELETE_CHILD`, not the file's DACL — the file DACL alone
/// does NOT prevent it. So `acl stamp` ALSO stamps the file's
/// immediate parent directory with the allow-list from
/// [`parent_allow_list_aces`] (user gets
/// Modify-without-FDC). When the parent can't be
/// stamped (no `WRITE_DAC` on it), the file falls back to the
/// per-exec no-`FILE_SHARE_DELETE` handle fence
/// ([`crate::fence`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMask {
    ReadDeny,
    WriteDeny,
}

impl AclMask {
    pub fn as_str(self) -> &'static str {
        match self {
            AclMask::ReadDeny => "read",
            AclMask::WriteDeny => "write",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "read" => Ok(AclMask::ReadDeny),
            "write" => Ok(AclMask::WriteDeny),
            other => bail!("unknown AclMask {other:?}"),
        }
    }

    /// True if applying `self`'s stamp would deny an access that
    /// `other`'s stamp permits (i.e. self is the stricter mask).
    /// Linear: `ReadDeny` (no Everyone-read ACE) is stricter than
    /// `WriteDeny` (which keeps `GENERIC_READ|EXECUTE`).
    pub fn is_stricter_than(self, other: AclMask) -> bool {
        matches!((self, other), (AclMask::ReadDeny, AclMask::WriteDeny))
    }
    /// `max(self, other)` under the strictness order.
    pub fn max(self, other: AclMask) -> AclMask {
        if self.is_stricter_than(other) {
            self
        } else {
            other
        }
    }
}

/// On-disk DACL classified against the broker stamp shapes — the
/// SOLE input the state machine trusts about protection state (the
/// DB row is a hint, corroborated against the marker hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StampClass {
    /// Not PROTECTED, or no marker AND no broker-shape match. The
    /// live DACL IS the original baseline.
    Unstamped,
    /// Broker file-stamp ACEs for `mask` + one marker encoding `h`.
    File(AclMask, MarkerHash),
    /// Broker dir-stamp ACEs (`(OI)(CI)` `broker_only_aces`) for
    /// `mask` + one non-inheriting marker. Inherits to the whole
    /// subtree; the marker stays on the dir itself.
    DirTarget(AclMask, MarkerHash),
    /// Parent allow-list ACEs + one marker.
    ParentAllowList(MarkerHash),
    /// PROTECTED and either (a) a broker shape with NO marker
    /// (stripped by an admin tool, or a legacy pre-marker stamp),
    /// or (b) a marker IS present but the non-marker ACEs don't
    /// exact-match a calibrated shape (admin added/tweaked an ACE,
    /// or a stamp from a different group/user SID). NEVER routed
    /// to `Unstamped` — that would set `original_sd = cur` (a
    /// derivative of the broker stamp) and silently destroy the
    /// user's real ACL.
    StampedUnrecognized,
}

/// A captured self-relative security-descriptor blob. Cheap newtype
/// over `Vec<u8>` so the byte-offset / bit-mask reads live in one
/// place behind named methods rather than scattered through the
/// state machine. Storage (the SQLite BLOB column) round-trips via
/// `as_bytes()` / `From<Vec<u8>>`.
#[derive(Debug, Clone)]
pub struct CapturedSd(Vec<u8>);

impl CapturedSd {
    /// Borrow as bytes for storage / hashing.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The SD's `SECURITY_DESCRIPTOR_CONTROL` word (LE u16 at
    /// bytes 2–3 of the self-relative header).
    pub fn control(&self) -> u16 {
        if self.0.len() < 4 {
            return 0;
        }
        u16::from_le_bytes([self.0[2], self.0[3]])
    }

    /// Equivalent for our purposes — byte-equal with
    /// `SE_DACL_AUTO_INHERITED` (0x0400) and
    /// `SE_SACL_AUTO_INHERITED` (0x0800) masked out of `control()`.
    /// Those are OS-set markers stamped after auto-inherit
    /// evaluation (any UNPROTECTED `SetNamedSecurityInfoW`, a
    /// parent DACL change, `Set-Acl`, etc.); they don't affect
    /// access and the OS can flip them at any time, so the state
    /// machine's "has this SD changed since we stamped/captured
    /// it?" checks must treat them as noise.
    pub fn equiv(&self, other: &CapturedSd) -> bool {
        const AI: u16 = 0x0C00;
        if self.0.len() != other.0.len() || self.0.len() < 4 {
            return self.0 == other.0;
        }
        (self.control() & !AI) == (other.control() & !AI)
            && self.0[..2] == other.0[..2]
            && self.0[4..] == other.0[4..]
    }
}

impl From<Vec<u8>> for CapturedSd {
    fn from(v: Vec<u8>) -> Self {
        CapturedSd(v)
    }
}

// ─── DACL read + ACE-walk primitives ────────────────────────────────
// Shared low-level wrappers so the recompose / explicit-only / walk
// callers don't each open-code GetNamedSecurityInfoW + GetAce loops.
// `winsta.rs::recompose_dacl` will adopt `filter_aces` with its own
// predicate (it KEEPS inherited ACEs; the file callers here drop
// them).

/// Read a file's DACL via
/// `GetNamedSecurityInfoW(SE_FILE_OBJECT, DACL_SECURITY_INFORMATION)`.
/// The returned `*mut ACL` points INTO the returned `OwnedSd`'s
/// buffer — keep the `OwnedSd` alive while using the pointer.
pub(crate) fn read_file_dacl(canonical_path: &str) -> Result<(OwnedSd, *mut ACL)> {
    let w = wstr(canonical_path);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let r = unsafe {
        GetNamedSecurityInfoW(
            pcwstr(&w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut psd,
        )
    };
    win32_ok(r, &format!("GetNamedSecurityInfoW('{canonical_path}')"))?;
    Ok((OwnedSd::from_raw(psd), dacl))
}

/// Kept ACE pointers from a [`filter_aces`] walk, plus their
/// summed size and the source ACL's revision (so a [`rebuild_acl`]
/// caller can preserve `ACL_REVISION_DS` for object-type ACEs).
pub(crate) struct KeptAces {
    pub(crate) aces: Vec<(*const c_void, u16)>,
    pub(crate) total_sz: usize,
    pub(crate) src_rev: ACE_REVISION,
}

impl KeptAces {
    /// No kept ACEs; `src_rev = ACL_REVISION` (the no-object-ACE
    /// default).
    pub(crate) const EMPTY: Self = Self {
        aces: Vec::new(),
        total_sz: 0,
        src_rev: ACL_REVISION,
    };
}

/// Walk every ACE of `acl` and collect `(ptr, AceSize)` for those
/// `keep` accepts. Returns `(kept, Σ kept sizes, source AclRevision)`.
/// `acl == null` → `(∅, 0, ACL_REVISION)`. The kept pointers point
/// into `acl`'s buffer; caller must keep that buffer alive.
///
/// `keep` receives the raw `ACE_HEADER` and `body` = the full ACE
/// bytes (`hdr.AceSize` long, starting at the ACE pointer — so
/// `body[ACE_FIXED..]` is the embedded SID).
///
/// The source's `AclRevision` is returned so a caller building a
/// fresh ACL from kept ACEs can preserve it: `AddAce` requires
/// `ACL_REVISION_DS` (4) when copying object-type ACEs, and
/// `RtlValidAcl` rejects an ACL whose revision doesn't match its
/// ACEs.
pub(crate) fn filter_aces(
    acl: *const ACL,
    mut keep: impl FnMut(&ACE_HEADER, &[u8]) -> bool,
) -> Result<KeptAces> {
    if acl.is_null() {
        return Ok(KeptAces::EMPTY);
    }
    let src_rev = ACE_REVISION(unsafe { (*acl).AclRevision } as u32);
    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            acl,
            &mut info as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
        .context("GetAclInformation")?;
    }
    let mut kept = KeptAces {
        aces: Vec::new(),
        total_sz: 0,
        src_rev,
    };
    for i in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        unsafe { GetAce(acl, i, &mut ace) }.map_err(|e| anyhow!("GetAce({i}): {e}"))?;
        if ace.is_null() {
            bail!("GetAce({i}) returned null");
        }
        let hdr = unsafe { &*(ace as *const ACE_HEADER) };
        let body = unsafe { std::slice::from_raw_parts(ace as *const u8, hdr.AceSize as usize) };
        if keep(hdr, body) {
            kept.aces.push((ace as *const c_void, hdr.AceSize));
            kept.total_sz += hdr.AceSize as usize;
        }
    }
    Ok(kept)
}

/// True iff `body[ACE_FIXED..]` starts with exactly `sid_bytes` —
/// i.e. the ACE's trustee SID is `sid_bytes`.
pub(crate) fn ace_sid_is(body: &[u8], sid_bytes: &[u8]) -> bool {
    body.get(ACE_FIXED..ACE_FIXED + sid_bytes.len()) == Some(sid_bytes)
}

/// One ACE split into `(type, flags, mask, sid)` for comparison.
#[derive(Debug, Clone)]
struct AceView {
    ace_type: u8,
    ace_flags: u8,
    mask: u32,
    sid: Vec<u8>,
}

impl AceView {
    fn key(&self) -> (u8, u8, u32, &[u8]) {
        (self.ace_type, self.ace_flags, self.mask, &self.sid)
    }
    /// `Some(h)` iff this is a marker ACE: deny, SID under the
    /// Null authority with exactly 8 sub-auths. Mask/flags are NOT
    /// checked (tolerant of canonicalizers).
    fn marker_hash(&self) -> Option<MarkerHash> {
        if self.ace_type != ACCESS_DENIED_ACE_TYPE {
            return None;
        }
        // Binary SID: rev(1) subauth-count(1) idauth[6] subauth[..].
        if self.sid.len() != 8 + 8 * 4
            || self.sid[0] != 1
            || self.sid[1] != 8
            || self.sid[2..8] != [0, 0, 0, 0, 0, 0]
        {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.sid[8..]);
        Some(h)
    }
}

/// Walk every ACE of `dacl` (SID bytes copied out).
fn walk_aces(dacl: *const ACL) -> Result<Vec<AceView>> {
    let mut out = Vec::new();
    let mut bad: Option<usize> = None;
    filter_aces(dacl, |hdr, body| {
        if body.len() < ACE_FIXED + 8 {
            bad.get_or_insert(body.len());
            return false;
        }
        let mask = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        let sid_start = &body[ACE_FIXED..];
        let sub = sid_start.get(1).copied().unwrap_or(0) as usize;
        let sid_len = (8 + 4 * sub).min(sid_start.len());
        out.push(AceView {
            ace_type: hdr.AceType,
            ace_flags: hdr.AceFlags,
            mask,
            sid: sid_start[..sid_len].to_vec(),
        });
        false // we copied what we need; don't keep ptrs
    })?;
    if let Some(sz) = bad {
        bail!("walk_aces: ACE too small ({sz}B)");
    }
    Ok(out)
}

/// Owned, sorted ACE-key set for order-independent comparison.
type AceKeys = Vec<(u8, u8, u32, Vec<u8>)>;

fn ace_keys(aces: &[AceView]) -> AceKeys {
    let mut v: AceKeys = aces
        .iter()
        .map(|a| {
            let (t, f, m, s) = a.key();
            (t, f, m, s.to_vec())
        })
        .collect();
    v.sort();
    v
}

/// Pre-sorted reference broker-shape ACE-key sets (sans marker)
/// for [`classify_sd`]'s order-independent exact match. Sorted
/// once at build time so the per-file compare is just `==`.
pub struct StampCalibration {
    read_deny: AceKeys,
    write_deny: AceKeys,
    dir_read_deny: AceKeys,
    dir_write_deny: AceKeys,
    parent: AceKeys,
}

#[derive(Copy, Clone)]
enum Shape {
    File(AclMask),
    Dir(AclMask),
    Parent,
}

impl StampCalibration {
    fn shape_of(&self, keys: &AceKeys) -> Option<Shape> {
        if *keys == self.read_deny {
            Some(Shape::File(AclMask::ReadDeny))
        } else if *keys == self.write_deny {
            Some(Shape::File(AclMask::WriteDeny))
        } else if *keys == self.dir_read_deny {
            Some(Shape::Dir(AclMask::ReadDeny))
        } else if *keys == self.dir_write_deny {
            Some(Shape::Dir(AclMask::WriteDeny))
        } else if *keys == self.parent {
            Some(Shape::Parent)
        } else {
            None
        }
    }
}

/// Per-batch inputs to `ensure_stamped`. Caches the
/// parsed/de-duped ALLOW ACE lists for each stamp shape so the
/// constant SIDs are `ConvertStringSidToSidW`'d once, not per
/// file (only the marker ACE varies). The full DACLs can't be
/// pre-built — each carries a per-file marker hash.
pub struct PrebuiltDacls {
    read_deny: ParsedAces,
    write_deny: ParsedAces,
    dir_read_deny: ParsedAces,
    dir_write_deny: ParsedAces,
    parent: ParsedAces,
    pub calib: StampCalibration,
}

impl PrebuiltDacls {
    /// Same-user mode: trustee = the discriminator group; parent
    /// allow-list applied. The `user_sid` for the parent allow-list
    /// is read here so callers don't repeat the lookup.
    ///
    /// (Separate-user mode does NOT use this — it applies an
    /// additive DENY ACE for the sandbox user via [`SbAceSet`]
    /// instead of a PROTECTED rewrite.)
    pub fn for_current_user(group_sid: &str) -> Result<Self> {
        let user_sid = crate::sid::current_user_sid()?;
        Self::build(group_sid, &user_sid)
    }

    pub fn build(trustee_sid: &str, user_sid: &str) -> Result<Self> {
        let read_deny =
            ParsedAces::parse(&broker_only_aces(trustee_sid, AclMask::ReadDeny, false))?;
        let write_deny =
            ParsedAces::parse(&broker_only_aces(trustee_sid, AclMask::WriteDeny, false))?;
        let dir_read_deny =
            ParsedAces::parse(&broker_only_aces(trustee_sid, AclMask::ReadDeny, true))?;
        let dir_write_deny =
            ParsedAces::parse(&broker_only_aces(trustee_sid, AclMask::WriteDeny, true))?;
        let parent = ParsedAces::parse(&parent_allow_list_aces(trustee_sid, user_sid))?;
        let keys_of = |a: &ParsedAces| -> Result<AceKeys> {
            let d = a.build_with_marker(None)?;
            Ok(ace_keys(&walk_aces(d.as_ptr())?))
        };
        let calib = StampCalibration {
            read_deny: keys_of(&read_deny)?,
            write_deny: keys_of(&write_deny)?,
            dir_read_deny: keys_of(&dir_read_deny)?,
            dir_write_deny: keys_of(&dir_write_deny)?,
            parent: keys_of(&parent)?,
        };
        Ok(Self {
            read_deny,
            write_deny,
            dir_read_deny,
            dir_write_deny,
            parent,
            calib,
        })
    }

    fn target_aces(&self, mask: AclMask, is_dir: bool) -> &ParsedAces {
        match (is_dir, mask) {
            (false, AclMask::ReadDeny) => &self.read_deny,
            (false, AclMask::WriteDeny) => &self.write_deny,
            (true, AclMask::ReadDeny) => &self.dir_read_deny,
            (true, AclMask::WriteDeny) => &self.dir_write_deny,
        }
    }
}

/// Classify a captured on-disk SD against the broker's stamp
/// shapes. See [`StampClass`]. `Unstamped` is the only result that
/// ever sets `original_sd = cur`, so any DACL that COULD be a
/// derivative of a broker stamp (PROTECTED + marker present, OR
/// PROTECTED + exact broker shape) routes to a fail-closed class
/// instead.
pub fn classify_sd(sd: &CapturedSd, calib: &StampCalibration) -> Result<StampClass> {
    // Real broker stamps are always PROTECTED. An UNPROTECTED DACL
    // whose inherited ACEs happen to match a broker shape (e.g. a
    // file under the broker-only state-DB dir) is pristine.
    if sd.control() & SE_DACL_PROTECTED.0 == 0 {
        return Ok(StampClass::Unstamped);
    }
    let psd = PSECURITY_DESCRIPTOR(sd.0.as_ptr() as *mut c_void);
    let mut present = windows::core::BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut def = windows::core::BOOL(0);
    unsafe {
        GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut def)
            .context("GetSecurityDescriptorDacl(classify)")?;
    }
    if !present.as_bool() || dacl.is_null() {
        return Ok(StampClass::Unstamped);
    }
    let all = walk_aces(dacl)?;
    let mut marker: Option<MarkerHash> = None;
    let mut rest: Vec<AceView> = Vec::with_capacity(all.len());
    for a in all {
        if let Some(h) = a.marker_hash() {
            if marker.is_some() {
                // ≥2 markers is never our write — but a marker IS
                // present, so don't route to Unstamped.
                return Ok(StampClass::StampedUnrecognized);
            }
            marker = Some(h);
        } else {
            rest.push(a);
        }
    }
    Ok(match (calib.shape_of(&ace_keys(&rest)), marker) {
        (Some(Shape::File(m)), Some(h)) => StampClass::File(m, h),
        (Some(Shape::Dir(m)), Some(h)) => StampClass::DirTarget(m, h),
        (Some(Shape::Parent), Some(h)) => StampClass::ParentAllowList(h),
        // Shape match + no marker, OR no shape match + marker
        // present (extra/tweaked ACE, or a stamp from a different
        // group/user SID — the marker is unforgeable so the DACL is
        // a derivative of SOME broker stamp). NEVER `Unstamped`.
        (Some(_), None) | (None, Some(_)) => StampClass::StampedUnrecognized,
        (None, None) => StampClass::Unstamped,
    })
}

/// Capture DACL+Owner+Group as a self-relative SD blob suitable for
/// storage and round-tripping into `restore_sd`.
pub fn capture_sd(canonical_path: &str) -> Result<CapturedSd> {
    let w = wstr(canonical_path);
    let info = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let r = unsafe {
        GetNamedSecurityInfoW(
            pcwstr(&w),
            SE_FILE_OBJECT,
            info,
            None,
            None,
            None,
            None,
            &mut psd,
        )
    };
    win32_ok(r, &format!("GetNamedSecurityInfoW('{canonical_path}')"))?;
    // The returned SD is documented self-relative; copy it out so we
    // own the bytes.
    let len = unsafe { GetSecurityDescriptorLength(psd) } as usize;
    if len == 0 {
        local_free(psd.0);
        bail!("GetSecurityDescriptorLength('{canonical_path}') == 0");
    }
    let bytes = unsafe { std::slice::from_raw_parts(psd.0 as *const u8, len).to_vec() };
    local_free(psd.0);
    Ok(CapturedSd(bytes))
}

/// Restore from a previously-captured SD blob, bit-exact wrt the
/// DACL-protected state:
///
/// - Purely-inherited original (every ACE `INHERITED_ACE`): restore
///   by clearing the explicit DACL with `UNPROTECTED` so the kernel
///   re-derives from the parent. Round-tripping the inherited ACEs
///   would persist them as explicit and decouple the file from
///   future parent-DACL changes.
/// - Original had ≥1 explicit ACE: round-trip the captured DACL and
///   set `PROTECTED` vs `UNPROTECTED` to match the original's
///   `SE_DACL_PROTECTED` control bit (read from the captured SD).
///   Our stamp always sets `PROTECTED`; without restoring the
///   original protected-state, an originally-unprotected file would
///   come back protected and stop auto-inheriting.
pub fn restore_sd(canonical_path: &str, sd: &CapturedSd) -> Result<()> {
    let sd_bytes = sd.as_bytes();
    if sd_bytes.is_empty() {
        bail!("restore_sd('{canonical_path}'): empty SD bytes");
    }
    let psd = PSECURITY_DESCRIPTOR(sd_bytes.as_ptr() as *mut c_void);
    let mut present = windows::core::BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = windows::core::BOOL(0);
    unsafe {
        GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut defaulted)
            .map_err(|e| anyhow!("GetSecurityDescriptorDacl(restore): {e}"))?;

        // Read the original's DACL-protected control bit. The
        // windows-0.62 binding types `pcontrol` as `*mut u16`
        // (raw `SECURITY_DESCRIPTOR_CONTROL` value), so compare
        // against `SE_DACL_PROTECTED.0`.
        let mut control: u16 = 0;
        let mut rev = 0u32;
        let was_protected = GetSecurityDescriptorControl(psd, &mut control, &mut rev).is_ok()
            && (control & SE_DACL_PROTECTED.0) != 0;

        // DACL ONLY. Stamp never touched owner/group, and writing
        // them back fails with `ERROR_INVALID_OWNER` for any owner
        // SID that isn't the caller's user / an `SE_GROUP_OWNER`
        // group / a `SeRestorePrivilege`-enabled token — which
        // would leave the file STUCK with the broker-only stamp.
        let mut info = DACL_SECURITY_INFORMATION;

        // Restore bit-exact wrt the protected-state:
        //
        // - NULL DACL → restore NULL (everyone full access) with
        //   UNPROTECTED. Our stamp set PROTECTED, and
        //   `SetNamedSecurityInfoW` leaves the bit unchanged when
        //   neither flag is given; a true NULL-DACL original is by
        //   construction unprotected (a protected break would have
        //   left an explicit empty ACL, not NULL), so UNPROTECTED
        //   re-couples it to its parent.
        // - Original PROTECTED → a protected DACL has no
        //   INHERITED_ACE ACEs (breaking inheritance copies them to
        //   explicit), so round-trip the whole captured DACL with
        //   PROTECTED.
        // - Original UNPROTECTED → pass ONLY the explicit
        //   (non-INHERITED_ACE) ACEs with UNPROTECTED and let the
        //   kernel re-inherit the rest. Passing the captured
        //   inherited ACEs back verbatim would duplicate them
        //   (our explicit copies + freshly-inherited ones). When
        //   the original was purely inherited this yields an empty
        //   explicit ACL — exactly "no explicit DACL, inheritance
        //   on".
        let explicit_only;
        let dacl_arg: Option<*const ACL> = if !present.as_bool() || dacl.is_null() {
            info |= UNPROTECTED_DACL_SECURITY_INFORMATION;
            None
        } else if was_protected {
            info |= PROTECTED_DACL_SECURITY_INFORMATION;
            Some(dacl as *const ACL)
        } else {
            explicit_only = build_explicit_only_acl(dacl)?;
            info |= UNPROTECTED_DACL_SECURITY_INFORMATION;
            Some(explicit_only.as_ptr() as *const ACL)
        };

        let w = wstr(canonical_path);
        let r = SetNamedSecurityInfoW(pcwstr(&w), SE_FILE_OBJECT, info, None, None, dacl_arg, None);
        win32_ok(
            r,
            &format!("SetNamedSecurityInfoW(restore '{canonical_path}')"),
        )?;
    }
    Ok(())
}

/// Broker-only ACE list for `mask`. `inherit` adds `(OI)(CI)` to
/// every ALLOW ACE (directory targets and the state-DB dir).
///
/// `trustee_sid` is "who CAN access" — under the same-user model
/// this is the discriminator group SID (the broker is in it; the
/// child has it deny-only); under the separate-user model it's the
/// REAL user's SID (the broker matches; the sandbox-user child
/// does not).
fn broker_only_aces(trustee_sid: &str, mask: AclMask, inherit: bool) -> Vec<Allow<'_>> {
    let fl = if inherit { OICI } else { NO_INHERIT };
    let ow = if inherit {
        Allow::OWNER_RIGHTS_OICI
    } else {
        Allow::OWNER_RIGHTS
    };
    let mut aces = vec![
        Allow(trustee_sid, Mask::FILE_ALL, fl),
        Allow(SID_SYSTEM, Mask::FILE_ALL, fl),
        Allow(SID_BUILTIN_ADMINS, Mask::FILE_ALL, fl), // dedup'd if == trustee
        ow,
    ];
    // WriteDeny: leave read+execute open to Everyone so the file
    // is still readable/runnable by the sandboxed child; only
    // write/delete/WRITE_DAC are broker-only.
    if mask == AclMask::WriteDeny {
        aces.push(Allow(SID_EVERYONE, Mask::FILE_READ_EXEC, fl));
    }
    aces
}

/// Parent allow-list ACE list: `PROTECTED`,
/// SYSTEM/Admins/`<group>`: `(OI)(CI)` `FILE_ALL`; `<user>`:
/// `(OI)(CI)` [`Mask::MODIFY_NO_FDC`]; [`Allow::OWNER_RIGHTS`]
/// (no inherit — applies to the directory itself only, so
/// non-protected children keep implicit owner rights). The
/// `OWNER_RIGHTS` ACE is mandatory: without it an owner-child gets
/// implicit `READ_CONTROL|WRITE_DAC`, can rewrite the directory's
/// DACL, and re-grant itself `FILE_DELETE_CHILD`.
fn parent_allow_list_aces<'a>(group_sid: &'a str, user_sid: &'a str) -> [Allow<'a>; 5] {
    [
        Allow(SID_SYSTEM, Mask::FILE_ALL, OICI),
        Allow(group_sid, Mask::FILE_ALL, OICI),
        Allow(SID_BUILTIN_ADMINS, Mask::FILE_ALL, OICI), // dedup'd if == group
        Allow(user_sid, Mask::MODIFY_NO_FDC, OICI),
        Allow::OWNER_RIGHTS,
    ]
}

/// One-shot build (parse + emit). The per-file stamp loop uses
/// [`PrebuiltDacls`] so the SID parse is amortized; this is for
/// one-off callers (state-DB dir, tests).
pub fn build_broker_only_dacl(
    group_sid: &str,
    mask: AclMask,
    inherit: bool,
    marker: Option<&MarkerHash>,
) -> Result<BuiltAcl> {
    ParsedAces::parse(&broker_only_aces(group_sid, mask, inherit))?.build_with_marker(marker)
}

/// One-shot build (parse + emit). See [`build_broker_only_dacl`].
pub fn build_parent_allow_list_dacl(
    group_sid: &str,
    user_sid: &str,
    marker: Option<&MarkerHash>,
) -> Result<BuiltAcl> {
    ParsedAces::parse(&parent_allow_list_aces(group_sid, user_sid))?.build_with_marker(marker)
}

/// Build + apply the broker-only stamp (DACL+marker, `PROTECTED`)
/// in one atomic `SetNamedSecurityInfoW`. The ORIGINAL SD must
/// already have been captured and persisted. `is_dir` selects the
/// `(OI)(CI)`-inheriting ACE shape so the stamp covers the whole
/// subtree; the marker stays `flags=0` (non-inheriting) so a
/// pure-inherit descendant's `classify_sd` is `Unstamped`.
pub fn stamp_target_apply(
    canonical_path: &str,
    dacls: &PrebuiltDacls,
    mask: AclMask,
    is_dir: bool,
    marker: &MarkerHash,
) -> Result<()> {
    let dacl = dacls
        .target_aces(mask, is_dir)
        .build_with_marker(Some(marker))?;
    set_file_dacl_protected(canonical_path, &dacl, "stamp")
}

/// Apply the broker-only DACL to a directory with `(OI)(CI)`
/// inheritance, optionally **prefixed** by a `(D;OICI;FA;;;
/// <deny_sid>)` ACE. Used by `state_db.rs` and `install.rs` to
/// protect `%LOCALAPPDATA%\sandbox-runtime\`.
///
/// `deny_sid` is the [`crate::user::SANDBOX_GROUP`] SID when the
/// sandbox user has been provisioned: the credential file in this
/// directory is encrypted with **machine-scope** DPAPI, which any
/// local account can decrypt — so the sandbox account MUST NOT be
/// able to read it. The broker-only `PROTECTED` allow set already
/// excludes the sandbox user (it's not in `<group_sid>` / SYSTEM /
/// Admins), but the explicit DENY makes that intent visible in
/// `Get-Acl` and survives any future widening of the allow set.
///
/// Built via SDDL because [`build_allow_dacl`] only emits ALLOW
/// ACEs (plus the marker DENY), and adding a generic DENY row to
/// the [`Allow`]/[`ParsedAces`] table would invite misuse in the
/// per-file stamp paths where DENY ACEs interact badly with
/// inheritance. NOT the `acl stamp` directory-target path —
/// that uses the marker-carrying [`PrebuiltDacls`] shapes.
pub fn stamp_dir_inheriting(
    canonical_path: &str,
    group_sid: &str,
    deny_sid: Option<&str>,
) -> Result<()> {
    let deny = deny_sid
        .map(|s| format!("(D;OICI;FA;;;{s})"))
        .unwrap_or_default();
    // Same trustees and masks as `broker_only_aces(ReadDeny,
    // inherit=true)`: <group>/SY/BA = FILE_ALL `(OI)(CI)`,
    // OWNER_RIGHTS = READ_CONTROL `(OI)(CI)`. SDDL's `FA` =
    // `FILE_ALL_ACCESS`; `RC` = `READ_CONTROL`; `S-1-3-4` =
    // OWNER_RIGHTS. Canonical ACE order = DENY before ALLOW.
    let sddl = format!(
        "D:P{deny}\
         (A;OICI;FA;;;{group_sid})\
         (A;OICI;FA;;;SY)\
         (A;OICI;FA;;;BA)\
         (A;OICI;RC;;;S-1-3-4)"
    );
    set_path_dacl_from_sddl(canonical_path, &sddl, "state-db dir")
}

/// SDDL → SD → DACL pointer → `SetNamedSecurityInfoW(PROTECTED)`.
/// One-shot helper for the few call sites that need a DENY ACE
/// (which the [`BuiltAcl`] machinery deliberately doesn't expose).
/// The `D:P` prefix in `sddl` is informational; `PROTECTED` is set
/// here regardless via `PROTECTED_DACL_SECURITY_INFORMATION`.
pub fn set_path_dacl_from_sddl(path: &str, sddl: &str, label: &str) -> Result<()> {
    use windows::Win32::Security::GetSecurityDescriptorDacl;
    let sd = crate::util::OwnedSd::from_sddl(sddl)
        .with_context(|| format!("{label}: build SD from SDDL"))?;
    let mut present = windows::core::BOOL::from(false);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = windows::core::BOOL::from(false);
    unsafe {
        GetSecurityDescriptorDacl(sd.ptr, &mut present, &mut dacl, &mut defaulted)
            .with_context(|| format!("{label}: GetSecurityDescriptorDacl"))?;
    }
    if !present.as_bool() || dacl.is_null() {
        bail!("{label}: SDDL '{sddl}' yielded no DACL");
    }
    write_file_dacl(path, dacl, Protection::Protected).context(label.to_owned())
}

// ─── Additive grants (working-tree access for the sandbox user) ─────
//
// Under the separate-user model the sandbox user has NO inherent
// rights on real-user-owned files. `acl grant` adds an inheritable
// ALLOW ACE for the sandbox user's SID on a path (typically the
// working-tree root) so the child can read/write there; `acl stamp
// --sandbox-user-sid` adds an explicit DENY ACE on a path (and a
// `(OI)(CI)` `FILE_DELETE_CHILD` DENY on its parent) so the child
// can NOT read/write/delete it even when an inherited
// `BUILTIN\Users` ACE would otherwise allow. Both are ADDITIVE
// (the path keeps its own explicit ACEs and inheritance);
// revoke/restore drops the SID's ACEs by walk-and-filter, not a
// full-SD restore.

/// Per-grant access level. `Modify` is [`Mask::MODIFY_NO_FDC`] (the
/// working-tree grant — read/write/create/delete-own but NOT
/// `FILE_DELETE_CHILD`, so a denied file inside the granted tree
/// cannot be deleted via parent-FDC even where the only sb-user
/// access comes from this grant). `ReadOnly` is
/// [`Mask::FILE_READ_EXEC`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantMask {
    ReadOnly,
    Modify,
}

/// Per-deny mask. `ReadDeny` denies everything; `WriteDeny` leaves
/// read+execute. The bits are the *denied* rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyMask {
    WriteDeny,
    ReadDeny,
}

/// One explicit ACE the sandbox user holds on a path. The
/// separate-user FS model is entirely additive: `acl grant` adds
/// ALLOW ACEs, `acl stamp --sandbox-user-sid` adds DENY ACEs (plus
/// a `(OI)(CI)` `FILE_DELETE_CHILD` DENY on the parent). Restore
/// drops the SID's ACEs via walk-and-filter — no PROTECTED rewrite,
/// no SD snapshot, no calibration. The same-user model still uses
/// [`PrebuiltDacls`]; the two paths share nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbAce {
    Grant(GrantMask),
    Deny(DenyMask),
    /// `(D;OICI;FILE_DELETE_CHILD;;;<sb>)` — applied to the parent
    /// of every denied target so the sandbox user cannot `del`/`ren`
    /// it via parent-FDC even when the parent carries an inherited
    /// `BUILTIN\Users:(F)` (which the sandbox user, a Users member,
    /// would otherwise pick up).
    DenyFdc,
}

impl GrantMask {
    fn bits(self) -> u32 {
        match self {
            GrantMask::ReadOnly => Mask::FILE_READ_EXEC.bits(),
            GrantMask::Modify => Mask::MODIFY_NO_FDC.bits(),
        }
    }
}

impl DenyMask {
    fn bits(self) -> u32 {
        match self {
            DenyMask::ReadDeny => Mask::FILE_ALL.bits(),
            DenyMask::WriteDeny => Mask::FILE_GENERIC_WRITE
                .with(Mask::DELETE)
                .with(Mask::FILE_WRITE_ATTRIBUTES)
                .bits(),
        }
    }
}

impl SbAce {
    /// `'grant' | 'deny' | 'deny_fdc'` — the row's `kind` column.
    pub fn kind(self) -> &'static str {
        match self {
            SbAce::Grant(_) => "grant",
            SbAce::Deny(_) => "deny",
            SbAce::DenyFdc => "deny_fdc",
        }
    }
    /// `'read' | 'modify' | 'denyRead' | 'denyWrite' | 'fdc'` — the
    /// row's `mask` / holder's `want_mask` column. Round-trips via
    /// [`SbAce::parse`].
    pub fn as_str(self) -> &'static str {
        match self {
            SbAce::Grant(GrantMask::ReadOnly) => "read",
            SbAce::Grant(GrantMask::Modify) => "modify",
            SbAce::Deny(DenyMask::ReadDeny) => "denyRead",
            SbAce::Deny(DenyMask::WriteDeny) => "denyWrite",
            SbAce::DenyFdc => "fdc",
        }
    }
    pub fn parse(kind: &str, mask: &str) -> Result<Self> {
        Ok(match (kind, mask) {
            ("grant", "read") => SbAce::Grant(GrantMask::ReadOnly),
            ("grant", "modify") => SbAce::Grant(GrantMask::Modify),
            ("deny", "denyRead") => SbAce::Deny(DenyMask::ReadDeny),
            ("deny", "denyWrite") => SbAce::Deny(DenyMask::WriteDeny),
            ("deny_fdc", _) => SbAce::DenyFdc,
            (k, m) => bail!("unknown SbAce kind={k:?} mask={m:?}"),
        })
    }
    /// Widening within one kind: `Modify ⊃ ReadOnly`, `ReadDeny ⊃
    /// WriteDeny`, `DenyFdc` is unit. Cross-kind is meaningless (a
    /// path can hold one `Grant` row AND one `Deny` row; never
    /// merged).
    pub fn max(self, other: Self) -> Self {
        use DenyMask::ReadDeny as Dr;
        use GrantMask::Modify as Gm;
        match (self, other) {
            (SbAce::Grant(Gm), _) | (_, SbAce::Grant(Gm)) => SbAce::Grant(Gm),
            (SbAce::Grant(_), _) | (_, SbAce::Grant(_)) => self,
            (SbAce::Deny(Dr), _) | (_, SbAce::Deny(Dr)) => SbAce::Deny(Dr),
            _ => self,
        }
    }
}

/// What [`apply_sandbox_aces`] should converge a path to: at most one
/// ALLOW ACE, one DENY ACE, and one parent-FDC DENY for the sandbox
/// user. State-DB recomputes this from the live holder rows on every
/// change so cross-holder mask escalation/downgrade and the
/// grant/deny-on-same-path interaction are handled in one place.
#[derive(Debug, Clone, Copy, Default)]
pub struct SbAceSet {
    pub grant: Option<GrantMask>,
    pub deny: Option<DenyMask>,
    pub deny_fdc: bool,
}

impl SbAceSet {
    /// The set's entries as [`NewAce`]s for `sid`, in canonical
    /// deny → deny-fdc → allow order. All carry [`OICI`].
    fn head_aces(&self, sid: PSID) -> Vec<NewAce> {
        let mut v = Vec::with_capacity(3);
        if let Some(m) = self.deny {
            v.push(NewAce::Deny(sid, m.bits(), OICI));
        }
        if self.deny_fdc {
            v.push(NewAce::Deny(sid, Mask::FILE_DELETE_CHILD.bits(), OICI));
        }
        if let Some(m) = self.grant {
            v.push(NewAce::Allow(sid, m.bits(), OICI));
        }
        v
    }
}

/// Converge `canonical_path`'s explicit ACEs for `sandbox_sid` to
/// exactly `set`. Idempotent — every existing explicit ACE for the
/// SID (allow AND deny) is dropped, then `set`'s entries are
/// prepended in canonical (deny-before-allow) order. Inherited ACEs
/// are dropped too; `SetNamedSecurityInfoW` without `PROTECTED_`
/// re-derives them from the parent.
///
/// `SetEntriesInAclW(REVOKE_ACCESS)` is NOT used: per MSDN it
/// removes `ACCESS_ALLOWED_ACE`/`SYSTEM_AUDIT_ACE` for the trustee,
/// not `ACCESS_DENIED_ACE` — so a prior `Deny`/`DenyFdc` ACE would
/// survive. `SET_ACCESS` discards all but adds a new ALLOW ACE,
/// which is wrong when `set` is empty. So we walk + filter
/// manually.
///
/// Both grant and deny carry `(OI)(CI)` so directory targets cover
/// the subtree; on a file the inheritance flags are inert.
pub fn apply_sandbox_aces(canonical_path: &str, sandbox_sid: &str, set: SbAceSet) -> Result<()> {
    let sid = LocalPsid::from_string(sandbox_sid)
        .with_context(|| format!("parse sandbox SID '{sandbox_sid}'"))?;
    let sid_bytes = sid.as_bytes();
    // 1. Read the current DACL. `_sd` owns the buffer `old`/`kept`
    //    point into; it's freed after step 4's write.
    let (_sd, old) =
        read_file_dacl(canonical_path).with_context(|| format!("recompose '{canonical_path}'"))?;
    // 2. Collect surviving explicit ACEs (drop inherited and any
    //    explicit ACE whose SID == sandbox_sid — allow AND deny).
    let kept = filter_aces(old, |hdr, body| {
        hdr.AceFlags & INHERITED_ACE == 0 && !ace_sid_is(body, sid_bytes)
    })?;
    // 3. Build fresh ACL: set's entries (deny-first canonical order)
    //    then surviving explicit ACEs.
    let new = rebuild_acl(kept.src_rev, &set.head_aces(sid.as_psid()), &kept, &[])?;
    // 4. Write back. UNPROTECTED so the kernel re-derives inherited
    //    ACEs from the parent.
    write_file_dacl(canonical_path, new.as_ptr(), Protection::Unprotected)
        .with_context(|| format!("recompose '{canonical_path}'"))
}

/// Build + apply the parent allow-list (DACL+marker, `PROTECTED`).
pub fn apply_parent_allow_list(
    canonical_parent_path: &str,
    dacls: &PrebuiltDacls,
    marker: &MarkerHash,
) -> Result<()> {
    let dacl = dacls.parent.build_with_marker(Some(marker))?;
    set_file_dacl_protected(canonical_parent_path, &dacl, "parent allow-list")
}

/// `SECURITY_ATTRIBUTES` for the named init-mutex — broker-only
/// (`<group>`/SYSTEM/Admins) so a sandbox child cannot open it
/// (and therefore cannot stall stamps by sitting on the lock).
/// `GENERIC_ALL` is the kernel-object equivalent of
/// `FILE_ALL_ACCESS`; the kernel resolves it via the mutex's
/// generic mapping at create time.
pub fn build_init_mutex_sa(group_sid: &str) -> Result<OwnedSa> {
    build_allow_dacl(&[
        Allow(group_sid, Mask::GENERIC_ALL, NO_INHERIT),
        Allow(SID_SYSTEM, Mask::GENERIC_ALL, NO_INHERIT),
        Allow(SID_BUILTIN_ADMINS, Mask::GENERIC_ALL, NO_INHERIT),
        Allow::OWNER_RIGHTS,
    ])?
    .into_security_attributes()
}

const INHERITED_ACE: u8 = 0x10;

/// Build a fresh ACL containing only the EXPLICIT (non-`INHERITED_ACE`)
/// ACEs of `src`, preserving their order and bytes. Used by
/// `restore_sd` when the original was unprotected: we pass these as
/// the explicit DACL with `UNPROTECTED` and the kernel re-derives the
/// inherited ACEs. If `src` is purely inherited the result is an
/// empty ACL ("no explicit DACL").
unsafe fn build_explicit_only_acl(src: *mut ACL) -> Result<Vec<u8>> {
    let kept = filter_aces(src, |hdr, _| hdr.AceFlags & INHERITED_ACE == 0)?;
    Ok(rebuild_acl(kept.src_rev, &[], &kept, &[])?.buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_id::canonicalize_path;

    fn ace_count(d: &BuiltAcl) -> u16 {
        // ACL.AceCount is bytes 4–5 (LE u16).
        u16::from_le_bytes([d.buf[4], d.buf[5]])
    }

    #[test]
    fn broker_only_dacl_builds() {
        for mask in [AclMask::ReadDeny, AclMask::WriteDeny] {
            for inherit in [false, true] {
                let d = build_broker_only_dacl(
                    "S-1-5-32-545", // BUILTIN\Users — any valid SID
                    mask,
                    inherit,
                    None,
                )
                .expect("build");
                assert_eq!(d.buf[0], 2, "{mask:?} inherit={inherit}");
                assert!(d.buf.len() >= size_of::<ACL>());
            }
        }
    }

    /// The hash-ACE marker round-trips through the ACL builder and
    /// is recovered by `walk_aces` / `AceView::marker_hash`. Also
    /// pins mask=READ_CONTROL (the mask-0 footgun) and flags=0
    /// (non-inheriting) on the emitted DENY ACE.
    #[test]
    fn marker_ace_round_trip() {
        let h: MarkerHash = std::array::from_fn(|i| i as u8);
        let d = build_broker_only_dacl("S-1-5-21-1-2-3-1004", AclMask::ReadDeny, false, Some(&h))
            .unwrap();
        // 4 broker ACEs + 1 marker.
        assert_eq!(ace_count(&d), 5);
        let aces = walk_aces(d.as_ptr()).unwrap();
        let m: Vec<_> = aces.iter().filter_map(AceView::marker_hash).collect();
        assert_eq!(m, vec![h], "marker hash not recovered");
        let deny = aces
            .iter()
            .find(|a| a.ace_type == ACCESS_DENIED_ACE_TYPE)
            .unwrap();
        assert_eq!(
            deny.mask,
            Mask::READ_CONTROL.bits(),
            "marker mask MUST be READ_CONTROL (mask-0 is silently \
             dropped by SetNamedSecurityInfoW)"
        );
        assert_eq!(deny.ace_flags, 0, "marker must be non-inheriting");
        // String-SID form regression.
        assert!(marker_sid_string(&h).starts_with("S-1-0-50462976-"));
    }

    /// `classify_sd` calibration: any DACL that COULD be a
    /// derivative of a broker stamp routes to a fail-closed class,
    /// NEVER `Unstamped` — the safety property that prevents
    /// `original_sd = cur` from overwriting the user's real ACL.
    #[test]
    fn classify_sd_calibration() {
        let g = "S-1-5-21-1-2-3-1003";
        let u = "S-1-5-21-1-2-3-1000";
        let calib = PrebuiltDacls::build(g, u).unwrap().calib;
        // Hand-roll a self-relative SD: Rev(1) Sbz1(1) Control(2)
        // Owner(4) Group(4) Sacl(4) Dacl(4) = 20B header + ACL.
        let sd_of = |d: &BuiltAcl, control: u16| -> CapturedSd {
            let mut sd = vec![0u8; 20 + d.buf.len()];
            sd[0] = 1;
            sd[2..4].copy_from_slice(&control.to_le_bytes());
            sd[16..20].copy_from_slice(&20u32.to_le_bytes());
            sd[20..].copy_from_slice(&d.buf);
            CapturedSd(sd)
        };
        // SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED.
        const PROT: u16 = 0x9004;
        const UNPROT: u16 = 0x8004;
        let h: MarkerHash = [7u8; 32];
        // File(ReadDeny) with marker.
        let rd = build_broker_only_dacl(g, AclMask::ReadDeny, false, Some(&h)).unwrap();
        assert_eq!(
            classify_sd(&sd_of(&rd, PROT), &calib).unwrap(),
            StampClass::File(AclMask::ReadDeny, h)
        );
        // ParentAllowList with marker.
        let p = build_parent_allow_list_dacl(g, u, Some(&h)).unwrap();
        assert_eq!(
            classify_sd(&sd_of(&p, PROT), &calib).unwrap(),
            StampClass::ParentAllowList(h)
        );
        // Broker shape, NO marker → StampedUnrecognized (NEVER
        // Unstamped — the marker-stripped fail-closed case).
        let nm = build_broker_only_dacl(g, AclMask::WriteDeny, false, None).unwrap();
        assert_eq!(
            classify_sd(&sd_of(&nm, PROT), &calib).unwrap(),
            StampClass::StampedUnrecognized
        );
        // Marker present but shape drifted (a stamp from a
        // DIFFERENT group SID) → StampedUnrecognized (NEVER
        // Unstamped — the marker is unforgeable).
        let foreign =
            build_broker_only_dacl("S-1-5-21-9-9-9-9009", AclMask::ReadDeny, false, Some(&h))
                .unwrap();
        assert_eq!(
            classify_sd(&sd_of(&foreign, PROT), &calib).unwrap(),
            StampClass::StampedUnrecognized
        );
        // NOT PROTECTED → always Unstamped, even when the
        // (inherited) ACEs happen to match a broker shape.
        assert_eq!(
            classify_sd(&sd_of(&nm, UNPROT), &calib).unwrap(),
            StampClass::Unstamped
        );
        // Anything else (no marker, no shape match) → Unstamped.
        let other = build_allow_dacl(&[Allow("S-1-5-32-545", Mask::FILE_GENERIC_READ, NO_INHERIT)])
            .unwrap();
        assert_eq!(
            classify_sd(&sd_of(&other, PROT), &calib).unwrap(),
            StampClass::Unstamped
        );
    }

    /// IsolatedDesk's `[broker, sb, SY]:GA` DACL — 3 ACEs,
    /// revision 2, GENERIC_ALL on each. Regression for the
    /// `KeptAces`/`rebuild_acl` chokepoint: a sizing or revision
    /// bug here breaks the SandboxUser desktop attach (R1 hang).
    #[test]
    fn isolated_desk_dacl_shape() {
        let d = build_allow_dacl(&[
            Allow("S-1-5-21-1-2-3-1000", Mask::GENERIC_ALL, NO_INHERIT),
            Allow("S-1-5-21-1-2-3-1004", Mask::GENERIC_ALL, NO_INHERIT),
            Allow(SID_SYSTEM, Mask::GENERIC_ALL, NO_INHERIT),
        ])
        .unwrap();
        assert_eq!(d.buf[0], 2, "AclRevision");
        assert_eq!(ace_count(&d), 3);
        let aces = walk_aces(d.as_ptr()).unwrap();
        for a in &aces {
            assert_eq!(a.ace_type, 0, "ACCESS_ALLOWED_ACE_TYPE");
            assert_eq!(a.mask, Mask::GENERIC_ALL.bits());
            assert_eq!(a.ace_flags, 0);
        }
    }

    #[test]
    fn build_allow_dacl_dedup() {
        // Same SID twice (case-insensitive) → 1 ACE; first wins.
        let d = build_allow_dacl(&[
            Allow(SID_BUILTIN_ADMINS, Mask::FILE_ALL, NO_INHERIT),
            Allow("s-1-5-32-544", Mask::FILE_READ_EXEC, NO_INHERIT),
        ])
        .unwrap();
        assert_eq!(ace_count(&d), 1);
    }

    #[test]
    fn broker_only_dacl_dedups_admins() {
        // group == Admins → 3 ACEs (group/SYSTEM/OWNER_RIGHTS), not 4.
        let with =
            build_broker_only_dacl(SID_BUILTIN_ADMINS, AclMask::ReadDeny, false, None).unwrap();
        let without =
            build_broker_only_dacl("S-1-5-32-545", AclMask::ReadDeny, false, None).unwrap();
        assert_eq!(ace_count(&with), 3);
        assert_eq!(ace_count(&without), 4);
    }

    #[test]
    fn aclmask_round_trip() {
        for m in [AclMask::ReadDeny, AclMask::WriteDeny] {
            assert_eq!(AclMask::parse(m.as_str()).unwrap(), m);
        }
        assert!(AclMask::parse("nope").is_err());
    }

    #[test]
    fn init_mutex_sa_builds() {
        for g in [SID_BUILTIN_ADMINS, "S-1-5-21-1-2-3-1004"] {
            let sa = build_init_mutex_sa(g).unwrap_or_else(|e| panic!("{g}: {e:#}"));
            assert!(!sa.as_ptr().is_null());
            // BA-dedup: 3 ACEs when group == Admins, else 4.
            let want = if g == SID_BUILTIN_ADMINS { 3 } else { 4 };
            assert_eq!(ace_count(&sa._acl), want, "group={g}");
        }
    }

    #[test]
    fn capture_restore_round_trip() {
        // Pick a temp file; capture, restore, capture again — the
        // two captures should be byte-identical (we never stamped,
        // so restore is a no-op-of-the-same-bytes). Skip if the
        // host denies SetNamedSecurityInfoW (non-admin without
        // SeRestorePrivilege on someone else's file) — the temp
        // dir is user-owned so this should pass even non-elevated.
        let tmp = std::env::temp_dir().join(format!("srt-win-acl-rt-{}.tmp", std::process::id()));
        std::fs::write(&tmp, b"x").unwrap();
        let (canon, _) = canonicalize_path(&tmp.display().to_string()).unwrap();
        let before = capture_sd(&canon).unwrap();
        if let Err(e) = restore_sd(&canon, &before) {
            eprintln!("skipping capture_restore_round_trip: {e}");
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        let after = capture_sd(&canon).unwrap();
        let _ = std::fs::remove_file(&tmp);
        // CapturedSd::equiv masks the OS-set AUTO_INHERITED marker
        // bits.
        assert!(
            before.equiv(&after),
            "before/after differ beyond the AI bits:\n  {:02x?}\n  {:02x?}",
            before.as_bytes(),
            after.as_bytes()
        );
    }

    /// Pin the load-bearing `Mask` consts. `MODIFY_NO_FDC` is now
    /// composed via `.with()/.without()` so a hex typo is
    /// impossible at the definition site, but pin its value (and
    /// the absence of `FILE_DELETE_CHILD` / presence of `DELETE`)
    /// so a change to one of the constituent consts is caught.
    /// `Allow::OWNER_RIGHTS.1` is the only spellable OWNER_RIGHTS
    /// mask; pin it non-zero and `WRITE_DAC`-free.
    #[test]
    fn mask_consts_regression() {
        let m = Mask::MODIFY_NO_FDC;
        assert_eq!(m.bits(), 0x0013_01bf);
        assert_ne!(m.bits() & Mask::DELETE.bits(), 0, "must carry DELETE");
        assert_eq!(m.bits() & Mask::FILE_DELETE_CHILD.bits(), 0);
        assert_eq!(m.bits() & 0xffe0_0000, 0, "stray high bits");

        let ow = Allow::OWNER_RIGHTS.1;
        assert_eq!(ow.bits(), Mask::READ_CONTROL.bits());
        assert_ne!(ow.bits(), 0);
        assert_eq!(ow.bits() & Mask::WRITE_DAC.bits(), 0);
    }

    /// `build_parent_allow_list_dacl` includes the `OWNER_RIGHTS`
    /// ACE. Regression: a mask-0 ACE is silently dropped by
    /// `SetNamedSecurityInfoW`; the builder must emit a non-zero
    /// `OWNER_RIGHTS` ACE in the buffer.
    #[test]
    fn parent_allow_list_dacl_builds_with_owner_rights() {
        for (group, want_aces) in [
            // group == Admins → BA dedup → 4 ACEs.
            (SID_BUILTIN_ADMINS, 4u16),
            // group ≠ Admins → 5 ACEs.
            ("S-1-5-21-1-2-3-1003", 5),
        ] {
            let d =
                build_parent_allow_list_dacl(group, "S-1-5-21-1-2-3-1000", None).expect("build");
            assert_eq!(ace_count(&d), want_aces, "group={group}");
            // S-1-3-4 (OWNER_RIGHTS) in binary: rev=01
            // subauth-count=01 idauth=000000000003
            // subauth[0]=04000000.
            const OW: [u8; 12] = [
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04, 0x00, 0x00, 0x00,
            ];
            assert!(
                d.buf.windows(OW.len()).any(|w| w == OW),
                "OWNER_RIGHTS SID missing from parent DACL bytes \
                 (group={group})"
            );
        }
    }

    #[test]
    fn captured_sd_equiv_masks_auto_inherited_only() {
        let sd = |v: &[u8]| CapturedSd::from(v.to_vec());
        // Identical → equiv.
        let a = sd(&[1, 0, 0x04, 0x80, 9, 9]);
        assert!(a.equiv(&a));
        assert_eq!(a.control(), 0x8004);
        // SE_DACL_AUTO_INHERITED (0x0400 → byte[3] |= 0x04) → equiv.
        let b = sd(&[1, 0, 0x04, 0x84, 9, 9]);
        assert_eq!(b.control(), 0x8404);
        assert!(a.equiv(&b));
        // SE_SACL_AUTO_INHERITED (0x0800 → byte[3] |= 0x08) → equiv.
        assert!(a.equiv(&sd(&[1, 0, 0x04, 0x88, 9, 9])));
        // Any other Control bit (e.g. SE_DACL_PROTECTED 0x1000 →
        // byte[3] |= 0x10) → NOT equiv.
        assert!(!a.equiv(&sd(&[1, 0, 0x04, 0x90, 9, 9])));
        // Body byte differs → NOT equiv.
        assert!(!a.equiv(&sd(&[1, 0, 0x04, 0x80, 9, 0])));
        // Length differs → NOT equiv.
        assert!(!a.equiv(&sd(&[1, 0, 0x04, 0x80, 9])));
    }
}
