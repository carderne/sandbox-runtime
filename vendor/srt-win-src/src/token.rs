//! Restricted-token construction for the deny-only-group sandbox.
//!
//! Token shape:
//!   - `SidsToDisable = [<group_sid>, BUILTIN\Administrators]` — flips
//!     them to `SE_GROUP_USE_FOR_DENY_ONLY` without touching the
//!     restricting list.
//!   - `LUA_TOKEN` flag — token reads as a normal limited-user token
//!     to NT components.
//!   - All privileges deleted except `SeChangeNotifyPrivilege`.
//!   - Integrity Level = Medium (same as a normal user process).
//!   - No `RestrictingSids` array — that breaks Schannel/LSA RPC.
//!
//! WFP's `ALE_USER_ID` AccessCheck honours
//! `SE_GROUP_USE_FOR_DENY_ONLY`, so an SDDL ACE
//! `(A;;CC;;;<group_sid>)` matches only when the group is *enabled*
//! — i.e. on the broker, never on the sandbox child.

use anyhow::{Context, Result, anyhow};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::{
    ACL_REVISION, AllocateAndInitializeSid, CreateRestrictedToken, DuplicateTokenEx, FreeSid,
    GetLengthSid, GetTokenInformation, LUA_TOKEN, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, PSID,
    SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY, SecurityImpersonation, SetTokenInformation,
    TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_USER, TokenDefaultDacl, TokenGroups,
    TokenIntegrityLevel, TokenPrimary, TokenPrivileges, TokenUser,
};
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::acl::{KeptAces, NO_INHERIT, NewAce, rebuild_acl};
use crate::sid::LocalPsid;
use crate::util::{pcwstr, wstr};

/// Medium IL (`SECURITY_MANDATORY_MEDIUM_RID`). The sandbox child
/// runs at Medium — same as normal user processes — so Schannel /
/// LSA / registry edge cases that fire at Low IL don't apply.
pub const IL_MEDIUM: u32 = 0x2000;

/// `BUILTIN\Administrators`. Always added to `SidsToDisable` so an
/// elevated broker still produces a non-admin child.
const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";

/// `SE_GROUP_INTEGRITY` attribute (winnt.h). Required on the
/// `TOKEN_MANDATORY_LABEL.Label.Attributes` field.
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

/// Every `SE_GROUP_LOGON_ID` SID in `token`'s `TokenGroups`, copied
/// into owned byte buffers (each is a self-relative SID; cast
/// `.as_ptr()` to `PSID` for Win32 calls). `SE_GROUP_LOGON_ID` is a
/// 2-bit value (`0xC000_0000`); both bits are required, not `!= 0`.
fn logon_sids_of(token: HANDLE) -> Result<Vec<Vec<u8>>> {
    let buf = get_token_info(token, TokenGroups)?;
    unsafe {
        let tg = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        Ok(
            std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize)
                .iter()
                .filter(|g| g.Attributes & (SE_GROUP_LOGON_ID as u32) == SE_GROUP_LOGON_ID as u32)
                .map(|g| {
                    let len = GetLengthSid(g.Sid) as usize;
                    std::slice::from_raw_parts(g.Sid.0 as *const u8, len).to_vec()
                })
                .collect(),
        )
    }
}

/// Open this process's primary token with full access.
pub fn open_self_token() -> Result<HANDLE> {
    unsafe {
        let mut h = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut h)
            .context("OpenProcessToken")?;
        Ok(h)
    }
}

/// Build the restricted child token from `base`. When `flip_group`
/// is `Some(sid)`, that SID is added to `SidsToDisable` alongside
/// `BUILTIN\Administrators` — the deny-only-group shape. When
/// `None` (the separate-sandbox-user runner path), Administrators +
/// every `SE_GROUP_LOGON_ID` SID in `base` is disabled instead — the
/// logon-SID strip is what stops the child reading same-session
/// real-user process memory; the broker compensates with
/// [`crate::winsta::grant_sandbox_on_session_bno`]. Returns a
/// non-primary token; the caller duplicates to primary via
/// [`to_primary`].
pub fn make_sandbox_token(base: HANDLE, flip_group: Option<&str>) -> Result<HANDLE> {
    // SIDs to disable. `LocalPsid` is RAII over
    // `ConvertStringSidToSidW` and frees with `LocalFree` on drop —
    // the donor used raw `PSID` + `FreeSid` here, which is the wrong
    // free fn for that allocator.
    //
    // CI uses `flip_group == Some(BUILTIN\Administrators)` (the only
    // SID that's both on the runner's token without a logout AND
    // discriminator-shaped). Dedup so `CreateRestrictedToken`
    // doesn't see the same SID twice in `SidsToDisable`.
    let group;
    let logon_sids;
    let admins = LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
    let mut psids: Vec<PSID> = vec![admins.as_psid()];
    match flip_group {
        Some(gsid) if !gsid.eq_ignore_ascii_case(SID_BUILTIN_ADMINS) => {
            group = LocalPsid::from_string(gsid)
                .with_context(|| format!("parse group SID '{gsid}'"))?;
            psids.push(group.as_psid());
        }
        Some(_) => {}
        None => {
            // `SandboxUser`: disable every logon-session SID.
            // `logon_sids` owns the bytes and must outlive
            // `CreateRestrictedToken`.
            logon_sids = logon_sids_of(base)?;
            psids.extend(logon_sids.iter().map(|s| PSID(s.as_ptr() as *mut c_void)));
        }
    }
    let disable: Vec<SID_AND_ATTRIBUTES> = psids
        .into_iter()
        .map(|s| SID_AND_ATTRIBUTES {
            Sid: s,
            Attributes: 0,
        })
        .collect();

    // Privileges to delete: everything in `base` except
    // SeChangeNotifyPrivilege.
    let to_delete = privileges_except(base, &["SeChangeNotifyPrivilege"])?;

    let mut out = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            base,
            LUA_TOKEN,
            Some(&disable),
            if to_delete.is_empty() {
                None
            } else {
                Some(&to_delete)
            },
            None, // RestrictingSids — intentionally empty
            &mut out,
        )
        .with_context(|| {
            format!(
                "CreateRestrictedToken(disable=[Admins{}])",
                flip_group
                    .map(|g| format!(",{g}"))
                    .unwrap_or_else(|| ",logon-SIDs".into()),
            )
        })?;
    }
    // `admins` / `group` / `logon_sids` (which back the disable-array
    // PSIDs) drop here.

    // RAII-own `out` so a `?` from set_il/set_default_dacl below
    // closes it.
    let guard = crate::util::OwnedHandle(out);
    set_il(guard.raw(), IL_MEDIUM)?;
    set_default_dacl(guard.raw(), base)?;
    Ok(guard.into_raw())
}

/// Duplicate to a primary token (`CreateProcessAsUserW` requires a
/// primary).
pub fn to_primary(token: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut out = HANDLE::default();
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut out,
        )
        .context("DuplicateTokenEx(primary)")?;
        Ok(out)
    }
}

/// Set the token's integrity level via a mandatory-label SID built
/// with `AllocateAndInitializeSid` (so [`FreeSid`] is the correct
/// release fn — the one place in this crate where it is).
fn set_il(tok: HANDLE, rid: u32) -> Result<()> {
    unsafe {
        let ml_auth = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        };
        let mut sid = PSID::default();
        AllocateAndInitializeSid(&ml_auth, 1, rid, 0, 0, 0, 0, 0, 0, 0, &mut sid)
            .context("AllocateAndInitializeSid(mandatory label)")?;
        let tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        let r = SetTokenInformation(
            tok,
            TokenIntegrityLevel,
            &tml as *const _ as *const c_void,
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid),
        );
        // Free regardless of outcome.
        FreeSid(sid);
        r.context("SetTokenInformation(IntegrityLevel)")?;
        Ok(())
    }
}

/// Rewrite the token's default DACL so objects the child *creates*
/// (process, thread, mutex, …) are accessible to SYSTEM and to
/// `base`'s **user** SID. The donor leaked the SYSTEM SID here; this
/// version uses [`LocalPsid`] so it's freed on return.
///
/// Keyed on the user SID, NOT the logon SID. Under
/// `LaunchMode::SandboxUser` every `SE_GROUP_LOGON_ID` SID in the
/// child token is deny-only (see [`make_sandbox_token`]'s `None`
/// path), so a logon-SID ALLOW ACE here would never grant — the
/// child couldn't open its own created objects, and `cmd.exe` /
/// conhost initialisation hangs. The user SID is enabled in the
/// child token under BOTH launch modes (the child IS that user), and
/// siblings inside the sandbox share it, so the user-SID grant
/// covers parallel-build workers opening each other's
/// pipes/mutexes too.
fn set_default_dacl(tok: HANDLE, base: HANDLE) -> Result<()> {
    let system = LocalPsid::from_string("S-1-5-18")?;
    let user_buf = get_token_info(base, TokenUser)?;
    let user = unsafe { (*(user_buf.as_ptr() as *const TOKEN_USER)).User.Sid };

    // GENERIC_ALL.
    const GENERIC_ALL: u32 = 0x1000_0000;
    let head = [
        NewAce::Allow(system.as_psid(), GENERIC_ALL, NO_INHERIT),
        NewAce::Allow(user, GENERIC_ALL, NO_INHERIT),
    ];
    let built = rebuild_acl(ACL_REVISION, &head, &KeptAces::EMPTY, &[])
        .context("rebuild_acl(default DACL)")?;
    let tdd = TOKEN_DEFAULT_DACL {
        DefaultDacl: built.as_ptr() as *mut _,
    };
    unsafe {
        SetTokenInformation(
            tok,
            TokenDefaultDacl,
            &tdd as *const _ as *const c_void,
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
        .context("SetTokenInformation(DefaultDacl)")?;
    }
    // `built`, `user_buf` (which backs `user`) and `system` drop here.
    Ok(())
}

fn get_token_info(tok: HANDLE, cls: TOKEN_INFORMATION_CLASS) -> Result<Vec<u8>> {
    unsafe {
        let mut len = 0u32;
        let _ = GetTokenInformation(tok, cls, None, 0, &mut len);
        if len == 0 {
            return Err(anyhow!("GetTokenInformation({cls:?}) sizing returned 0"));
        }
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(
            tok,
            cls,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
        .with_context(|| format!("GetTokenInformation({cls:?})"))?;
        Ok(buf)
    }
}

/// Every privilege LUID in `base` except those named in `keep`.
fn privileges_except(base: HANDLE, keep: &[&str]) -> Result<Vec<LUID_AND_ATTRIBUTES>> {
    let keep_luids: Vec<LUID> = keep
        .iter()
        .filter_map(|n| {
            let mut l = LUID::default();
            let w = wstr(n);
            unsafe { LookupPrivilegeValueW(None, pcwstr(&w), &mut l).ok()? };
            Some(l)
        })
        .collect();
    let buf = get_token_info(base, TokenPrivileges)?;
    unsafe {
        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let arr = std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize);
        Ok(arr
            .iter()
            .filter(|p| {
                !keep_luids
                    .iter()
                    .any(|k| k.LowPart == p.Luid.LowPart && k.HighPart == p.Luid.HighPart)
            })
            .map(|p| LUID_AND_ATTRIBUTES {
                Luid: p.Luid,
                Attributes: Default::default(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::CloseHandle;

    #[test]
    fn restricted_token_builds() {
        // Group SID is BUILTIN\Users — always present, so the test
        // doesn't depend on the discriminator group being installed.
        let base = open_self_token().expect("open_self_token");
        let r = make_sandbox_token(base, Some("S-1-5-32-545"));
        unsafe {
            let _ = CloseHandle(base);
        }
        let tok = r.expect("make_sandbox_token");
        let prim = to_primary(tok).expect("to_primary");
        unsafe {
            let _ = CloseHandle(tok);
            let _ = CloseHandle(prim);
        }
    }

    #[test]
    fn privileges_except_keeps_change_notify() {
        let base = open_self_token().expect("open_self_token");
        let to_delete = privileges_except(base, &["SeChangeNotifyPrivilege"]).unwrap();
        // Resolve SeChangeNotifyPrivilege's LUID and assert it's NOT
        // in the deletion set.
        let mut keep = LUID::default();
        let w = wstr("SeChangeNotifyPrivilege");
        unsafe {
            LookupPrivilegeValueW(None, pcwstr(&w), &mut keep).unwrap();
            let _ = CloseHandle(base);
        }
        assert!(
            !to_delete
                .iter()
                .any(|p| p.Luid.LowPart == keep.LowPart && p.Luid.HighPart == keep.HighPart),
            "SeChangeNotifyPrivilege must not be in the deletion set"
        );
    }
}
