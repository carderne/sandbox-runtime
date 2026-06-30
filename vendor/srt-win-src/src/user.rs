//! Sandbox user account lifecycle.
//!
//! `srt-win install` provisions a dedicated local user
//! ([`SANDBOX_USER`]) and a local group ([`SANDBOX_GROUP`]) that
//! holds it. The sandboxed child will eventually run **as that
//! user** (via `CreateProcessWithLogonW` from a non-elevated
//! broker), so its token carries a different user SID, a fresh
//! logon session, and is NOT a member of the discriminator group —
//! which structurally closes the surrogate-spawn class (schtasks,
//! `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS, RunAs="Interactive
//! User" COM) that a same-user deny-only-group token cannot.
//!
//! This module is the **provisioning** half only: create/delete the
//! account, set/rotate its password, hide it from the logon UI, and
//! report status. The runner that actually launches the child under
//! this account is a separate, later piece.
//!
//! ## Why a group AND a user
//!
//! [`SANDBOX_GROUP`] is the trustee for the credential-file DENY ACE
//! and (later) the working-tree grant. Keying those on the *group*
//! rather than the user SID means a future multi-account design
//! (e.g. per-session sandbox users) only adds members; the DACLs
//! and WFP filters don't change. It is **distinct** from the
//! discriminator group (`sandbox-runtime-net`) — the real user is a
//! member of *that* one, the sandbox user is a member of *this* one,
//! and never both.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::ffi::c_void;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserAdd, NetUserDel, NetUserGetInfo,
    NetUserSetInfo, NERR_UserExists, NERR_UserNotFound,
    UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_INFO_1003,
    USER_INFO_1008, USER_PRIV_USER,
};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_DWORD,
};
use windows::Win32::UI::Shell::DeleteProfileW;

use crate::util::{pcwstr, wstr};
use crate::{sam, sid};

/// The dedicated local account the sandboxed child runs as.
pub const SANDBOX_USER: &str = "srt-sandbox";

/// Local group that holds [`SANDBOX_USER`]. Trustee for the
/// credential-file DENY ACE — distinct from the discriminator
/// group `sandbox-runtime-net` (which holds the *real* user).
pub const SANDBOX_GROUP: &str = "sandbox-runtime-users";

/// Result of [`provision`] — the password is returned in clear so
/// the caller can DPAPI-encrypt and persist it; it is not stored
/// anywhere by this module.
#[derive(Debug)]
pub struct ProvisionedUser {
    pub username: String,
    /// `S-1-5-21-…` of [`SANDBOX_USER`].
    pub sid: String,
    /// `S-1-5-21-…` of [`SANDBOX_GROUP`].
    pub group_sid: String,
    /// 32 chars, freshly generated on every [`provision`] call (so
    /// re-running install rotates it).
    pub password: String,
}

/// Result of [`status`]. Every field is independently observed so a
/// half-provisioned state (e.g. user exists but not in the group) is
/// surfaced rather than collapsed to a single boolean.
#[derive(Debug, Serialize)]
pub struct UserStatus {
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub group_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_sid: Option<String>,
    /// In `BUILTIN\Users` — required for interactive logon rights.
    pub in_builtin_users: bool,
    /// In [`SANDBOX_GROUP`].
    pub in_sandbox_group: bool,
    /// Winlogon `SpecialAccounts\UserList\srt-sandbox` = 0.
    pub hidden_from_logon: bool,
}

const WINLOGON_USERLIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

/// `BUILTIN\Users` — well-known SID that's stable across locales,
/// unlike the *name* "Users" / "Benutzer" / "Utilisateurs".
const SID_BUILTIN_USERS: &str = "S-1-5-32-545";

/// Create [`SANDBOX_GROUP`] and [`SANDBOX_USER`] (idempotent), set a
/// fresh random password (rotated if the user already exists), add
/// the user to `BUILTIN\Users` and [`SANDBOX_GROUP`], hide it from
/// the Winlogon user-picker, and return both SIDs plus the password.
///
/// Requires elevation (NetUserAdd → `ERROR_ACCESS_DENIED` otherwise).
pub fn provision() -> Result<ProvisionedUser> {
    let password = gen_password().context("generate sandbox password")?;

    sam::ensure_local_group(
        SANDBOX_GROUP, "sandbox-runtime sandbox-user group",
    )?;
    ensure_user(SANDBOX_USER, &password)?;

    // Resolve the freshly-created user's SID so group membership is
    // added by PSID — see [`sam::add_member`].
    let sid = sid::lookup_account_sid(SANDBOX_USER)
        .context("resolve sandbox user SID")?;
    let user_psid = sid::LocalPsid::from_string(&sid)?;

    // BUILTIN\Users membership is required for the account to hold
    // the interactive-logon right that `CreateProcessWithLogonW`
    // depends on. Resolve the **localised** group name from the
    // well-known SID so this works on non-English Windows.
    let builtin_users = sid::lookup_account_name(SID_BUILTIN_USERS)
        .context("resolve BUILTIN\\Users name")?;
    sam::add_member(&builtin_users, &user_psid)?;
    sam::add_member(SANDBOX_GROUP, &user_psid)?;

    set_logon_ui_hidden(SANDBOX_USER, true)?;

    let group_sid = sid::lookup_account_sid(SANDBOX_GROUP)
        .context("resolve sandbox group SID")?;
    Ok(ProvisionedUser {
        username: SANDBOX_USER.into(),
        sid,
        group_sid,
        password,
    })
}

/// Delete [`SANDBOX_USER`]'s roaming/local profile (best-effort),
/// the account itself, [`SANDBOX_GROUP`], and the Winlogon hide
/// value. Idempotent — every step tolerates already-absent state.
pub fn deprovision() -> Result<()> {
    // Profile delete needs the SID *string*; resolve before
    // NetUserDel removes the SAM mapping. Failure to resolve (user
    // already gone) is fine — no profile to delete.
    if let Ok(s) = sid::lookup_account_sid(SANDBOX_USER) {
        let sid_w = wstr(&s);
        // Best-effort: profile may never have been created (no
        // `LOGON_WITH_PROFILE` yet), or may be locked by a stuck
        // child. Either way the account delete below still works.
        unsafe {
            let _ = DeleteProfileW(
                pcwstr(&sid_w),
                PCWSTR::null(),
                PCWSTR::null(),
            );
        }
    }
    let user_w = wstr(SANDBOX_USER);
    let rc = unsafe { NetUserDel(PCWSTR::null(), pcwstr(&user_w)) };
    if rc != 0 && rc != NERR_UserNotFound {
        return Err(anyhow!("NetUserDel({SANDBOX_USER}): {rc}"));
    }
    sam::delete_local_group(SANDBOX_GROUP)?;
    // Best-effort: the key may never have been created.
    let _ = set_logon_ui_hidden(SANDBOX_USER, false);
    Ok(())
}

/// Observe each piece of the provisioned state independently. Does
/// not require elevation.
pub fn status() -> Result<UserStatus> {
    let sid = sid::lookup_account_sid(SANDBOX_USER).ok();
    let group_sid = sid::lookup_account_sid(SANDBOX_GROUP).ok();
    let in_builtin_users = sid
        .as_deref()
        .map(|s| sam::is_member_of(SID_BUILTIN_USERS, s))
        .transpose()?
        .unwrap_or(false);
    let in_sandbox_group = match (&sid, &group_sid) {
        (Some(u), Some(g)) => sam::is_member_of(g, u)?,
        _ => false,
    };
    Ok(UserStatus {
        exists: sid.is_some(),
        sid,
        group_exists: group_sid.is_some(),
        group_sid,
        in_builtin_users,
        in_sandbox_group,
        hidden_from_logon: is_logon_ui_hidden(SANDBOX_USER),
    })
}

// ────────────────────── internals ──────────────────────

/// 32 characters drawn uniformly from an 85-symbol alphabet via
/// `BCryptGenRandom` (system CSPRNG). Excludes characters that
/// quoting layers between here and `CreateProcessWithLogonW` are
/// known to mishandle (`"`, `\`, ``` ` ```, whitespace) and the
/// shell-special `&|<>^` set, so the password survives any cmd /
/// PowerShell relay the runner spec may go through. ≈ 32 × log₂ 85
/// ≈ 205 bits; Windows local-account max length is 127.
fn gen_password() -> Result<String> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789!#$%()*+,-./:;=?@[]_{}~";
    const N: usize = 32;
    const { assert!(ALPHA.len() == 85) };
    let mut raw = [0u8; N];
    let st = unsafe {
        BCryptGenRandom(None, &mut raw, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    if st.0 != 0 {
        return Err(anyhow!("BCryptGenRandom: NTSTATUS=0x{:08x}", st.0));
    }
    // Rejection sample so each output byte is a uniform pick from
    // ALPHA (85 doesn't divide 256). One refill is overwhelmingly
    // enough — the loop is a correctness backstop, not a hot path.
    let bound = (u8::MAX - (u8::MAX % ALPHA.len() as u8)) as usize;
    let mut out = String::with_capacity(N);
    let mut i = 0usize;
    while out.len() < N {
        if i == raw.len() {
            let st = unsafe {
                BCryptGenRandom(
                    None, &mut raw, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if st.0 != 0 {
                return Err(anyhow!(
                    "BCryptGenRandom (refill): NTSTATUS=0x{:08x}",
                    st.0
                ));
            }
            i = 0;
        }
        let b = raw[i] as usize;
        i += 1;
        if b < bound {
            out.push(ALPHA[b % ALPHA.len()] as char);
        }
    }
    Ok(out)
}

/// `NetUserAdd(level=1)` if absent; on `NERR_UserExists`,
/// `NetUserSetInfo(level=1003)` to rotate the password and
/// `NetUserSetInfo(level=1008)` to OR `UF_DONT_EXPIRE_PASSWD` into
/// the existing flags. Either way the account ends up with
/// `password` and a non-expiring password — even if an older build
/// or a domain GPO cleared the flag since the previous install.
fn ensure_user(name: &str, password: &str) -> Result<()> {
    let mut name_w = wstr(name);
    let mut pw_w = wstr(password);
    let mut comment_w = wstr("sandbox-runtime sandboxed-child account");
    let info = USER_INFO_1 {
        usri1_name: PWSTR(name_w.as_mut_ptr()),
        usri1_password: PWSTR(pw_w.as_mut_ptr()),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: PWSTR::null(),
        usri1_comment: PWSTR(comment_w.as_mut_ptr()),
        // UF_SCRIPT is required by SAM on workstation SKUs (legacy
        // LAN-Manager flag); without it NetUserAdd returns
        // NERR_BadUsername / ERROR_INVALID_PARAMETER.
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
        usri1_script_path: PWSTR::null(),
    };
    let rc = unsafe {
        NetUserAdd(
            PCWSTR::null(), 1, &info as *const _ as *const u8, None,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    if rc != NERR_UserExists {
        return Err(anyhow!("NetUserAdd({name}): {rc}"));
    }
    // Already exists — rotate the password so the credential file
    // about to be (re)written matches.
    let info1003 = USER_INFO_1003 {
        usri1003_password: PWSTR(pw_w.as_mut_ptr()),
    };
    let rc = unsafe {
        NetUserSetInfo(
            PCWSTR::null(),
            pcwstr(&name_w),
            1003,
            &info1003 as *const _ as *const u8,
            None,
        )
    };
    if rc != 0 {
        return Err(anyhow!(
            "NetUserSetInfo({name}, level=1003 password rotate): {rc}"
        ));
    }
    // Re-assert UF_DONT_EXPIRE_PASSWD: read level-1 flags, OR in,
    // write back via level-1008 (flags only — level-1 SetInfo would
    // overwrite priv/home_dir/comment).
    let mut buf: *mut u8 = std::ptr::null_mut();
    let rc = unsafe {
        NetUserGetInfo(PCWSTR::null(), pcwstr(&name_w), 1, &mut buf)
    };
    if rc != 0 {
        return Err(anyhow!("NetUserGetInfo({name}, level=1): {rc}"));
    }
    let cur_flags = unsafe { (*(buf as *const USER_INFO_1)).usri1_flags };
    unsafe {
        let _ = NetApiBufferFree(Some(buf as *const c_void));
    }
    let info1008 = USER_INFO_1008 {
        usri1008_flags: cur_flags | UF_DONT_EXPIRE_PASSWD,
    };
    let rc = unsafe {
        NetUserSetInfo(
            PCWSTR::null(),
            pcwstr(&name_w),
            1008,
            &info1008 as *const _ as *const u8,
            None,
        )
    };
    if rc != 0 {
        return Err(anyhow!(
            "NetUserSetInfo({name}, level=1008 flags): {rc}"
        ));
    }
    Ok(())
}

/// Write (or delete) `HKLM\…\Winlogon\SpecialAccounts\UserList\<user>
/// = 0` so the account doesn't appear on the lock-screen user
/// picker. Cosmetic only — the account is still fully usable via
/// `CreateProcessWithLogonW`.
fn set_logon_ui_hidden(user: &str, hide: bool) -> Result<()> {
    if hide {
        crate::util::reg_set_value(
            HKEY_LOCAL_MACHINE,
            WINLOGON_USERLIST,
            user,
            REG_DWORD,
            &0u32.to_ne_bytes(),
        )?;
    } else {
        let sub_w = wstr(WINLOGON_USERLIST);
        let val_w = wstr(user);
        let mut hkey = HKEY::default();
        // Open (not create) — if the key was never made there's
        // nothing to delete.
        let r = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                pcwstr(&sub_w),
                None,
                KEY_SET_VALUE,
                &mut hkey,
            )
        };
        if r.is_err() {
            return Ok(());
        }
        unsafe {
            let _ = RegDeleteValueW(hkey, pcwstr(&val_w));
            let _ = RegCloseKey(hkey);
        }
    }
    Ok(())
}

fn is_logon_ui_hidden(user: &str) -> bool {
    let sub_w = wstr(WINLOGON_USERLIST);
    let val_w = wstr(user);
    let mut hkey = HKEY::default();
    let r = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            pcwstr(&sub_w),
            None,
            KEY_READ,
            &mut hkey,
        )
    };
    if r.is_err() {
        return false;
    }
    let mut data = [0u8; 4];
    let mut cb: u32 = 4;
    let r = unsafe {
        RegQueryValueExW(
            hkey,
            pcwstr(&val_w),
            None,
            None,
            Some(data.as_mut_ptr()),
            Some(&mut cb),
        )
    };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    // Hidden iff the value exists AND is 0 (a value of 1 explicitly
    // shows the account; absence = default = shown).
    r != ERROR_FILE_NOT_FOUND
        && r.is_ok()
        && cb == 4
        && u32::from_ne_bytes(data) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_shape() {
        let p = gen_password().expect("gen");
        assert_eq!(p.len(), 32);
        assert!(p.is_ascii());
        // No characters from the excluded set.
        for c in ['"', '\\', '`', ' ', '&', '|', '<', '>', '^'] {
            assert!(!p.contains(c), "password contains '{c}': {p}");
        }
        // Two calls differ (overwhelmingly).
        assert_ne!(p, gen_password().unwrap());
    }

    #[test]
    fn builtin_users_name_resolves() {
        // The exact name is locale-dependent; just check it's
        // non-empty and round-trips back to the well-known SID.
        let name =
            sid::lookup_account_name(SID_BUILTIN_USERS).expect("name");
        assert!(!name.is_empty());
        let back = sid::lookup_account_sid(&name).expect("sid");
        assert_eq!(back, SID_BUILTIN_USERS);
    }

    #[test]
    fn status_for_absent_user_is_falsey() {
        // The CI smoke installs/uninstalls under the real names, so
        // here we only sanity-check that status() doesn't error and
        // its booleans agree with `exists`.
        let st = status().expect("status");
        if !st.exists {
            assert!(st.sid.is_none());
            assert!(!st.in_builtin_users);
            assert!(!st.in_sandbox_group);
        }
    }
}
