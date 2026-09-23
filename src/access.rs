//! Per-site access: an admin may restrict which sites (the local collector, or a remote
//! agent) a user can see or change, on top of their ordinary role (viewer/editor/admin).
//!
//! Grants live in their own `site_access` table (`user_id, site, permission`), one row per
//! (user, site) pair a grant was ever set for, `ON DELETE CASCADE` from `users` — deleting a user
//! now removes their grants as a plain consequence of a foreign key, not a special case
//! `SqliteStore::delete_user` has to filter for by hand. **No grant for a (user, site) pair means
//! full access to it** — installations that never open this page see no change in behaviour, and
//! an admin always sees every site regardless of grants (they already manage the whole install
//! from Settings/Users/Audit).
//!
//! A real failure to read the grants table is **not** treated as "no grants" (which used to mean
//! full access for everyone — the wrong direction to fail open in). `readable`/`writable` deny by
//! default when the store itself cannot answer; only an *absence* of a matching row grants access.

use serde::{Deserialize, Serialize};

use crate::store::Store;

/// `""` stands for the local site (no agent) throughout this module, matching how `Asset.agent_id
/// == None` is already shown as `tr('local')` in the console.
pub const LOCAL_SITE: &str = "";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Read,
    Write,
    None,
}

impl Permission {
    fn parse(s: &str) -> Option<Permission> {
        match s {
            "read" => Some(Permission::Read),
            "write" => Some(Permission::Write),
            "none" => Some(Permission::None),
            _ => None,
        }
    }

    pub fn can_read(self) -> bool {
        !matches!(self, Permission::None)
    }

    pub fn can_write(self) -> bool {
        matches!(self, Permission::Write)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub user_id: i64,
    /// `LOCAL_SITE` (`""`) or an agent id.
    pub site: String,
    pub permission: Permission,
}

/// Every grant on record (every user, every site).
pub fn load_all(store: &dyn Store) -> anyhow::Result<Vec<Grant>> {
    Ok(store
        .site_access_all()?
        .into_iter()
        .filter_map(|(user_id, site, permission)| Permission::parse(&permission).map(|permission| Grant { user_id, site, permission }))
        .collect())
}

/// What `user_id` may do with `site` right now. Admins are never restricted; anyone else with
/// no matching grant has full (read+write) access, same as before this feature existed.
pub fn effective(grants: &[Grant], user_id: i64, role: &str, site: &str) -> Permission {
    if role == "admin" {
        return Permission::Write;
    }
    grants.iter().find(|g| g.user_id == user_id && g.site == site).map(|g| g.permission).unwrap_or(Permission::Write)
}

/// The site a device or event belongs to, as `effective`/`Grant.site` expect it.
pub fn site_of(agent_id: &Option<String>) -> &str {
    agent_id.as_deref().unwrap_or(LOCAL_SITE)
}

/// Convenience wrappers over `load_all` + `effective`, for call sites that only have a `Store`
/// (e.g. inside a `blocking` closure) rather than the web layer's `AppState`. A store error here
/// denies access rather than granting it — the opposite of what `load_all` returning "no grants"
/// on a read failure used to mean.
pub fn readable(store: &dyn Store, user_id: i64, role: &str, agent_id: &Option<String>) -> bool {
    if role == "admin" {
        return true;
    }
    match load_all(store) {
        Ok(grants) => effective(&grants, user_id, role, site_of(agent_id)).can_read(),
        Err(e) => {
            tracing::error!("could not check site access, denying by default: {e:#}");
            false
        }
    }
}

pub fn writable(store: &dyn Store, user_id: i64, role: &str, agent_id: &Option<String>) -> bool {
    if role == "admin" {
        return true;
    }
    match load_all(store) {
        Ok(grants) => effective(&grants, user_id, role, site_of(agent_id)).can_write(),
        Err(e) => {
            tracing::error!("could not check site access, denying by default: {e:#}");
            false
        }
    }
}

/// Replace every grant for one user (a full set from the admin UI). Unrecognised permission
/// strings are rejected; `LOCAL_SITE`/agent ids are not validated against `list_agents` here —
/// the UI only offers ids it knows about, and a grant for a site that later disappears is simply
/// never consulted again.
pub fn set_for_user(store: &dyn Store, user_id: i64, rows: &[(String, String)], _now: i64) -> Result<(), String> {
    for (_, perm) in rows {
        Permission::parse(perm).ok_or_else(|| format!("unknown permission '{perm}'"))?;
    }
    store.site_access_set_for_user(user_id, rows).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;
    use crate::store::AuthStore;

    #[test]
    fn no_grant_is_full_access_and_admins_are_never_restricted() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = store.create_user("u", "x", "viewer", true, 100).unwrap().id;
        let grants = load_all(&store).unwrap();
        assert_eq!(effective(&grants, id, "viewer", LOCAL_SITE), Permission::Write);
        assert_eq!(effective(&grants, id, "admin", "site-a"), Permission::Write); // even with a grant, below
        set_for_user(&store, id, &[("site-a".into(), "none".into())], 100).unwrap();
        let grants = load_all(&store).unwrap();
        assert_eq!(effective(&grants, id, "admin", "site-a"), Permission::Write);
    }

    #[test]
    fn a_grant_restricts_only_that_user_and_that_site() {
        let store = SqliteStore::open_in_memory().unwrap();
        let a = store.create_user("a", "x", "viewer", true, 100).unwrap().id;
        let b = store.create_user("b", "x", "viewer", true, 100).unwrap().id;
        set_for_user(&store, a, &[("site-a".into(), "none".into()), ("site-b".into(), "read".into())], 100).unwrap();
        let grants = load_all(&store).unwrap();
        assert_eq!(effective(&grants, a, "viewer", "site-a"), Permission::None);
        assert_eq!(effective(&grants, a, "viewer", "site-b"), Permission::Read);
        assert_eq!(effective(&grants, a, "viewer", "site-c"), Permission::Write); // no grant: full access
        assert_eq!(effective(&grants, b, "viewer", "site-a"), Permission::Write); // a different user: unaffected
    }

    #[test]
    fn setting_for_a_user_replaces_their_whole_previous_set() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = store.create_user("u", "x", "viewer", true, 100).unwrap().id;
        set_for_user(&store, id, &[("site-a".into(), "read".into())], 100).unwrap();
        set_for_user(&store, id, &[("site-b".into(), "write".into())], 200).unwrap();
        let grants = load_all(&store).unwrap();
        assert_eq!(effective(&grants, id, "viewer", "site-a"), Permission::Write); // cleared
        assert_eq!(effective(&grants, id, "viewer", "site-b"), Permission::Write);
    }

    #[test]
    fn an_unknown_permission_string_is_rejected_and_nothing_is_saved() {
        let store = SqliteStore::open_in_memory().unwrap();
        assert!(set_for_user(&store, 1, &[("site-a".into(), "delete-everything".into())], 100).is_err());
        assert!(load_all(&store).unwrap().is_empty());
    }

    #[test]
    fn read_and_write_permissions_read_can_read() {
        assert!(Permission::Read.can_read() && !Permission::Read.can_write());
        assert!(Permission::Write.can_read() && Permission::Write.can_write());
        assert!(!Permission::None.can_read() && !Permission::None.can_write());
    }

    #[test]
    fn deleting_a_user_removes_their_grants_but_leaves_everyone_elses_alone() {
        let store = SqliteStore::open_in_memory().unwrap();
        let disabled = store.create_user("temp", "x", "viewer", true, 100).unwrap();
        let other = store.create_user("kept", "x", "viewer", true, 100).unwrap();
        set_for_user(&store, disabled.id, &[("site-a".into(), "none".into())], 100).unwrap();
        set_for_user(&store, other.id, &[("site-a".into(), "read".into())], 100).unwrap();
        store.update_user(disabled.id, None, Some(true), None, None).unwrap();

        assert!(store.delete_user(disabled.id).unwrap());

        let grants = load_all(&store).unwrap();
        assert!(grants.iter().all(|g| g.user_id != disabled.id), "{grants:?}");
        assert_eq!(effective(&grants, other.id, "viewer", "site-a"), Permission::Read, "unrelated user's grant survives");
    }
}
