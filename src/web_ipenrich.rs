//! IP enrichment HTTP handlers: the Settings → Network → Network Intelligence box (admin-only
//! configuration), a public-ish status summary (for the Health page and the sign-in-free "About"
//! attribution line DB-IP's CC BY 4.0 licence requires), and the on-demand single-IP lookup the
//! click-through detail panel calls. See `ipenrich/mod.rs` and `IP_ENRICHMENT.md` for the actual
//! enrichment logic — this file is only the HTTP surface over it, same split as `web_ai.rs` is to
//! `ai.rs`.

use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::ipenrich::{self, settings, DnsConfig, GeoipConfig};
use crate::model::now_ts;
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

pub const DB_IP_ATTRIBUTION: &str = ipenrich::geoip::DB_IP_ATTRIBUTION;

/// What every signed-in role may see: is reverse DNS on, is a GeoIP database installed and how
/// current is it — no resolver address, no file paths (those are an admin's business, see `get`).
#[derive(Serialize)]
pub struct PublicStatus {
    pub dns_enabled: bool,
    pub geoip: ipenrich::ProviderStatus,
    pub attribution: &'static str,
}

pub(crate) async fn status(State(st): State<AppState>) -> Json<PublicStatus> {
    Json(PublicStatus { dns_enabled: st.ipenrich.dns_enabled(), geoip: st.ipenrich.geoip_status(), attribution: DB_IP_ATTRIBUTION })
}

#[derive(Serialize)]
pub struct Settings {
    pub dns: DnsConfig,
    pub geoip: GeoipConfig,
    pub cache_geoip_ttl_secs: i64,
    pub cache_dns_ttl_secs: i64,
    /// Never the secret itself — only whether one is already saved, same pattern as every other
    /// stored credential in this codebase (API tokens, channel webhook secrets, provider keys).
    pub custom_api_secret_set: bool,
}

pub(crate) async fn get(State(st): State<AppState>) -> Result<Json<Settings>, ApiError> {
    let (dns, geoip, ttls, secret) = blocking(&st.store, |s| {
        Ok((settings::dns_config(s), settings::geoip_config(s), settings::cache_ttls(s), settings::custom_api_secret(s)))
    })
    .await?;
    Ok(Json(Settings { dns, geoip, cache_geoip_ttl_secs: ttls.geoip_secs, cache_dns_ttl_secs: ttls.dns_secs, custom_api_secret_set: secret.is_some() }))
}

#[derive(Deserialize)]
pub struct PutReq {
    #[serde(default)]
    dns: Option<DnsConfig>,
    #[serde(default)]
    geoip: Option<GeoipConfig>,
    #[serde(default)]
    cache_geoip_ttl_secs: Option<i64>,
    #[serde(default)]
    cache_dns_ttl_secs: Option<i64>,
    /// Blank/absent: leave the stored secret as it is (same "blank means unchanged" convention as
    /// `web_ai.rs`'s keys and every notification channel's webhook secret).
    #[serde(default)]
    custom_api_secret: String,
}

pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PutReq>) -> Result<Response, ApiError> {
    if let Some(dns) = &b.dns {
        if dns.primary.parse::<IpAddr>().is_err() {
            return Ok(err(StatusCode::BAD_REQUEST, "DNS resolver must be an IP address"));
        }
        if let Some(s) = &dns.secondary {
            if !s.is_empty() && s.parse::<IpAddr>().is_err() {
                return Ok(err(StatusCode::BAD_REQUEST, "secondary DNS resolver must be an IP address"));
            }
        }
        if !(100..=30_000).contains(&dns.timeout_ms) {
            return Ok(err(StatusCode::BAD_REQUEST, "timeout must be between 100 and 30000 ms"));
        }
    }
    if let Some(t) = b.cache_geoip_ttl_secs {
        if t < 60 {
            return Ok(err(StatusCode::BAD_REQUEST, "the GeoIP cache TTL must be at least 60 seconds"));
        }
    }
    if let Some(t) = b.cache_dns_ttl_secs {
        if t < 60 {
            return Ok(err(StatusCode::BAD_REQUEST, "the DNS cache TTL must be at least 60 seconds"));
        }
    }
    let now = now_ts();
    let dns_for_service = b.dns.clone();
    let ttl_changed = b.cache_geoip_ttl_secs.is_some() || b.cache_dns_ttl_secs.is_some();
    let geoip_changed = b.geoip.is_some();
    blocking(&st.store, move |s| {
        if let Some(dns) = &b.dns {
            settings::save_dns_config(s, dns, now)?;
        }
        if let Some(geoip) = &b.geoip {
            settings::save_geoip_config(s, geoip, now)?;
        }
        if b.cache_geoip_ttl_secs.is_some() || b.cache_dns_ttl_secs.is_some() {
            let mut ttls = settings::cache_ttls(s);
            if let Some(t) = b.cache_geoip_ttl_secs {
                ttls.geoip_secs = t;
            }
            if let Some(t) = b.cache_dns_ttl_secs {
                ttls.dns_secs = t;
            }
            settings::save_cache_ttls(s, ttls, now)?;
        }
        if !b.custom_api_secret.is_empty() {
            settings::save_custom_api_secret(s, &b.custom_api_secret, now)?;
        }
        Ok(())
    })
    .await?;
    // reflected in the running service immediately, no restart needed — the same "settings take
    // effect within seconds" promise every other config box in this console already makes.
    if let Some(dns) = dns_for_service {
        st.ipenrich.set_dns_config(dns);
    }
    if ttl_changed {
        let ttls = blocking(&st.store, |s| Ok(settings::cache_ttls(s))).await?;
        st.ipenrich.set_ttls(ttls);
    }
    if geoip_changed {
        let db_path = st.shared.db_path.clone();
        let (ipenrich, store) = (st.ipenrich.clone(), st.store.clone());
        blocking(&store, move |s| {
            ipenrich::reconfigure_geoip(&ipenrich, s, &db_path);
            Ok(())
        })
        .await?;
    }
    audit(&st, &me.username, "ipenrich.settings.update", None, json!({}));
    let (dns, geoip, ttls, secret) = blocking(&st.store, |s| Ok((settings::dns_config(s), settings::geoip_config(s), settings::cache_ttls(s), settings::custom_api_secret(s)))).await?;
    Ok(Json(Settings { dns, geoip, cache_geoip_ttl_secs: ttls.geoip_secs, cache_dns_ttl_secs: ttls.dns_secs, custom_api_secret_set: secret.is_some() }).into_response())
}

/// The click-through detail panel's data source: a real, as-fresh-as-possible answer for one IP,
/// awaited directly (unlike the best-effort fields already inline on an event/alert).
pub(crate) async fn lookup(State(st): State<AppState>, Path(ip): Path<String>) -> Result<Response, ApiError> {
    let Ok(ip) = ip.parse::<IpAddr>() else { return Ok(err(StatusCode::BAD_REQUEST, "not a valid IP address")) };
    let info = st.ipenrich.enrich_now(ip, now_ts()).await;
    Ok(Json(info).into_response())
}
