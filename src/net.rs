//! Interface discovery and selection (Linux, macOS, and — unverified, see `WINDOWS.md` — Windows).

#[cfg(unix)]
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use anyhow::{bail, Result};
use ipnet::Ipv4Net;
#[cfg(unix)]
use nix::ifaddrs::getifaddrs;
#[cfg(unix)]
use nix::net::if_::InterfaceFlags;

use crate::model::Mac;

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub mac: Mac,
    pub ip: Ipv4Addr,
    pub net: Ipv4Net,
}

/// Up, non-loopback, non-point-to-point Ethernet-like interfaces with an IPv4 address.
#[cfg(unix)]
pub fn list_interfaces() -> Result<Vec<Iface>> {
    #[derive(Default)]
    struct Partial {
        mac: Option<Mac>,
        v4: Option<(Ipv4Addr, Ipv4Addr)>,
        usable: bool,
    }
    let mut by_name: BTreeMap<String, Partial> = BTreeMap::new();
    for ifa in getifaddrs()? {
        let p = by_name.entry(ifa.interface_name.clone()).or_default();
        p.usable = ifa.flags.contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_RUNNING)
            && !ifa.flags.intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT);
        let Some(addr) = &ifa.address else { continue };
        if let Some(link) = addr.as_link_addr() {
            if let Some(b) = link.addr() {
                p.mac = Some(Mac(b));
            }
        } else if let Some(sin) = addr.as_sockaddr_in() {
            let mask = ifa
                .netmask
                .as_ref()
                .and_then(|m| m.as_sockaddr_in())
                .map(|m| m.ip());
            if let Some(mask) = mask {
                p.v4 = Some((sin.ip(), mask));
            }
        }
    }

    let mut out = Vec::new();
    for (name, p) in by_name {
        let (Some(mac), Some((ip, mask)), true) = (p.mac, p.v4, p.usable) else {
            continue;
        };
        if !mac.is_valid() || ip.is_link_local() || ip.is_loopback() {
            continue;
        }
        let Ok(net) = Ipv4Net::with_netmask(ip, mask) else {
            continue;
        };
        out.push(Iface {
            name,
            mac,
            ip,
            net: net.trunc(),
        });
    }
    Ok(out)
}

/// Every up, non-loopback, non-point-to-point interface, whether or not it has
/// an IPv4 address. A mirror/SPAN destination port usually has none, so this
/// (unlike `list_interfaces`) is what offers it as a candidate.
#[cfg(unix)]
pub fn list_all_up() -> Result<Vec<String>> {
    let mut names: std::collections::BTreeSet<String> = Default::default();
    for ifa in getifaddrs()? {
        let usable = ifa.flags.contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_RUNNING)
            && !ifa.flags.intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT);
        if usable {
            names.insert(ifa.interface_name.clone());
        }
    }
    Ok(names.into_iter().collect())
}

// ---------------------------------------------------------------------------------- Windows
//
// getifaddrs(3) has no Windows equivalent; GetAdaptersAddresses is the documented replacement
// (used this way by, among others, Npcap's own examples). **Unverified**: written against the
// Win32 API's documented behaviour, not run on a real Windows machine — see WINDOWS.md. Capture
// itself does not work on Windows yet regardless (no Npcap wiring), so nothing calls this in
// anger today; it exists so the rest of the collector has a real interface list to build on once
// that lands.
#[cfg(windows)]
mod windows_ifaces {
    use super::*;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH};
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};

    /// One adapter's name, MAC, up/down state and IPv4 addresses (with prefix length), read from
    /// one `GetAdaptersAddresses` call. `list_interfaces`/`list_all_up` each filter/map this the
    /// same way the Unix `getifaddrs` loop does.
    struct Adapter {
        name: String,
        mac: Option<Mac>,
        up: bool,
        v4: Vec<(Ipv4Addr, u8)>, // address, prefix length
    }

    fn adapters() -> Result<Vec<Adapter>> {
        // MS's own documented pattern: guess a buffer size, retry once with the size the call
        // itself reports back if that guess was too small.
        let mut size: u32 = 15_000;
        let mut buf: Vec<u8>;
        let mut ret;
        loop {
            buf = vec![0u8; size as usize];
            // SAFETY: `buf` is sized `size` bytes and `size` is updated in place; the call only
            // writes within that buffer and only reads the fixed-size arguments before it.
            ret = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut size,
                )
            };
            if ret != ERROR_BUFFER_OVERFLOW {
                break;
            }
        }
        if ret != ERROR_SUCCESS {
            anyhow::bail!("GetAdaptersAddresses failed (error {ret})");
        }
        let mut out = Vec::new();
        // SAFETY: `cur` starts at a value the call above just wrote as the head of its own
        // linked list (or is null, if there were no adapters at all), and every `Next` pointer
        // in that list was written by the same call — this walks exactly the list Windows built.
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = unsafe { &*cur };
            let name = unsafe { widestring_to_string(a.FriendlyName) };
            let mac = (a.PhysicalAddressLength == 6).then(|| Mac(a.PhysicalAddress[..6].try_into().unwrap()));
            let up = a.OperStatus == IfOperStatusUp;
            let mut v4 = Vec::new();
            // SAFETY: each `FirstUnicastAddress`/`Next` in this inner list was likewise written
            // by the same successful call, for the lifetime of `buf`.
            let mut ua = a.FirstUnicastAddress;
            while !ua.is_null() {
                let u = unsafe { &*ua };
                let sa = u.Address.lpSockaddr;
                if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET {
                    let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                    // SAFETY: `S_un` is a single-field union (`S_addr`, a plain u32) in this SDK version.
                    let addr = unsafe { sin.sin_addr.S_un.S_addr };
                    let ip = Ipv4Addr::from(u32::from_be(addr));
                    v4.push((ip, u.OnLinkPrefixLength));
                }
                ua = u.Next;
            }
            if let Some(name) = name {
                out.push(Adapter { name, mac, up, v4 });
            }
            cur = a.Next;
        }
        Ok(out)
    }

    /// A Win32 `PWSTR` (NUL-terminated UTF-16) as an owned `String`. `None` for a null pointer or
    /// invalid UTF-16 rather than panicking — a hostile or unusual adapter name must not crash this.
    unsafe fn widestring_to_string(p: windows_sys::core::PWSTR) -> Option<String> {
        if p.is_null() {
            return None;
        }
        let mut len = 0isize;
        while *p.offset(len) != 0 {
            len += 1;
            if len > 4096 {
                return None; // clearly not a real NUL-terminated name; do not scan forever
            }
        }
        let slice = std::slice::from_raw_parts(p, len as usize);
        String::from_utf16(slice).ok()
    }

    pub fn list_interfaces() -> Result<Vec<Iface>> {
        let mut out = Vec::new();
        for a in adapters()? {
            let Some(mac) = a.mac else { continue };
            if !a.up || !mac.is_valid() {
                continue;
            }
            for (ip, prefix) in &a.v4 {
                if ip.is_link_local() || ip.is_loopback() {
                    continue;
                }
                let Ok(net) = Ipv4Net::new(*ip, *prefix) else { continue };
                out.push(Iface { name: a.name.clone(), mac, ip: *ip, net: net.trunc() });
            }
        }
        Ok(out)
    }

    pub fn list_all_up() -> Result<Vec<String>> {
        Ok(adapters()?.into_iter().filter(|a| a.up).map(|a| a.name).collect())
    }
}
#[cfg(windows)]
pub use windows_ifaces::{list_all_up, list_interfaces};

/// True if `name` names an up, non-loopback interface, with or without an
/// IPv4 address: used to validate a mirror/SPAN interface before capture.
pub fn exists_up(name: &str) -> Result<bool> {
    Ok(list_all_up()?.iter().any(|n| n == name))
}

/// Choose the interface to monitor: the one holding the default route if it can
/// be determined, otherwise the first private-range candidate.
pub fn select(name: Option<&str>) -> Result<Iface> {
    let all = list_interfaces()?;
    if let Some(name) = name {
        return all.into_iter().find(|i| i.name == name).ok_or_else(|| {
            anyhow::anyhow!("interface {name:?} not found, not up, or has no IPv4 address (try `denis interfaces`)")
        });
    }
    if all.is_empty() {
        bail!("no usable network interface found (need one that is up with an IPv4 address)");
    }
    if let Some(gw) = default_gateway() {
        if let Some(i) = all.iter().find(|i| i.net.contains(&gw)) {
            return Ok(i.clone());
        }
    }
    Ok(all
        .iter()
        .find(|i| i.ip.is_private())
        .unwrap_or(&all[0])
        .clone())
}

/// IPv4 default gateway, if any.
pub fn default_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.trim().strip_prefix("gateway:")?.trim().parse().ok())
    }
    #[cfg(target_os = "linux")]
    {
        parse_proc_net_route(&std::fs::read_to_string("/proc/net/route").ok()?)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// `/proc/net/route`: `Iface Destination Gateway Flags ...`, fields in hex and
/// little-endian. The default route has destination 0 and the RTF_GATEWAY (0x2) flag.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_route(text: &str) -> Option<Ipv4Addr> {
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 3 && f[1] == "00000000" && u32::from_str_radix(f[3], 16).ok()? & 0x2 != 0 {
            let g = u32::from_str_radix(f[2], 16).ok()?;
            Some(Ipv4Addr::from(g.swap_bytes()))
        } else {
            None
        }
    })
}

/// Maximum hosts swept before the range is clamped to the /24 around us.
pub const MAX_SWEEP_HOSTS: usize = 1022;

/// Scannable host addresses (excluding ourselves). Very large subnets are
/// clamped to our own /24 so a /16 doesn't turn into a 65k-packet sweep.
pub fn sweep_targets(net: Ipv4Net, own_ip: Ipv4Addr) -> (Vec<Ipv4Addr>, bool) {
    let clamped = net.hosts().count() > MAX_SWEEP_HOSTS;
    let range = if clamped {
        Ipv4Net::new(own_ip, 24).unwrap().trunc()
    } else {
        net
    };
    (range.hosts().filter(|ip| *ip != own_ip).collect(), clamped)
}

/// Seconds east of UTC for the local time zone right now (so "03:00" means the
/// owner's 03:00). 0 if it cannot be determined.
#[cfg(unix)]
pub fn local_utc_offset_secs() -> i64 {
    // SAFETY: localtime_r only reads `t` and writes the zero-initialised `tm`.
    unsafe {
        let t: libc::time_t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as libc::time_t)
            .unwrap_or(0);
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff as i64
    }
}

/// **Unverified** (see `WINDOWS.md`): Windows' CRT `tm` has no `tm_gmtoff`, so this uses
/// `GetTimeZoneInformation` instead — its `Bias`/`DaylightBias` are minutes *west* of UTC (the
/// opposite sign of this function's own contract), which is why they are negated and summed.
#[cfg(windows)]
pub fn local_utc_offset_secs() -> i64 {
    use windows_sys::Win32::System::SystemServices::TIME_ZONE_ID_DAYLIGHT;
    use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    // SAFETY: `tzi` is zero-initialised and the call only ever writes into it.
    unsafe {
        let mut tzi: TIME_ZONE_INFORMATION = std::mem::zeroed();
        let id = GetTimeZoneInformation(&mut tzi);
        let bias = tzi.Bias + if id == TIME_ZONE_ID_DAYLIGHT { tzi.DaylightBias } else { 0 };
        -(bias as i64) * 60
    }
}

#[cfg(unix)]
pub fn local_hostname() -> Option<String> {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|h| h.trim_end_matches(".local").to_string())
        .filter(|h| !h.is_empty())
}

/// `COMPUTERNAME` is set by Windows itself for every process; no syscall needed the way
/// `gethostname(3)` is on Unix.
#[cfg(windows)]
pub fn local_hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().filter(|h| !h.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_excludes_self_and_edges() {
        let net: Ipv4Net = "192.168.1.0/24".parse().unwrap();
        let (t, clamped) = sweep_targets(net, Ipv4Addr::new(192, 168, 1, 10));
        assert!(!clamped);
        assert_eq!(t.len(), 253);
        assert!(!t.contains(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(!t.contains(&Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!t.contains(&Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn huge_subnet_is_clamped_to_own_24() {
        let net: Ipv4Net = "10.0.0.0/16".parse().unwrap();
        let (t, clamped) = sweep_targets(net, Ipv4Addr::new(10, 0, 7, 9));
        assert!(clamped);
        assert_eq!(t.len(), 253);
        assert!(t.iter().all(|ip| ip.octets()[2] == 7));
    }

    #[test]
    fn parses_linux_default_route() {
        let t = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                 docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
                 enp3s0\t00000000\t0A000AC0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                 enp3s0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route(t), Some(Ipv4Addr::new(192, 10, 0, 10)));
        // no default route, and a default without the GATEWAY flag
        assert_eq!(parse_proc_net_route("Iface\tDestination\tGateway\tFlags\n"), None);
        assert_eq!(parse_proc_net_route("Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0001\n"), None);
        // 192.168.1.1 encodes as 0101A8C0
        let t = "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0101A8C0\t0003\n";
        assert_eq!(parse_proc_net_route(t), Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn local_utc_offset_is_a_plausible_zone() {
        let o = local_utc_offset_secs();
        assert!((-12 * 3600..=14 * 3600).contains(&o), "{o}");
        assert_eq!(o % 900, 0, "zones are whole quarter-hours");
    }

    #[test]
    fn lists_interfaces_without_error() {
        // Environment-dependent content, but must never error or panic.
        let _ = list_interfaces().unwrap();
    }
}
