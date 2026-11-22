//! Guardrails for outbound HTTP requests whose URLs (or hosts) a message can
//! influence: avatar fetches to sender-controlled domains, BIMI logo URLs from
//! sender-controlled DNS, RFC 8058 unsubscribe endpoints from headers.
//!
//! SSRF is blocked at two layers, both of which must hold before a byte is
//! sent or received:
//!
//! 1. URL level ([`is_public_https_url`]): https only, IP-literal hosts must
//!    be public, and known-local names (`localhost`, ...) are refused. This is
//!    checked on the initial URL and on every redirect hop, which also covers
//!    IP literals — they never reach DNS, so a resolver-level check could
//!    not see them.
//! 2. DNS level ([`PublicDnsResolver`]): installed on the client, it resolves
//!    the host *at connect time* and returns only public addresses; the
//!    connector dials exactly the filtered list. A name that resolves to no
//!    public address fails, and there is no check-then-connect window because
//!    the address list the OS dials is the one we vetted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use url::{Host, Url};

/// A DNS resolver that only ever hands out public, globally routable
/// addresses. Install with `ClientBuilder::dns_resolver`.
pub struct PublicDnsResolver;

/// Shared instance for `ClientBuilder::dns_resolver`.
pub fn dns_resolver() -> Arc<PublicDnsResolver> {
    Arc::new(PublicDnsResolver)
}

/// A redirect policy that follows at most `max_hops` hops and only onto
/// public https destinations. Stopped hops surface as the 3xx response
/// itself (callers already treat non-2xx as failure).
pub fn redirect_policy(max_hops: usize) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() < max_hops && is_public_https_url(attempt.url()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// https scheme plus a public destination. IP literals are classified here;
/// domain names pass unless they name a known-local host — their resolved
/// addresses are vetted for real by [`PublicDnsResolver`] when the connection
/// opens.
pub fn is_public_https_url(url: &Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    match url.host() {
        Some(Host::Ipv4(v4)) => is_public_ip(v4.into()),
        Some(Host::Ipv6(v6)) => is_public_ip(v6.into()),
        Some(Host::Domain(name)) => is_allowed_dns_name(name),
        None => false,
    }
}

/// True when `ip` is globally routable. Everything special — loopback,
/// RFC1918, link-local, CGNAT, unspecified, multicast, reserved,
/// benchmarking/documentation, and the IPv4-mapped/compatible forms of
/// those — is refused.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0                                  // 0.0.0.0/8   "this" network
        || a == 10                            // 10.0.0.0/8  private
        || a == 127                           // 127.0.0.0/8 loopback
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 CGNAT
        || (a == 169 && b == 254)             // 169.254.0.0/16 link-local
        || (a == 172 && (16..=31).contains(&b))  // 172.16.0.0/12 private
        || (a == 192 && b == 0 && c == 0)     // 192.0.0.0/24 protocol assignments
        || (a == 192 && b == 0 && c == 2)     // 192.0.2.0/24 TEST-NET-1
        || (a == 192 && b == 168)             // 192.168.0.0/16 private
        || (a == 198 && (18..=19).contains(&b))  // 198.18.0.0/15 benchmarking
        || (a == 198 && b == 51 && c == 100)  // 198.51.100.0/24 TEST-NET-2
        || (a == 203 && b == 0 && c == 113)   // 203.0.113.0/24 TEST-NET-3
        || a >= 224) // 224/4 multicast, 240/4 reserved
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible) embed a real IPv4;
    // classify that address. ::1/:: are handled below anyway.
    if let Some(v4) = ip.to_ipv4() {
        return is_public_ipv4(v4);
    }
    let s = ip.segments();
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        // NAT64 well-known prefix 64:ff9b::/96 embeds IPv4 in the low bits.
        return is_public_ipv4(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    !(ip.is_unspecified()                     // ::
        || ip.is_loopback()                   // ::1
        || ip.is_multicast()                  // ff00::/8
        || (s[0] & 0xfe00) == 0xfc00          // fc00::/7 unique-local
        || (s[0] & 0xffc0) == 0xfe80          // fe80::/10 link-local
        || (s[0] == 0x2001 && s[1] == 0x0db8)) // 2001:db8::/32 documentation
}

/// Names that must never be connected to even before DNS runs. Everything
/// else is still filtered by the resolved addresses; this exists so local
/// names fail fast and so a resolver quirk returning a local name for a
/// public query can never reach a local socket.
fn is_allowed_dns_name(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    !name.is_empty()
        && name != "localhost"
        && !name.ends_with(".localhost")
        && !name.ends_with(".local")
        && !name.ends_with(".internal")
        && !name.ends_with(".lan")
        && !name.ends_with(".home")
        && !name.ends_with(".corp")
        && !name.ends_with(".home.arpa")
}

/// Is `s` a syntactically valid public-style DNS hostname: lowercase ASCII
/// `[a-z0-9-]` labels of 1-63 chars joined by dots, at least two labels,
/// total length ≤ 253, not an IP literal. Used to vet sender-domain input
/// before it is used in paths or fetches.
pub fn is_dns_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 || s.parse::<IpAddr>().is_ok() {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if !labels.iter().all(label_ok) {
        return false;
    }
    // An all-numeric TLD is never a real domain; rejecting it also catches
    // IP-ish spellings the parser missed (`127.1`, `2130706433.1`, ...).
    if labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    is_allowed_dns_name(s)
}

impl reqwest::dns::Resolve for PublicDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let host = name.as_str().to_string();
            if !is_allowed_dns_name(&host) {
                return Err(format!("netguard: blocked local hostname {host}").into());
            }
            // getaddrinfo with port 0: the connector substitutes the real
            // port afterwards. Resolve, then keep only public answers so the
            // socket can never land on a loopback/private/LAN peer — not even
            // via a second answer behind a public one.
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| is_public_ip(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("netguard: {host} resolves to no public address").into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(s: &str) -> bool {
        is_public_ip(s.parse().unwrap())
    }

    #[test]
    fn ipv4_classifier() {
        for bad in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "10.255.255.255",
            "127.0.0.1",
            "127.53.0.1",
            "100.64.0.0",
            "100.127.255.255",
            "169.254.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.168.0.1",
            "192.168.255.255",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public(bad), "{bad} should be refused");
        }
        for good in [
            "1.1.1.1",
            "8.8.8.8",
            "11.0.0.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.0.1",
            "172.32.0.1",
            "169.253.0.1",
            "192.0.1.1",
            "192.1.0.1",
            "192.167.0.1",
            "192.169.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "203.0.114.1",
            "223.255.255.255",
        ] {
            assert!(public(good), "{good} should be public");
        }
    }

    #[test]
    fn ipv6_classifier() {
        for bad in [
            "::",
            "::1",
            "fe80::1",
            "febf::ffff",
            "fc00::1",
            "fdff::abcd",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.0.1",
            "::127.0.0.1",     // deprecated v4-compatible loopback
            "64:ff9b::7f00:1", // NAT64 embedding 127.0.0.1
            "64:ff9b::a00:1",  // NAT64 embedding 10.0.0.1
        ] {
            assert!(!public(bad), "{bad} should be refused");
        }
        for good in [
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808", // NAT64 embedding 8.8.8.8
            "fe79::1",          // just below fe80::/10
        ] {
            assert!(public(good), "{good} should be public");
        }
    }

    #[test]
    fn url_guard_requires_https_and_public_host() {
        let ok = |s: &str| is_public_https_url(&Url::parse(s).unwrap());
        // Scheme.
        assert!(!ok("http://8.8.8.8/x"));
        assert!(!ok("ftp://example.com/x"));
        // IP literals, including encodings WHATWG normalizes to dotted quad.
        assert!(!ok("https://127.0.0.1/x"));
        assert!(!ok("https://2130706433/x")); // 127.0.0.1 as one integer
        assert!(!ok("https://0x7f000001/x"));
        assert!(!ok("https://0177.0.0.1/x"));
        assert!(!ok("https://169.254.169.254/latest/meta-data"));
        assert!(!ok("https://[::1]/x"));
        assert!(!ok("https://[fe80::1]/x"));
        assert!(!ok("https://[::ffff:127.0.0.1]/x"));
        // Local names.
        assert!(!ok("https://localhost/x"));
        assert!(!ok("https://foo.localhost/x"));
        assert!(!ok("https://printer.local/x"));
        // Public names and public literals pass the URL stage (DNS still
        // vets names at connect time).
        assert!(ok("https://example.com/x"));
        assert!(ok("https://8.8.8.8/x"));
        assert!(ok("https://[2606:4700:4700::1111]/x"));
    }

    #[test]
    fn dns_hostname_validation() {
        for good in [
            "example.com",
            "a.b.example.io",
            "email.apple.com",
            "x-y.example.co.uk",
            "163.com",
            "xn--nxasmq6b.example", // punycode label
            "example.com.",         // FQDN trailing-dot form
        ] {
            assert!(is_dns_hostname(good), "{good} should be a hostname");
        }
        for bad in [
            "",
            ".",
            "localhost",
            "foo.localhost",
            "printer.local",
            "nodot",
            "a/../../comail.db",
            "..",
            "a..b.com",
            ".example.com",
            "-example.com",
            "example-.com",
            "exa mple.com",
            "a\\b.com",
            "a/b.com",
            "a_b.com",
            "Example.COM", // validator is for the already-lowercased input
            "127.0.0.1",
            "127.1",
            "0.0.0.0",
            "[::1]",
            "example.123",
        ] {
            assert!(!is_dns_hostname(bad), "{bad} should be refused");
        }
        // Length limits: total > 253 and a 64-char label.
        let long_label = format!("{}.com", "a".repeat(64));
        assert!(!is_dns_hostname(&long_label));
        let max_label = format!("{}.com", "a".repeat(63));
        assert!(is_dns_hostname(&max_label));
        let long_total = format!("{}.{}.com", "a".repeat(63), "b".repeat(200));
        assert!(!is_dns_hostname(&long_total));
    }
}
