//! Company attribution: who owns and operates this site, merged from
//! RDAP registrant data, the TLS certificate's org, page metadata
//! (JSON-LD Organization / og:site_name), and DNS providers + TXT
//! verification tokens that reveal which SaaS vendors the company uses.

use super::assets::Page;
use super::dns;
use crate::model::{CompanyInfo, DnsRecord, TlsInfo};
use std::net::IpAddr;
use tokio_util::sync::CancellationToken;

/// TXT-verification / MX / NS substrings → the vendor they reveal.
const PROVIDERS: &[(&str, &str)] = &[
    // TXT domain-verification tokens.
    ("google-site-verification", "Google"),
    ("ms=", "Microsoft"),
    ("stripe-verification", "Stripe"),
    ("atlassian-domain-verification", "Atlassian"),
    ("hubspot", "HubSpot"),
    ("docusign", "DocuSign"),
    ("adobe-idp-site-verification", "Adobe"),
    ("apple-domain-verification", "Apple"),
    ("facebook-domain-verification", "Meta"),
    ("docker-verification", "Docker"),
    ("linear-domain-verification", "Linear"),
    ("asana-domain-verification", "Asana"),
    ("slack-domain-verification", "Slack"),
    ("notion", "Notion"),
    ("gitlab-verification", "GitLab"),
    ("github-verification", "GitHub"),
    ("dropbox-domain-verification", "Dropbox"),
    ("zoom_verify", "Zoom"),
    ("servicenow", "ServiceNow"),
    ("sendgrid", "SendGrid"),
    ("mandrill_verify", "Mailchimp"),
    ("protonmail-verification", "Proton"),
    ("openai-domain-verification", "OpenAI"),
    ("yandex-verification", "Yandex"),
    ("baidu-site-verification", "Baidu"),
    ("detectify-verification", "Detectify"),
    ("calendly", "Calendly"),
    // SPF includes → mail SaaS.
    ("include:_spf.google.com", "Google Workspace"),
    ("include:spf.protection.outlook.com", "Microsoft 365"),
    ("include:sendgrid.net", "SendGrid"),
    ("include:_spf.salesforce.com", "Salesforce"),
    ("include:mail.zendesk.com", "Zendesk"),
    ("include:spf.mtasv.net", "Postmark"),
    // MX → mail provider.
    ("aspmx.l.google.com", "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("mimecast.com", "Mimecast"),
    ("pphosted.com", "Proofpoint"),
    ("zoho.com", "Zoho Mail"),
    ("mail.protonmail.ch", "Proton Mail"),
    ("mx01.mail.icloud.com", "iCloud Mail"),
    // NS → DNS provider.
    ("ns.cloudflare.com", "Cloudflare DNS"),
    ("awsdns-", "AWS Route53"),
    ("googledomains.com", "Google Domains"),
    ("googleclouddns", "Google Cloud DNS"),
    ("azure-dns", "Azure DNS"),
    ("domaincontrol.com", "GoDaddy"),
    ("dnsimple.com", "DNSimple"),
    ("digitalocean.com", "DigitalOcean"),
    ("nsone.net", "NS1"),
    ("dynect.net", "Dyn"),
];

/// Gather everything knowable about who runs `host`/`ip`. `page` is the
/// parsed HTML (when the site answered) — its JSON-LD and og tags are
/// the strongest self-declared company signals.
pub async fn gather(
    host: &str,
    ip: IpAddr,
    site: &super::http::Site,
    tls: Option<&TlsInfo>,
    page: Option<&Page>,
    page_url: &url::Url,
    cancel: CancellationToken,
) -> CompanyInfo {
    let domain = dns::registered_domain(host);
    let domain_ref = domain.as_deref().unwrap_or("");

    let (reg, txt, mx, ns, ip_org, asn, sec_txt) = tokio::join!(
        async {
            match domain {
                Some(_) => dns::rdap_domain(domain_ref).await,
                None => (None, None),
            }
        },
        async {
            match domain {
                Some(_) => dns::doh(domain_ref, "TXT").await,
                None => Vec::new(),
            }
        },
        async {
            match domain {
                Some(_) => dns::doh(domain_ref, "MX").await,
                None => Vec::new(),
            }
        },
        async {
            match domain {
                Some(_) => dns::doh(domain_ref, "NS").await,
                None => Vec::new(),
            }
        },
        dns::rdap_ip(ip),
        dns::asn_org(ip),
        security_txt(site, page_url, cancel),
    );

    let (registrant, registrar) = reg;

    // Organisation names, in evidence-priority order.
    let mut names: Vec<String> = Vec::new();
    let mut push_name = |n: Option<&str>| {
        if let Some(n) = n {
            let n = n.trim();
            if !n.is_empty() && !names.iter().any(|e| e.eq_ignore_ascii_case(n)) {
                names.push(n.to_string());
            }
        }
    };
    push_name(registrant.as_deref());
    push_name(tls.and_then(|t| t.org.as_deref()));
    if let Some(p) = page {
        push_name(jsonld_org(&p.jsonld).as_deref());
        push_name(meta(&p.meta, "og:site_name"));
        push_name(meta(&p.meta, "application-name"));
    }

    // SaaS/provider detection across all record types.
    let mut saas: Vec<String> = Vec::new();
    for value in txt.iter().chain(mx.iter()).chain(ns.iter()) {
        let low = value.to_ascii_lowercase();
        for (needle, vendor) in PROVIDERS {
            if low.contains(*needle) && !saas.iter().any(|v| v == vendor) {
                saas.push(vendor.to_string());
            }
        }
    }

    let mut records = Vec::new();
    for (kind, vals, cap) in [("mx", &mx, 4), ("ns", &ns, 4), ("txt", &txt, 8)] {
        for v in vals.iter().take(cap) {
            records.push(DnsRecord {
                kind: kind.into(),
                value: v.chars().take(160).collect(),
            });
        }
    }

    CompanyInfo {
        names,
        registrar,
        ip_org,
        asn,
        dns: records,
        saas,
        security_txt: sec_txt,
    }
}

/// `/.well-known/security.txt` — a 200 on it is a professional-site tell.
async fn security_txt(
    site: &super::http::Site,
    page_url: &url::Url,
    cancel: CancellationToken,
) -> bool {
    let Some(host) = page_url.host_str() else {
        return false;
    };
    let port_part = page_url.port().map(|p| format!(":{p}")).unwrap_or_default();
    let Ok(u) = url::Url::parse(&format!(
        "{}://{host}{port_part}/.well-known/security.txt",
        page_url.scheme()
    )) else {
        return false;
    };
    site.fetch(&u, cancel)
        .await
        .map(|r| r.status == 200)
        .unwrap_or(false)
}

fn meta<'a>(meta: &'a [(String, String)], key: &str) -> Option<&'a str> {
    meta.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

/// `Organization` name from JSON-LD — first `@type` containing
/// "Organization"/"Corporation"/"WebSite" publisher.
fn jsonld_org(jsonld: &[String]) -> Option<String> {
    for doc in jsonld {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(doc) else {
            continue;
        };
        let mut stack = vec![&v];
        while let Some(n) = stack.pop() {
            if let Some(obj) = n.as_object() {
                let is_org = obj
                    .get("@type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|t| {
                        [
                            "Organization",
                            "Corporation",
                            "LocalBusiness",
                            "NGO",
                            "Airline",
                        ]
                        .contains(&t)
                    });
                if is_org && let Some(name) = obj.get("name").and_then(serde_json::Value::as_str) {
                    return Some(name.to_string());
                }
                if let Some(pub_) = obj.get("publisher") {
                    stack.push(pub_);
                }
                if let Some(arr) = obj.get("@graph").and_then(serde_json::Value::as_array) {
                    stack.extend(arr.iter());
                }
            } else if let Some(arr) = n.as_array() {
                stack.extend(arr.iter());
            }
        }
    }
    None
}
