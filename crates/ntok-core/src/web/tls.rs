//! TLS reconnaissance: connect to `ip:port` with the site's SNI, accept
//! every certificate (reconnaissance reads what is there — it doesn't
//! gate on trust), then parse the leaf for subject, issuer, SANs and
//! validity with `x509-parser`.

use crate::model::TlsInfo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use x509_parser::prelude::FromDer;

/// Accept every certificate — the point is to read it, not trust it.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn config() -> &'static Arc<ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let mut c = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(c)
    })
}

/// Handshake with `server_name` SNI on `ip:port`; returns the leaf
/// certificate details. `None` when the port isn't TLS or doesn't answer.
pub async fn fetch(ip: IpAddr, server_name: &str, port: u16, timeout: Duration) -> Option<TlsInfo> {
    let name: ServerName<'static> = if let Ok(ip) = server_name.parse::<IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(server_name.to_string()).ok()?
    };
    let tcp = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(config()));
    let tls = tokio::time::timeout(timeout, connector.connect(name, tcp))
        .await
        .ok()?
        .ok()?;
    let (_, conn) = tls.get_ref();
    let protocol = format!("{:?}", conn.protocol_version()?)
        .replace("TLSv", "TLS ")
        .replace('_', ".");
    let leaf = conn.peer_certificates()?.first()?.clone();
    drop(tls);
    parse_cert(&leaf, protocol)
}

fn parse_cert(der: &CertificateDer<'_>, protocol: String) -> Option<TlsInfo> {
    use x509_parser::oid_registry::{OID_X509_COMMON_NAME, OID_X509_ORGANIZATION_NAME};
    use x509_parser::x509::X509Name;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref()).ok()?;
    let attr = |name: &X509Name, oid: &x509_parser::oid_registry::Oid| {
        name.iter_attributes()
            .find(|a| a.attr_type() == oid)
            .and_then(|a| a.as_str().ok().map(str::to_string))
    };
    let cn_of = |n: &X509Name| attr(n, &OID_X509_COMMON_NAME);
    let org_of = |n: &X509Name| attr(n, &OID_X509_ORGANIZATION_NAME);

    let subj = cert.subject();
    let iss = cert.issuer();

    let mut san = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for gn in &ext.value.general_names {
            use x509_parser::extensions::GeneralName::*;
            match gn {
                DNSName(d) => san.push(d.to_string()),
                IPAddress(ip) => {
                    let ip: Option<IpAddr> = match ip.len() {
                        4 => Some(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).into()),
                        16 => {
                            let mut o = [0u8; 16];
                            o.copy_from_slice(ip);
                            Some(std::net::Ipv6Addr::from(o).into())
                        }
                        _ => None,
                    };
                    if let Some(ip) = ip {
                        san.push(ip.to_string());
                    }
                }
                URI(u) => san.push(u.to_string()),
                _ => {}
            }
        }
    }

    let not_after = cert.validity().not_after.to_datetime();
    let now = time_now();
    let expired = not_after.unix_timestamp() < now;

    Some(TlsInfo {
        protocol,
        subject_cn: cn_of(subj),
        org: org_of(subj),
        issuer_cn: cn_of(iss),
        issuer_org: org_of(iss),
        not_before: fmt_time(cert.validity().not_before.to_datetime()),
        not_after: fmt_time(not_after),
        san: {
            san.sort();
            san.dedup();
            san
        },
        expired,
        self_signed: cert.tbs_certificate.subject == cert.tbs_certificate.issuer,
    })
}

fn fmt_time(t: time::OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.to_string())
}

fn time_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
