//! 本地 CA：生成一次，长期复用；按域名即时签发叶子证书

use anyhow::{Context, Result};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::path::PathBuf;
use std::sync::Mutex;

pub const CN: &str = "Mewway Local CA";

pub struct Ca {
    dir: PathBuf,
    issuer: Mutex<Issuer<'static, KeyPair>>,
}

impl Ca {
    pub fn load_or_create() -> Result<Self> {
        let dir = crate::config::Settings::dir();
        let der_path = dir.join("ca.der");
        let key_path = dir.join("ca.key");

        if der_path.exists() && key_path.exists() {
            let der = std::fs::read(&der_path)?;
            let key_pem = std::fs::read_to_string(&key_path)?;
            if let Ok(key) = KeyPair::from_pem(&key_pem) {
                let cert = CertificateDer::from(der.clone());
                if let Ok(issuer) = Issuer::from_ca_cert_der(&cert, key) {
                    return Ok(Self { dir, issuer: Mutex::new(issuer) });
                }
            }
            // 文件损坏则重新生成
            let _ = std::fs::remove_file(&der_path);
            let _ = std::fs::remove_file(&key_path);
        }

        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, CN);
        dn.push(DnType::OrganizationName, "Mewway");
        params.distinguished_name = dn;
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2044, 1, 1);

        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        let der = cert.der().to_vec();
        std::fs::write(&der_path, &der)?;
        std::fs::write(&key_path, key.serialize_pem())?;
        let issuer = Issuer::new(params, key);

        Ok(Self { dir, issuer: Mutex::new(issuer) })
    }

    pub fn der_path(&self) -> PathBuf {
        self.dir.join("ca.der")
    }

    /// 为某个域名签发一张叶子证书
    pub fn leaf(&self, host: &str) -> Result<CertifiedKey> {
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = date_time_ymd(2024, 1, 1);
        params.not_after = date_time_ymd(2044, 1, 1);

        let key = KeyPair::generate()?;
        let cert = {
            let issuer = self.issuer.lock().unwrap_or_else(|e| e.into_inner());
            params.signed_by(&key, &*issuer)?
        };

        let key_der = PrivatePkcs8KeyDer::from(key.serialize_der());
        let signing = rustls::crypto::ring::sign::any_supported_type(&key_der.into())
            .context("构造签名密钥失败")?;
        Ok(CertifiedKey::new(vec![cert.der().clone()], signing))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手动跑：cargo test leaf_smoke -- --ignored --nocapture
    #[test]
    #[ignore]
    fn leaf_smoke() {
        let ca = Ca::load_or_create().expect("加载 CA 失败");
        for h in ["huggingface.co", "cdn-lfs.huggingface.co", "hf.co"] {
            match ca.leaf(h) {
                Ok(ck) => println!("{h} -> ok, cert 链长 {}", ck.cert.len()),
                Err(e) => println!("{h} -> 失败: {e:#}"),
            }
        }
    }
}
