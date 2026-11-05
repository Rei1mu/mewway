//! 本地 CA：生成一次，长期复用；按域名即时签发叶子证书

use anyhow::{Context, Result};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::path::PathBuf;
use std::sync::Mutex;

pub const CN: &str = "Mewway Local CA";

/// CA 证书结构版本。改动 CA 的密钥用途 / 链结构 / 是否签发 CRL 时必须 +1，
/// 旧版本缓存会被自动丢弃并重签。这里从 2 升到 3：CA 重新带上 `CrlSign`
/// （版本 2 因为去掉了它、又没有 CRL，导致 Windows 原生 TLS 栈对自定义根
/// 做强制吊销检查时因「找不到吊销信息」而硬失败）。
const CA_VERSION: u32 = 3;

pub struct Ca {
    dir: PathBuf,
    issuer: Mutex<Issuer<'static, KeyPair>>,
    /// 缓存 CA 自身的 DER，签发叶子证书时拼进链里一起下发给客户端
    ///（之前只发叶子、不发 CA，导致 schannel / .NET 拼链不稳而报吊销错误）。
    ca_der: CertificateDer<'static>,
    /// 由本 CA 签署的 CRL（吊销列表为空，mewway 从不吊销任何叶子证书）。
    /// 叶子证书里会带上指向它的 CRL Distribution Point，这样 Windows 原生
    /// TLS 栈（schannel / .NET / GCM）能查到「有效的吊销信息」而非「查无此项」，
    /// 从而放行 TLS 握手与 GitHub 身份验证，而不是报 CRYPT_E_NO_REVOCATION_CHECK。
    crl_der: Vec<u8>,
}

impl Ca {
    pub fn load_or_create() -> Result<Self> {
        let dir = crate::config::Settings::dir();
        let der_path = dir.join("ca.der");
        let key_path = dir.join("ca.key");
        let ver_path = dir.join("ca.version");

        // 版本不符（或文件缺失）则强制重签，确保旧 CA 不会残留
        let version_ok = std::fs::read_to_string(&ver_path)
            .map(|s| s.trim() == CA_VERSION.to_string())
            .unwrap_or(false);
        if !version_ok {
            let _ = std::fs::remove_file(&der_path);
            let _ = std::fs::remove_file(&key_path);
        }

        // 优先复用已存在的 CA；损坏或缺失再重新生成。
        let loaded: Option<(Issuer<'static, KeyPair>, CertificateDer<'static>)> =
            if der_path.exists() && key_path.exists() {
                let der = std::fs::read(&der_path)?;
                let key_pem = std::fs::read_to_string(&key_path)?;
                if let Ok(key) = KeyPair::from_pem(&key_pem) {
                    let cert = CertificateDer::from(der.clone());
                    if let Ok(issuer) = Issuer::from_ca_cert_der(&cert, key) {
                        Some((issuer, CertificateDer::from(der)))
                    } else {
                        // 文件损坏则重新生成
                        let _ = std::fs::remove_file(&der_path);
                        let _ = std::fs::remove_file(&key_path);
                        None
                    }
                } else {
                    let _ = std::fs::remove_file(&der_path);
                    let _ = std::fs::remove_file(&key_path);
                    None
                }
            } else {
                None
            };

        let (issuer, ca_der) = match loaded {
            Some(v) => v,
            None => {
                let mut params = CertificateParams::new(Vec::<String>::new())?;
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                // 必须保留 CrlSign：mewway 要亲手签一张 CRL 给 Windows 查。
                // 没有它签出的 CRL 会被 schannel 判为「无效签发者」而报离线吊销。
                // 根 CA 自身不带 CRL Distribution Point（否则 Windows 会去查根自己的
                // 吊销，反而触发 SEC_E_UNTRUSTED_ROOT）。
                params.key_usages = vec![
                    KeyUsagePurpose::KeyCertSign,
                    KeyUsagePurpose::CrlSign,
                    KeyUsagePurpose::DigitalSignature,
                ];
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
                std::fs::write(&ver_path, CA_VERSION.to_string())?;
                (Issuer::new(params, key), CertificateDer::from(der))
            }
        };

        // 由本 CA 签署一张 CRL（空列表 = 没有任何证书被吊销），缓存其 DER 供
        // HTTP 端点 /mewway.crl 下发。这是让 Windows 原生 TLS 栈通过吊销检查的
        // 关键：它强制检查自定义根 CA 的吊销信息，没有 CRL 可查就直接握手失败。
        let crl_der = build_crl(&issuer)?;

        Ok(Self {
            dir,
            issuer: Mutex::new(issuer),
            ca_der,
            crl_der,
        })
    }

    /// 返回由本 CA 签署的 CRL（DER 编码）。HTTP 端点 /mewway.crl 用它下发。
    pub fn crl_der(&self) -> &[u8] {
        &self.crl_der
    }

    pub fn der_path(&self) -> PathBuf {
        self.dir.join("ca.der")
    }

    /// 为某个域名签发一张叶子证书
    ///
    /// `crl_url` 是这张证书 CRL Distribution Point 指向的地址（即本代理暴露的
    /// `http://127.0.0.1:<port>/mewway.crl`），Windows 会去那里拉 CRL 做吊销检查。
    pub fn leaf(&self, host: &str, crl_url: &str) -> Result<CertifiedKey> {
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // 叶子带 CRL Distribution Point，指向本代理下发的 CRL。这是非关键的，
        // 但足以让 schannel 找到吊销信息并放行（根 CA 本身不带 CRL DP）。
        params.crl_distribution_points = vec![CrlDistributionPoint { uris: vec![crl_url.to_string()] }];
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
        // 下发完整链 [叶子, CA]：客户端（含 Windows schannel / .NET）才能稳定拼出
        // 到受信任根证书的链，避免「只发叶子」时在链构建阶段连带触发吊销检查报错。
        let certs = vec![cert.der().clone(), self.ca_der.clone()];
        Ok(CertifiedKey::new(certs, signing))
    }
}

/// 用给定 CA 签发一张空吊销列表的 CRL（证明「本 CA 没吊销任何证书」）。
fn build_crl(issuer: &Issuer<'_, KeyPair>) -> Result<Vec<u8>> {
    let params = CertificateRevocationListParams {
        this_update: date_time_ymd(2024, 1, 1),
        next_update: date_time_ymd(2044, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = params
        .signed_by(issuer)
        .map_err(|e| anyhow::anyhow!("签发 CRL 失败：{e}（CA 可能缺少 CrlSign 用途位）"))?;
    Ok(crl.der().as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证：叶子证书链必须包含 [叶子, CA] 两张（之前只发叶子会触发 Windows 原生 TLS 栈吊销报错）。
    #[test]
    fn leaf_chain_includes_ca() {
        let ca = Ca::load_or_create().expect("加载 CA 失败");
        let ck = ca
            .leaf("github.com", "http://127.0.0.1:1/mewway.crl")
            .expect("签发叶子失败");
        assert_eq!(ck.cert.len(), 2, "证书链应含 [叶子, CA] 两张");
    }

    /// 验证：CA 必须签出一张非空、合法的 CRL（DER 以 SEQUENCE 开头），
    /// 否则 Windows 原生 TLS 栈会因查不到吊销信息而握手失败。
    #[test]
    fn crl_is_generated() {
        let ca = Ca::load_or_create().expect("加载 CA 失败");
        let der = ca.crl_der();
        assert!(!der.is_empty(), "CRL 不应为空");
        assert_eq!(der[0], 0x30, "CRL DER 应以 SEQUENCE 开头");
    }

    /// 手动跑：cargo test leaf_smoke -- --ignored --nocapture
    #[test]
    #[ignore]
    fn leaf_smoke() {
        let ca = Ca::load_or_create().expect("加载 CA 失败");
        for h in ["huggingface.co", "cdn-lfs.huggingface.co", "hf.co"] {
            match ca.leaf(h, "http://127.0.0.1:1/mewway.crl") {
                Ok(ck) => println!("{h} -> ok, cert 链长 {}", ck.cert.len()),
                Err(e) => println!("{h} -> 失败: {e:#}"),
            }
        }
    }
}
