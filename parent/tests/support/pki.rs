use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
pub struct Pki(pub PathBuf);
impl Pki {
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let path = std::env::temp_dir().join(format!(
            "parent-pki-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        let result = Self(path);
        assert!(std::process::Command::new("bash")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/parent-pki.sh"
            ))
            .arg(&result.0)
            .status()
            .unwrap()
            .success());
        result
    }
    pub fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.0.join(name)).unwrap()
    }
    pub fn identity(&self, name: &str) -> Identity {
        Identity::from_pem(
            self.read(&format!("{name}.pem")),
            self.read(&format!("{name}.key")),
        )
    }
    pub fn pin(&self, name: &str) -> String {
        hex::encode(Sha256::digest(self.read(&format!("{name}.der"))))
    }
    pub fn acl(&self, operator: &str) -> String {
        format!(
            "{} clone-operator\n{} listener\n{} observer\n",
            self.pin(operator),
            self.pin("listener"),
            self.pin("observer")
        )
    }
    #[allow(dead_code)] // Used by perimeter tests; clone tests use the CLI's endpoint builder.
    pub fn endpoint(
        &self,
        addr: std::net::SocketAddr,
        who: Option<&str>,
        name: &str,
        ca: &str,
    ) -> Endpoint {
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(self.read(ca)))
            .domain_name(name);
        if let Some(who) = who {
            tls = tls.identity(self.identity(who));
        }
        Endpoint::from_shared(format!("https://{addr}"))
            .unwrap()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(1))
            .tls_config(tls)
            .unwrap()
    }
}
impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
