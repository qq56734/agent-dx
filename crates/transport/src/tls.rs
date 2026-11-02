//! Deployment-owned TLS files and shared HTTP/gRPC TLS builders.
use adx_protocol::auth::{Peers, Principal};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
    sync::Arc,
};
use tokio_rustls::TlsAcceptor;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    #[serde(default)]
    pub mode: crate::rpc::SecurityMode,
    #[serde(default)]
    pub ca: PathBuf,
    #[serde(default)]
    pub certificate: PathBuf,
    #[serde(default)]
    pub private_key: PathBuf,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub peers: BTreeMap<String, PathBuf>,
}

pub fn grpc_client_config(
    ca: impl Into<PathBuf>,
    certificate: impl Into<PathBuf>,
    private_key: impl Into<PathBuf>,
    server_name: &str,
) -> Result<ClientTlsConfig, Box<dyn std::error::Error>> {
    crate::install_crypto_provider();
    if server_name.trim().is_empty() {
        return Err("TLS server_name required".into());
    }
    Ok(ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(std::fs::read(ca.into())?))
        .identity(Identity::from_pem(
            std::fs::read(certificate.into())?,
            std::fs::read(private_key.into())?,
        ))
        .domain_name(server_name))
}

/// Load one rustls server identity with optional client certificate
/// verification. Callers select ALPN explicitly for HTTP/1.1 or HTTP/2.
pub fn http_server_acceptor(
    certificate: impl Into<PathBuf>,
    private_key: impl Into<PathBuf>,
    client_ca: Option<PathBuf>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    crate::install_crypto_provider();
    let mut certificate = BufReader::new(File::open(certificate.into())?);
    let certificates = server_certificates(&mut certificate, "TLS certificate file is empty")?;
    let mut private_key = BufReader::new(File::open(private_key.into())?);
    let key = rustls_pemfile::private_key(&mut private_key)?.ok_or("TLS private key is empty")?;
    let client_ca = client_ca
        .map(|path| {
            let mut reader = BufReader::new(File::open(path)?);
            server_certificates(&mut reader, "TLS client CA file is empty")
        })
        .transpose()?;
    server_acceptor(certificates, key, client_ca, alpn_protocols)
}

/// Same ADX TLS policy for callers that validate private files before parsing them.
/// Returns an error for empty/invalid PEM, mismatched keys or invalid client trust.
pub fn http_server_acceptor_pem(
    mut certificate: &[u8],
    mut private_key: &[u8],
    client_ca: Option<&[u8]>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    crate::install_crypto_provider();
    let certificates = server_certificates(&mut certificate, "TLS certificate file is empty")?;
    let key = rustls_pemfile::private_key(&mut private_key)?.ok_or("TLS private key is empty")?;
    let client_ca = client_ca
        .map(|mut reader| server_certificates(&mut reader, "TLS client CA file is empty"))
        .transpose()?;
    server_acceptor(certificates, key, client_ca, alpn_protocols)
}

fn server_certificates(
    reader: &mut dyn BufRead,
    empty_error: &'static str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>>
{
    let certificates = rustls_pemfile::certs(reader).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(empty_error.into());
    }
    Ok(certificates)
}

fn server_acceptor(
    certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    client_ca: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let builder = rustls::ServerConfig::builder();
    let mut config = match client_ca {
        None => builder
            .with_no_client_auth()
            .with_single_cert(certificates, key)?,
        Some(ca_certificates) => {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in ca_certificates {
                roots.add(certificate)?;
            }
            let verifier =
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certificates, key)?
        }
    };
    config.alpn_protocols = alpn_protocols;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

impl TlsFiles {
    pub fn load_rpc(
        &self,
        principal: Principal,
    ) -> Result<(Option<ServerTlsConfig>, crate::rpc::RpcClient, Peers), Box<dyn std::error::Error>>
    {
        if self.mode == crate::rpc::SecurityMode::Network {
            return Ok((
                None,
                crate::rpc::RpcClient::network(principal),
                Peers::network(),
            ));
        }
        let (server, client, peers) = self.load()?;
        Ok((Some(server), client.into(), peers))
    }

    pub fn load(
        &self,
    ) -> Result<(ServerTlsConfig, ClientTlsConfig, Peers), Box<dyn std::error::Error>> {
        crate::install_crypto_provider();
        if self.server_name.trim().is_empty() {
            return Err("TLS server_name required".into());
        }
        let identity = Identity::from_pem(
            std::fs::read(&self.certificate)?,
            std::fs::read(&self.private_key)?,
        );
        let mut peers = Vec::new();
        for (role, path) in &self.peers {
            let principal = match role.as_str() {
                "coordinator" => Principal::Coordinator,
                "apiserver" => Principal::ApiServer,
                "ingress" => Principal::Ingress,
                value if value.starts_with("node:") && value.len() > 5 => {
                    Principal::Node(value[5..].into())
                }
                _ => return Err("invalid TLS peer role".into()),
            };
            peers.push((std::fs::read(path)?, principal));
        }
        if peers.is_empty() {
            return Err("TLS peer identities required".into());
        }
        let client = grpc_client_config(
            &self.ca,
            &self.certificate,
            &self.private_key,
            &self.server_name,
        )?;
        Ok((
            ServerTlsConfig::new()
                .identity(identity)
                .client_ca_root(Certificate::from_pem(std::fs::read(&self.ca)?)),
            client,
            Peers::new(peers),
        ))
    }
}
