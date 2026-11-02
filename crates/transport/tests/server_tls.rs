use adx_transport::tls::{http_server_acceptor, http_server_acceptor_pem};

#[test]
fn file_server_rejects_empty_certificate_before_opening_key() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("empty.pem");
    std::fs::write(&certificate, b"").unwrap();
    let result = http_server_acceptor(
        certificate,
        directory.path().join("missing-key"),
        None,
        vec![],
    );
    let error = result.err().expect("empty certificate must be rejected");
    assert_eq!(error.to_string(), "TLS certificate file is empty");
}

#[test]
fn validated_pem_server_rejects_empty_certificate() {
    let result = http_server_acceptor_pem(b"", b"", None, vec![]);
    let error = result.err().expect("empty certificate must be rejected");
    assert_eq!(error.to_string(), "TLS certificate file is empty");
}

#[test]
fn validated_pem_server_accepts_a_valid_identity_and_rejects_empty_client_ca() {
    let certificate = include_bytes!("../../../gateway/tests/fixtures/ingress-cert.pem");
    let key = include_bytes!("../../../gateway/tests/fixtures/ingress-key.pem");
    assert!(http_server_acceptor_pem(certificate, key, None, vec![]).is_ok());
    let error = http_server_acceptor_pem(certificate, key, Some(b""), vec![])
        .err()
        .expect("empty client CA must be rejected");
    assert_eq!(error.to_string(), "TLS client CA file is empty");
}
