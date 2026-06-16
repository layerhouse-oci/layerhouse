use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use base64::Engine;
use clap::{Args, Subcommand};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

const DEFAULT_CA_DAYS: u32 = 3650;
const DEFAULT_CERT_DAYS: u32 = 825;
const DEFAULT_NAMESPACE: &str = "layerhouse";
const DEFAULT_SERVER_TLS_SECRET: &str = "layerhouse-server-tls";
const DEFAULT_RAFT_TLS_SECRET: &str = "layerhouse-raft-mtls";
const DEFAULT_STATEFULSET_NAME: &str = "layerhouse";
const DEFAULT_HEADLESS_SERVICE: &str = "layerhouse-headless";
const DEFAULT_REPLICAS: u16 = 3;
const DEFAULT_OUT: &str = "./layerhouse-airgap";
const DEFAULT_IMAGE_REPOSITORY: &str = "ghcr.io/layerhouse-oci/layerhouse-server";
const DEFAULT_IMAGE_TAG: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Subcommand)]
pub enum AirGappedCommands {
    /// Guided air-gapped Kubernetes bootstrap
    Bootstrap(BootstrapArgs),
    /// Certificate generation helpers
    Cert {
        #[command(subcommand)]
        command: CertCommands,
    },
    /// Kubernetes bundle generation helpers
    K8s {
        #[command(subcommand)]
        command: K8sCommands,
    },
}

#[derive(Debug, Args)]
pub struct BootstrapArgs {
    /// Prompt for bootstrap inputs
    #[arg(long)]
    pub interactive: bool,
}

#[derive(Debug, Subcommand)]
pub enum CertCommands {
    /// Generate an internal CA and registry server certificate
    Init(CertInitArgs),
}

#[derive(Debug, Args, Clone)]
pub struct CertInitArgs {
    /// Registry DNS name or IP address, without scheme, path, or port
    #[arg(long)]
    pub registry_host: String,
    /// Additional DNS names or IP addresses to include as SANs
    #[arg(long = "san")]
    pub sans: Vec<String>,
    /// Kubernetes namespace used for Raft peer DNS SANs
    #[arg(long, default_value = DEFAULT_NAMESPACE)]
    pub namespace: String,
    /// StatefulSet name used for Raft peer DNS SANs
    #[arg(long, default_value = DEFAULT_STATEFULSET_NAME)]
    pub statefulset_name: String,
    /// Headless Service name used for Raft peer DNS SANs
    #[arg(long, default_value = DEFAULT_HEADLESS_SERVICE)]
    pub headless_service: String,
    /// Number of StatefulSet replicas to include in Raft peer DNS SANs
    #[arg(long, default_value_t = DEFAULT_REPLICAS)]
    pub replicas: u16,
    /// Output directory
    #[arg(long, default_value = DEFAULT_OUT)]
    pub out: PathBuf,
    /// CA validity in days
    #[arg(long, default_value_t = DEFAULT_CA_DAYS)]
    pub ca_days: u32,
    /// Registry certificate validity in days
    #[arg(long, default_value_t = DEFAULT_CERT_DAYS)]
    pub cert_days: u32,
    /// Replace existing generated files
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Debug, Subcommand)]
pub enum K8sCommands {
    /// Generate Kubernetes TLS and containerd trust artifacts from existing certs
    BundleGenerate(BundleGenerateArgs),
}

#[derive(Debug, Args, Clone)]
pub struct BundleGenerateArgs {
    /// Registry endpoint used in image references, including port when present
    #[arg(long)]
    pub registry_endpoint: String,
    /// Directory containing ca.crt plus server/ and raft/ certificate material
    #[arg(long)]
    pub cert_dir: PathBuf,
    /// Kubernetes namespace for generated Secret examples
    #[arg(long, default_value = DEFAULT_NAMESPACE)]
    pub namespace: String,
    /// Kubernetes Secret name for public registry TLS
    #[arg(long, default_value = DEFAULT_SERVER_TLS_SECRET)]
    pub server_tls_secret: String,
    /// Kubernetes Secret name for Raft mutual TLS
    #[arg(long, default_value = DEFAULT_RAFT_TLS_SECRET)]
    pub raft_tls_secret: String,
    /// Server image repository for generated Helm values
    #[arg(long, default_value = DEFAULT_IMAGE_REPOSITORY)]
    pub image_repository: String,
    /// Server image tag for generated Helm values
    #[arg(long, default_value = DEFAULT_IMAGE_TAG)]
    pub image_tag: String,
    /// Output directory
    #[arg(long, default_value = DEFAULT_OUT)]
    pub out: PathBuf,
    /// Replace existing generated files
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Debug, Error)]
pub enum AirGappedError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("certificate generation: {0}")]
    Certificate(#[from] rcgen::Error),
}

pub type Result<T> = std::result::Result<T, AirGappedError>;

pub fn run(command: AirGappedCommands) -> Result<()> {
    match command {
        AirGappedCommands::Bootstrap(args) => run_bootstrap(args),
        AirGappedCommands::Cert {
            command: CertCommands::Init(args),
        } => {
            cert_init(args)?;
            Ok(())
        }
        AirGappedCommands::K8s {
            command: K8sCommands::BundleGenerate(args),
        } => {
            bundle_generate(args)?;
            Ok(())
        }
    }
}

fn run_bootstrap(args: BootstrapArgs) -> Result<()> {
    if !args.interactive {
        return Err(AirGappedError::InvalidInput(
            "bootstrap currently requires --interactive".to_string(),
        ));
    }

    let registry_host = prompt("Registry host (DNS or IP, no port)", None)?;
    let default_endpoint = registry_host.clone();
    let registry_endpoint = prompt(
        "Registry endpoint for image pulls (host[:port])",
        Some(&default_endpoint),
    )?;
    let namespace = prompt("Kubernetes namespace", Some(DEFAULT_NAMESPACE))?;
    let statefulset_name = prompt("StatefulSet name", Some(DEFAULT_STATEFULSET_NAME))?;
    let headless_service = prompt("Headless Service name", Some(DEFAULT_HEADLESS_SERVICE))?;
    let replicas = prompt("Replica count", Some(&DEFAULT_REPLICAS.to_string()))?
        .parse::<u16>()
        .map_err(|_| AirGappedError::InvalidInput("replica count must be a number".to_string()))?;
    let server_tls_secret = prompt(
        "Kubernetes server TLS Secret name",
        Some(DEFAULT_SERVER_TLS_SECRET),
    )?;
    let raft_tls_secret = prompt(
        "Kubernetes Raft mTLS Secret name",
        Some(DEFAULT_RAFT_TLS_SECRET),
    )?;
    let out = PathBuf::from(prompt("Output directory", Some(DEFAULT_OUT))?);
    let overwrite = prompt_bool("Overwrite existing generated files?", false)?;

    let cert_args = CertInitArgs {
        registry_host,
        sans: Vec::new(),
        namespace: namespace.clone(),
        statefulset_name,
        headless_service,
        replicas,
        out: out.clone(),
        ca_days: DEFAULT_CA_DAYS,
        cert_days: DEFAULT_CERT_DAYS,
        overwrite,
    };
    cert_init(cert_args)?;

    let bundle_args = BundleGenerateArgs {
        registry_endpoint,
        cert_dir: out.join("certs"),
        namespace,
        server_tls_secret,
        raft_tls_secret,
        image_repository: DEFAULT_IMAGE_REPOSITORY.to_string(),
        image_tag: DEFAULT_IMAGE_TAG.to_string(),
        out,
        overwrite,
    };
    bundle_generate(bundle_args)?;

    Ok(())
}

pub fn cert_init(args: CertInitArgs) -> Result<()> {
    let registry_host = validate_registry_host(&args.registry_host)?;
    if args.namespace.trim().is_empty()
        || args.statefulset_name.trim().is_empty()
        || args.headless_service.trim().is_empty()
    {
        return Err(AirGappedError::InvalidInput(
            "namespace, statefulset-name, and headless-service cannot be empty".to_string(),
        ));
    }
    if args.replicas == 0 {
        return Err(AirGappedError::InvalidInput(
            "replicas must be greater than zero".to_string(),
        ));
    }

    let mut server_sans = BTreeSet::new();
    server_sans.insert(registry_host.clone());
    for san in &args.sans {
        server_sans.insert(validate_registry_host(san)?);
    }
    let server_sans = server_sans.into_iter().collect::<Vec<_>>();
    let raft_sans = raft_dns_sans(
        &args.statefulset_name,
        &args.headless_service,
        &args.namespace,
        args.replicas,
    );

    let cert_dir = args.out.join("certs");
    let server_dir = cert_dir.join("server");
    let raft_dir = cert_dir.join("raft");
    fs::create_dir_all(&cert_dir)?;
    fs::create_dir_all(&server_dir)?;
    fs::create_dir_all(&raft_dir)?;

    let ca_key_path = cert_dir.join("ca.key");
    let ca_cert_path = cert_dir.join("ca.crt");
    let server_key_path = server_dir.join("tls.key");
    let server_cert_path = server_dir.join("tls.crt");
    let raft_ca_path = raft_dir.join("ca.crt");
    let raft_key_path = raft_dir.join("tls.key");
    let raft_cert_path = raft_dir.join("tls.crt");

    ensure_writable(
        &[
            &ca_key_path,
            &ca_cert_path,
            &server_key_path,
            &server_cert_path,
            &raft_ca_path,
            &raft_key_path,
            &raft_cert_path,
        ],
        args.overwrite,
    )?;

    let now = OffsetDateTime::now_utc();
    let ca_key = KeyPair::generate()?;
    let ca_key_pem = ca_key.serialize_pem();
    let mut ca_params = CertificateParams::new(vec!["layerhouse-airgap-ca.local".to_string()])?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(
        DnType::CommonName,
        format!("Layerhouse Air-Gapped CA for {registry_host}"),
    );
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params.not_before = now - Duration::days(1);
    ca_params.not_after = now + days(args.ca_days);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key)?;

    let (server_cert, server_key_pem) =
        signed_leaf(&registry_host, server_sans, &ca, now, args.cert_days, false)?;
    let (raft_cert, raft_key_pem) = signed_leaf(
        &format!("{}.{}", args.statefulset_name, args.namespace),
        raft_sans,
        &ca,
        now,
        args.cert_days,
        true,
    )?;

    write_file(&ca_cert_path, ca.pem().as_bytes(), false)?;
    write_file(&ca_key_path, ca_key_pem.as_bytes(), true)?;
    write_file(&server_cert_path, server_cert.pem().as_bytes(), false)?;
    write_file(&server_key_path, server_key_pem.as_bytes(), true)?;
    write_file(&raft_ca_path, ca.pem().as_bytes(), false)?;
    write_file(&raft_cert_path, raft_cert.pem().as_bytes(), false)?;
    write_file(&raft_key_path, raft_key_pem.as_bytes(), true)?;

    println!("Generated air-gapped certs in {}", cert_dir.display());
    Ok(())
}

fn signed_leaf(
    common_name: &str,
    sans: Vec<String>,
    ca: &CertifiedIssuer<'_, KeyPair>,
    now: OffsetDateTime,
    cert_days: u32,
    client_auth: bool,
) -> Result<(rcgen::Certificate, String)> {
    let key = KeyPair::generate()?;
    let key_pem = key.serialize_pem();
    let mut params = CertificateParams::new(sans)?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name.to_string());
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = if client_auth {
        vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ]
    } else {
        vec![ExtendedKeyUsagePurpose::ServerAuth]
    };
    params.not_before = now - Duration::days(1);
    params.not_after = now + days(cert_days);
    let cert = params.signed_by(&key, ca)?;
    Ok((cert, key_pem))
}

pub fn bundle_generate(args: BundleGenerateArgs) -> Result<()> {
    let registry_endpoint = validate_registry_endpoint(&args.registry_endpoint)?;
    let image_repository = args.image_repository.trim();
    let image_tag = args.image_tag.trim();
    if args.namespace.trim().is_empty() {
        return Err(AirGappedError::InvalidInput(
            "--namespace cannot be empty".to_string(),
        ));
    }
    if args.server_tls_secret.trim().is_empty() {
        return Err(AirGappedError::InvalidInput(
            "--server-tls-secret cannot be empty".to_string(),
        ));
    }
    if args.raft_tls_secret.trim().is_empty() {
        return Err(AirGappedError::InvalidInput(
            "--raft-tls-secret cannot be empty".to_string(),
        ));
    }
    if image_repository.is_empty() {
        return Err(AirGappedError::InvalidInput(
            "--image-repository cannot be empty".to_string(),
        ));
    }
    if image_tag.is_empty() {
        return Err(AirGappedError::InvalidInput(
            "--image-tag cannot be empty".to_string(),
        ));
    }

    let ca_crt = fs::read(args.cert_dir.join("ca.crt"))?;
    let server_crt = fs::read(args.cert_dir.join("server").join("tls.crt"))?;
    let server_key = fs::read(args.cert_dir.join("server").join("tls.key"))?;
    let raft_ca = fs::read(args.cert_dir.join("raft").join("ca.crt"))?;
    let raft_crt = fs::read(args.cert_dir.join("raft").join("tls.crt"))?;
    let raft_key = fs::read(args.cert_dir.join("raft").join("tls.key"))?;

    let containerd_dir = args.out.join("containerd");
    let k8s_dir = args.out.join("k8s");
    let helm_dir = args.out.join("helm");
    fs::create_dir_all(&containerd_dir)?;
    fs::create_dir_all(&k8s_dir)?;
    fs::create_dir_all(&helm_dir)?;

    let hosts_path = containerd_dir.join("hosts.toml");
    let install_path = containerd_dir.join("install.md");
    let server_secret_path = k8s_dir.join("server-tls-secret.yaml");
    let raft_secret_path = k8s_dir.join("raft-mtls-secret.yaml");
    let server_tls_path = k8s_dir.join("server-tls-config.toml");
    let raft_tls_path = k8s_dir.join("raft-tls-config.toml");
    let pull_secret_path = k8s_dir.join("image-pull-secret.example.yaml");
    let helm_values_path = helm_dir.join("values-air-gapped.yaml");
    let ca_copy_path = containerd_dir.join("ca.crt");
    let readme_path = args.out.join("README.md");

    ensure_writable(
        &[
            &hosts_path,
            &install_path,
            &ca_copy_path,
            &server_secret_path,
            &raft_secret_path,
            &server_tls_path,
            &raft_tls_path,
            &pull_secret_path,
            &helm_values_path,
            &readme_path,
        ],
        args.overwrite,
    )?;

    let hosts = containerd_hosts(&registry_endpoint);
    let install = containerd_install_md(&registry_endpoint);
    let server_secret = kubernetes_tls_secret(
        &args.namespace,
        &args.server_tls_secret,
        &server_crt,
        &server_key,
    );
    let raft_secret = kubernetes_raft_tls_secret(
        &args.namespace,
        &args.raft_tls_secret,
        &raft_ca,
        &raft_crt,
        &raft_key,
    );
    let server_tls = server_tls_config(&args.server_tls_secret);
    let raft_tls = raft_tls_config(&args.raft_tls_secret);
    let pull_secret = image_pull_secret_example(&args.namespace, &registry_endpoint);
    let helm_values = helm_values(
        &args.namespace,
        &registry_endpoint,
        &args.server_tls_secret,
        &args.raft_tls_secret,
        image_repository,
        image_tag,
    );
    let readme = bundle_readme(
        &registry_endpoint,
        &args.namespace,
        &args.server_tls_secret,
        &args.raft_tls_secret,
    );

    write_file(&hosts_path, hosts.as_bytes(), false)?;
    write_file(&install_path, install.as_bytes(), false)?;
    write_file(&server_secret_path, server_secret.as_bytes(), false)?;
    write_file(&raft_secret_path, raft_secret.as_bytes(), false)?;
    write_file(&server_tls_path, server_tls.as_bytes(), false)?;
    write_file(&raft_tls_path, raft_tls.as_bytes(), false)?;
    write_file(&pull_secret_path, pull_secret.as_bytes(), false)?;
    write_file(&helm_values_path, helm_values.as_bytes(), false)?;
    write_file(&readme_path, readme.as_bytes(), false)?;

    // Keep a copy beside the generated snippets so operators can distribute it
    // through their normal node-management channel.
    write_file(&ca_copy_path, &ca_crt, false)?;

    println!(
        "Generated Kubernetes/containerd bundle in {}",
        args.out.display()
    );
    Ok(())
}

fn validate_registry_host(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AirGappedError::InvalidInput(
            "registry host cannot be empty".to_string(),
        ));
    }
    if value.contains("://") || value.contains('/') {
        return Err(AirGappedError::InvalidInput(format!(
            "registry host must not include scheme or path: {value}"
        )));
    }
    if value.contains(':') && value.parse::<IpAddr>().is_err() {
        return Err(AirGappedError::InvalidInput(format!(
            "registry host must not include a port: {value}"
        )));
    }
    Ok(value.to_string())
}

fn validate_registry_endpoint(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AirGappedError::InvalidInput(
            "registry endpoint cannot be empty".to_string(),
        ));
    }
    if value.contains("://") || value.contains('/') {
        return Err(AirGappedError::InvalidInput(format!(
            "registry endpoint must be host[:port], without scheme or path: {value}"
        )));
    }
    Ok(value.to_string())
}

fn raft_dns_sans(
    statefulset_name: &str,
    headless_service: &str,
    namespace: &str,
    replicas: u16,
) -> Vec<String> {
    let mut sans = BTreeSet::new();
    sans.insert(headless_service.to_string());
    sans.insert(format!("{headless_service}.{namespace}.svc"));
    sans.insert(format!("{headless_service}.{namespace}.svc.cluster.local"));
    sans.insert(format!("*.{headless_service}"));
    sans.insert(format!("*.{headless_service}.{namespace}.svc"));
    sans.insert(format!(
        "*.{headless_service}.{namespace}.svc.cluster.local"
    ));
    for ordinal in 0..replicas {
        let pod = format!("{statefulset_name}-{ordinal}");
        sans.insert(pod.clone());
        sans.insert(format!("{pod}.{headless_service}"));
        sans.insert(format!("{pod}.{headless_service}.{namespace}.svc"));
        sans.insert(format!(
            "{pod}.{headless_service}.{namespace}.svc.cluster.local"
        ));
    }
    sans.into_iter().collect()
}

fn ensure_writable(paths: &[&Path], overwrite: bool) -> Result<()> {
    if overwrite {
        return Ok(());
    }
    for path in paths {
        if path.exists() {
            return Err(AirGappedError::InvalidInput(format!(
                "{} already exists; pass --overwrite to replace generated files",
                path.display()
            )));
        }
    }
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    fs::write(path, bytes)?;
    if private {
        set_private_permissions(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn days(value: u32) -> Duration {
    Duration::days(i64::from(value))
}

fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    match default {
        Some(default) => print!("{label} [{default}]: "),
        None => print!("{label}: "),
    }
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if input.is_empty() {
        default
            .map(str::to_string)
            .ok_or_else(|| AirGappedError::InvalidInput(format!("{label} is required")))
    } else {
        Ok(input.to_string())
    }
}

fn prompt_bool(label: &str, default: bool) -> Result<bool> {
    let default_text = if default { "Y/n" } else { "y/N" };
    loop {
        let value = prompt(label, Some(default_text))?;
        match value.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            "y/n" => return Ok(default),
            _ => eprintln!("Please answer yes or no."),
        }
    }
}

fn containerd_hosts(endpoint: &str) -> String {
    format!(
        r#"server = "https://{endpoint}"

[host."https://{endpoint}"]
  capabilities = ["pull", "resolve", "push"]
  ca = "/etc/containerd/certs.d/{endpoint}/ca.crt"
"#
    )
}

fn containerd_install_md(endpoint: &str) -> String {
    format!(
        r#"# containerd trust install

Install `ca.crt` and `hosts.toml` on every Kubernetes node through your normal
node-management path.

Target paths:

```text
/etc/containerd/certs.d/{endpoint}/ca.crt
/etc/containerd/certs.d/{endpoint}/hosts.toml
```

Restart or reload containerd according to your node OS.

Verify from a node:

```bash
crictl pull {endpoint}/qa/alpine:v1
```
"#
    )
}

fn kubernetes_tls_secret(namespace: &str, name: &str, cert: &[u8], key: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {name}
  namespace: {namespace}
type: kubernetes.io/tls
data:
  tls.crt: {}
  tls.key: {}
"#,
        b64.encode(cert),
        b64.encode(key)
    )
}

fn server_tls_config(secret_name: &str) -> String {
    format!(
        r#"# Mount Kubernetes Secret `{secret_name}` at /etc/layerhouse/tls.
[server.tls]
cert_path = "/etc/layerhouse/tls/tls.crt"
key_path = "/etc/layerhouse/tls/tls.key"
"#
    )
}

fn raft_tls_config(secret_name: &str) -> String {
    format!(
        r#"# Mount Kubernetes Secret `{secret_name}` at /etc/layerhouse/raft-tls.
[raft]
listen = "0.0.0.0:5051"

[raft.tls]
cert_path = "/etc/layerhouse/raft-tls/tls.crt"
key_path = "/etc/layerhouse/raft-tls/tls.key"
server_ca_path = "/etc/layerhouse/raft-tls/server-ca.crt"
client_ca_path = "/etc/layerhouse/raft-tls/client-ca.crt"
"#
    )
}

fn kubernetes_raft_tls_secret(
    namespace: &str,
    name: &str,
    ca: &[u8],
    cert: &[u8],
    key: &[u8],
) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {name}
  namespace: {namespace}
type: Opaque
data:
  tls.crt: {}
  tls.key: {}
  server-ca.crt: {}
  client-ca.crt: {}
"#,
        b64.encode(cert),
        b64.encode(key),
        b64.encode(ca),
        b64.encode(ca)
    )
}

fn helm_values(
    namespace: &str,
    endpoint: &str,
    server_tls_secret: &str,
    raft_tls_secret: &str,
    image_repository: &str,
    image_tag: &str,
) -> String {
    let endpoint_host = endpoint.split(':').next().unwrap_or(endpoint);
    format!(
        r#"replicaCount: 3

image:
  repository: "{image_repository}"
  tag: "{image_tag}"

storage:
  s3:
    existingSecret: layerhouse-s3
    endpoint: "https://s3.internal.example.com"
    bucket: "layerhouse"
    region: "us-east-1"
    pathStyle: true

server:
  tls:
    existingSecret: "{server_tls_secret}"
    dnsNames:
      - "{endpoint_host}"

raft:
  tls:
    existingSecret: "{raft_tls_secret}"

auth:
  enabled: false

namespaceOverride: "{namespace}"
"#
    )
}

fn image_pull_secret_example(namespace: &str, endpoint: &str) -> String {
    format!(
        r#"# Replace USERNAME and TOKEN before applying.
apiVersion: v1
kind: Secret
metadata:
  name: layerhouse-pull
  namespace: {namespace}
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: |
    {{
      "auths": {{
        "{endpoint}": {{
          "username": "USERNAME",
          "password": "TOKEN"
        }}
      }}
    }}
"#
    )
}

fn bundle_readme(
    endpoint: &str,
    namespace: &str,
    server_secret: &str,
    raft_secret: &str,
) -> String {
    format!(
        r#"# Layerhouse Air-Gapped Kubernetes Bundle

Registry endpoint:

```text
{endpoint}
```

Apply registry TLS to Kubernetes:

```bash
kubectl apply -f k8s/server-tls-secret.yaml
kubectl apply -f k8s/raft-mtls-secret.yaml
```

The Helm values file expects Secret `{server_secret}` mounted for registry TLS
and Secret `{raft_secret}` mounted for Raft mTLS in namespace `{namespace}`.

Install with:

```bash
helm upgrade --install layerhouse ./deploy/kubernetes/helm \
  --namespace {namespace} --create-namespace \
  -f helm/values-air-gapped.yaml
```

Install `containerd/ca.crt` and `containerd/hosts.toml` on every node under:

```text
/etc/containerd/certs.d/{endpoint}/
```

Verify:

```bash
curl --cacert certs/ca.crt https://{endpoint}/v2/
crictl pull {endpoint}/qa/alpine:v1
kubectl run layerhouse-pull-test --image={endpoint}/qa/alpine:v1 --restart=Never
```

Keep `certs/ca.key` offline. Do not mount it into Kubernetes.
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_rejects_scheme_path_and_port() {
        assert!(validate_registry_host("https://registry.internal").is_err());
        assert!(validate_registry_host("registry.internal/path").is_err());
        assert!(validate_registry_host("registry.internal:32000").is_err());
        assert_eq!(
            validate_registry_host("registry.internal").unwrap(),
            "registry.internal"
        );
        assert_eq!(validate_registry_host("127.0.0.1").unwrap(), "127.0.0.1");
    }

    #[test]
    fn endpoint_keeps_port_for_containerd_path() {
        let hosts = containerd_hosts("registry.internal:32000");
        assert!(hosts.contains("https://registry.internal:32000"));
        assert!(hosts.contains("/etc/containerd/certs.d/registry.internal:32000/ca.crt"));
    }

    #[test]
    fn tls_secret_does_not_include_ca_key() {
        let yaml = kubernetes_tls_secret("orb", "tls", b"cert", b"key");
        assert!(yaml.contains("kubernetes.io/tls"));
        assert!(yaml.contains("tls.crt"));
        assert!(yaml.contains("tls.key"));
        assert!(!yaml.contains("ca.key"));
    }

    #[test]
    fn raft_sans_cover_statefulset_dns() {
        let sans = raft_dns_sans("layerhouse", "layerhouse-headless", "registry", 2);
        assert!(sans.contains(&"layerhouse-0".to_string()));
        assert!(sans.contains(&"layerhouse-0.layerhouse-headless".to_string()));
        assert!(sans.contains(&"layerhouse-0.layerhouse-headless.registry.svc".to_string()));
        assert!(
            sans.contains(
                &"layerhouse-1.layerhouse-headless.registry.svc.cluster.local".to_string()
            )
        );
        assert!(sans.contains(&"*.layerhouse-headless".to_string()));
        assert!(sans.contains(&"*.layerhouse-headless.registry.svc".to_string()));
        assert!(sans.contains(&"*.layerhouse-headless.registry.svc.cluster.local".to_string()));
    }

    #[test]
    fn raft_secret_does_not_include_ca_key() {
        let yaml = kubernetes_raft_tls_secret("orb", "raft", b"ca", b"cert", b"key");
        assert!(yaml.contains("server-ca.crt"));
        assert!(yaml.contains("client-ca.crt"));
        assert!(yaml.contains("tls.crt"));
        assert!(yaml.contains("tls.key"));
        assert!(!yaml.contains("ca.key"));
    }

    #[test]
    fn helm_values_use_cli_version_and_no_registry_endpoint_value() {
        let yaml = helm_values(
            "layerhouse",
            "registry.internal:32000",
            "layerhouse-server-tls",
            "layerhouse-raft-mtls",
            DEFAULT_IMAGE_REPOSITORY,
            DEFAULT_IMAGE_TAG,
        );

        assert!(yaml.contains(&format!("repository: \"{DEFAULT_IMAGE_REPOSITORY}\"")));
        assert!(yaml.contains(&format!("tag: \"{DEFAULT_IMAGE_TAG}\"")));
        assert!(yaml.contains("dnsNames:\n      - \"registry.internal\""));
        assert!(!yaml.contains("registryEndpoint"));
    }

    #[test]
    fn helm_values_keep_explicit_image_override() {
        let yaml = helm_values(
            "layerhouse",
            "registry.internal",
            "layerhouse-server-tls",
            "layerhouse-raft-mtls",
            "registry.internal/layerhouse-server",
            "v9.9.9",
        );

        assert!(yaml.contains("repository: \"registry.internal/layerhouse-server\""));
        assert!(yaml.contains("tag: \"v9.9.9\""));
    }

    #[test]
    fn bundle_generate_writes_image_overrides() {
        let root = std::env::temp_dir().join(format!(
            "layerhouse-airgap-image-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cert_dir = root.join("certs");
        let out = root.join("out");
        fs::create_dir_all(cert_dir.join("server")).unwrap();
        fs::create_dir_all(cert_dir.join("raft")).unwrap();
        fs::write(cert_dir.join("ca.crt"), b"ca").unwrap();
        fs::write(cert_dir.join("server").join("tls.crt"), b"cert").unwrap();
        fs::write(cert_dir.join("server").join("tls.key"), b"key").unwrap();
        fs::write(cert_dir.join("raft").join("ca.crt"), b"ca").unwrap();
        fs::write(cert_dir.join("raft").join("tls.crt"), b"cert").unwrap();
        fs::write(cert_dir.join("raft").join("tls.key"), b"key").unwrap();

        bundle_generate(BundleGenerateArgs {
            registry_endpoint: "registry.internal:32000".to_string(),
            cert_dir,
            namespace: "layerhouse".to_string(),
            server_tls_secret: "layerhouse-server-tls".to_string(),
            raft_tls_secret: "layerhouse-raft-mtls".to_string(),
            image_repository: "registry.internal/layerhouse-server".to_string(),
            image_tag: "v9.9.9".to_string(),
            out: out.clone(),
            overwrite: false,
        })
        .unwrap();

        let values = fs::read_to_string(out.join("helm").join("values-air-gapped.yaml")).unwrap();
        assert!(values.contains("repository: \"registry.internal/layerhouse-server\""));
        assert!(values.contains("tag: \"v9.9.9\""));
        assert!(!values.contains("registryEndpoint"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bundle_rejects_existing_containerd_ca_without_overwrite() {
        let root = std::env::temp_dir().join(format!(
            "layerhouse-airgap-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cert_dir = root.join("certs");
        let out = root.join("out");
        fs::create_dir_all(cert_dir.join("server")).unwrap();
        fs::create_dir_all(cert_dir.join("raft")).unwrap();
        fs::create_dir_all(out.join("containerd")).unwrap();
        fs::write(cert_dir.join("ca.crt"), b"ca").unwrap();
        fs::write(cert_dir.join("server").join("tls.crt"), b"cert").unwrap();
        fs::write(cert_dir.join("server").join("tls.key"), b"key").unwrap();
        fs::write(cert_dir.join("raft").join("ca.crt"), b"ca").unwrap();
        fs::write(cert_dir.join("raft").join("tls.crt"), b"cert").unwrap();
        fs::write(cert_dir.join("raft").join("tls.key"), b"key").unwrap();
        fs::write(out.join("containerd").join("ca.crt"), b"existing").unwrap();

        let err = bundle_generate(BundleGenerateArgs {
            registry_endpoint: "registry.internal:32000".to_string(),
            cert_dir,
            namespace: "layerhouse".to_string(),
            server_tls_secret: "layerhouse-server-tls".to_string(),
            raft_tls_secret: "layerhouse-raft-mtls".to_string(),
            image_repository: DEFAULT_IMAGE_REPOSITORY.to_string(),
            image_tag: DEFAULT_IMAGE_TAG.to_string(),
            out: out.clone(),
            overwrite: false,
        })
        .unwrap_err();

        assert!(err.to_string().contains("containerd/ca.crt"));
        let _ = fs::remove_dir_all(root);
    }
}
