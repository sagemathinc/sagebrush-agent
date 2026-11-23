//! The S3 backend rustic_core reads and writes through. It follows rustic_backend's OpenDAL backend (the same fork,
//! Apache-2.0 OR MIT), narrowed to one service with our own HTTP client: https only (except the test-only loopback
//! feature), no redirect followed, system roots, no option that weakens TLS, and credentials only from the handle
//! (never from the environment, AWS config files or instance metadata).

use std::{sync::OnceLock, time::Duration};

use bytes::Bytes;
use log::trace;
use opendal::{
    blocking::Operator,
    layers::RetryLayer,
    options::{ListOptions, ReadOptions},
    HttpTransporter, OperationContext,
};
use opendal_http_transport_reqwest::ReqwestTransport;
use rustic_core::{BytesList, ErrorKind, FileType, Id, ReadBackend, RusticError, RusticResult, WriteBackend, ALL_FILE_TYPES};
use tokio::runtime::Runtime;

use crate::config::Destination;
use crate::error::{Fail, Result};

/// One request (a pack can be large) may take this long.
const TIMEOUT: Duration = Duration::from_secs(600);
const RETRIES: usize = 5;

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("a tokio runtime"))
}

/// The HTTP client: no redirects (a redirect to another host is refused, design §2), https only unless the
/// test-only loopback endpoint was accepted, and reqwest's verified TLS with system roots.
pub fn http_client(plain_http: bool) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!plain_http)
        .timeout(TIMEOUT)
        .build()
        .map_err(|e| Fail::new("destination_refused", format!("couldn't build the HTTP client: {e}")))
}

#[derive(Clone, Debug)]
pub struct S3Backend {
    operator: Operator,
    location: String,
}

impl S3Backend {
    pub fn new(d: &Destination) -> Result<Self> {
        let client = http_client(d.plain_http)?;
        let context = OperationContext::new().with_http_transport(HttpTransporter::new(ReqwestTransport::new(client)));
        // A typed builder, not a string-keyed option map: nothing from the person's config reaches OpenDAL except
        // these values, and the AWS environment, config files and instance metadata are never consulted.
        let builder = opendal::services::S3::default()
            .bucket(&d.bucket)
            .root(&format!("/{}", d.prefix))
            .endpoint(&d.endpoint)
            .region(&d.region)
            .access_key_id(&d.access_key_id)
            .secret_access_key(&d.secret_access_key)
            .disable_config_load()
            .disable_ec2_metadata();
        let op = opendal::Operator::new(builder)
            .map_err(|e| Fail::new("destination_refused", format!("couldn't configure the S3 destination: {}", e.kind())))?
            .with_context(context)
            .layer(RetryLayer::new().with_max_times(RETRIES).with_jitter());
        let _guard = runtime().enter();
        let operator = Operator::new(op).map_err(|e| Fail::new("destination_refused", format!("couldn't open the S3 destination: {}", e.kind())))?;
        Ok(Self { operator, location: format!("s3:{}/{}", d.bucket, d.prefix) })
    }

    fn path(tpe: FileType, id: &Id) -> String {
        let hex = id.to_hex();
        match tpe {
            FileType::Config => "config".to_string(),
            FileType::Pack => format!("data/{}/{}", &hex[0..2], &hex[..]),
            _ => format!("{}/{}", tpe.dirname(), &hex[..]),
        }
    }
}

fn backend_err(what: &'static str, path: &str, err: opendal::Error) -> Box<RusticError> {
    RusticError::with_source(ErrorKind::Backend, "{what} `{path}` failed in the S3 backend.", err)
        .attach_context("what", what)
        .attach_context("path", path.to_string())
}

impl ReadBackend for S3Backend {
    fn location(&self) -> String {
        self.location.clone()
    }

    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        trace!("listing {tpe:?}");
        let size = |len: u64| u32::try_from(len).ok();
        if tpe == FileType::Config {
            return match self.operator.stat("config") {
                Ok(meta) => Ok(vec![(Id::default(), size(meta.content_length()).unwrap_or_default())]),
                Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(Vec::new()),
                Err(e) => Err(backend_err("Reading the metadata of", "config", e)),
            };
        }
        let dir = format!("{}/", tpe.dirname());
        let lister = self
            .operator
            .lister_options(&dir, ListOptions { recursive: true, ..Default::default() })
            .map_err(|e| backend_err("Listing", &dir, e))?;
        let mut out = Vec::new();
        for entry in lister {
            // (a listing error must fail the operation: a silently short list could let prune or check miss a file)
            let entry = entry.map_err(|e| backend_err("Listing", &dir, e))?;
            let meta = entry.metadata();
            if !meta.is_file() {
                continue;
            }
            let Some(id) = Id::parse_some(entry.name(), tpe) else { continue };
            let Some(len) = size(meta.content_length()) else {
                return Err(RusticError::new(ErrorKind::Backend, "A file in `{dir}` is larger than 4 GiB.").attach_context("dir", dir.clone()));
            };
            out.push((id, len));
        }
        Ok(out)
    }

    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
        let path = Self::path(tpe, id);
        Ok(self.operator.read(&path).map_err(|e| backend_err("Reading", &path, e))?.to_bytes())
    }

    /// Warm-up commands aren't used (no cold storage tier); the object key, for completeness.
    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        Self::path(tpe, id)
    }

    fn read_partial(&self, tpe: FileType, id: &Id, _cacheable: bool, offset: u32, length: u32) -> RusticResult<Bytes> {
        let path = Self::path(tpe, id);
        let range = u64::from(offset)..u64::from(offset) + u64::from(length);
        Ok(self
            .operator
            .read_options(&path, ReadOptions { range: range.into(), ..Default::default() })
            .map_err(|e| backend_err("Partially reading", &path, e))?
            .to_bytes())
    }
}

impl WriteBackend for S3Backend {
    fn create(&self) -> RusticResult<()> {
        for tpe in ALL_FILE_TYPES {
            let dir = format!("{}/", tpe.dirname());
            self.operator.create_dir(&dir).map_err(|e| backend_err("Creating", &dir, e))?;
        }
        for i in 0u8..=255 {
            let dir = format!("data/{i:02x}/");
            self.operator.create_dir(&dir).map_err(|e| backend_err("Creating", &dir, e))?;
        }
        Ok(())
    }

    fn write_bytes(&self, tpe: FileType, id: &Id, _cacheable: bool, content: BytesList) -> RusticResult<()> {
        let path = Self::path(tpe, id);
        _ = self.operator.write(&path, content.into_vec()).map_err(|e| backend_err("Writing", &path, e))?;
        Ok(())
    }

    fn remove(&self, tpe: FileType, id: &Id, _cacheable: bool) -> RusticResult<()> {
        let path = Self::path(tpe, id);
        self.operator.delete(&path).map_err(|e| backend_err("Deleting", &path, e))?;
        Ok(())
    }
}
