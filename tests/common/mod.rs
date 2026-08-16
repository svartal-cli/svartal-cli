//! Shared test scaffolding: a transport that answers from a routing function
//! and records what it was asked, and a fixture loader.

#![allow(dead_code)] // Each test binary uses a different slice of this.

use std::cell::RefCell;
use std::path::PathBuf;

use serde_json::Value;
use svartal::http::{Body, HttpError, HttpTransport, Request, Response};

pub fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("fixture {}: {error}", path.display());
    }))
    .unwrap()
}

pub fn json_response(status: u16, body: &Value) -> Response {
    Response { status, body: serde_json::to_vec(body).unwrap() }
}

type Router = Box<dyn Fn(&Request) -> Response>;

pub struct FakeTransport {
    router: Router,
    requests: RefCell<Vec<Request>>,
}

impl FakeTransport {
    pub fn new(router: impl Fn(&Request) -> Response + 'static) -> Self {
        Self { router: Box::new(router), requests: RefCell::new(Vec::new()) }
    }

    /// Every request, in order.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.borrow().clone()
    }

    pub fn urls(&self) -> Vec<String> {
        self.requests.borrow().iter().map(|request| request.url.clone()).collect()
    }

    pub fn count(&self, url: &str) -> usize {
        self.requests.borrow().iter().filter(|request| request.url == url).count()
    }

    /// The form fields of the last request sent to `url`.
    pub fn last_form(&self, url: &str) -> Vec<(String, String)> {
        self.requests
            .borrow()
            .iter()
            .rev()
            .find(|request| request.url == url)
            .and_then(|request| match &request.body {
                Some(Body::Form(fields)) => Some(fields.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    pub fn last_headers(&self, url: &str) -> Vec<(String, String)> {
        self.requests
            .borrow()
            .iter()
            .rev()
            .find(|request| request.url == url)
            .map(|request| request.headers.clone())
            .unwrap_or_default()
    }
}

impl HttpTransport for FakeTransport {
    fn send(&self, request: Request) -> Result<Response, HttpError> {
        let response = (self.router)(&request);
        self.requests.borrow_mut().push(request);
        Ok(response)
    }
}

pub fn form_value(fields: &[(String, String)], name: &str) -> Option<String> {
    fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone())
}

/// A throwaway state directory, removed when the test ends.
///
/// Hand-rolled rather than a crate: the tests need one directory with a name
/// nothing else will pick, and that is a process id, a clock reading and a
/// counter. A test must never write into the real `~/.config/svartal`.
pub struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "svartal-cli-test-{tag}-{}-{nanos}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("temporary directory");
        Self { path }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
