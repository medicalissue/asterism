//! Device-owned image catalog and pull plane.
//!
//! Image bytes belong to the device that stores them. The CLI and a remote
//! management client therefore ask this plane for both the read model and the
//! pull; neither caller is allowed to use its own cache as a proxy for this
//! device's state.

use std::sync::OnceLock;

use asterism_core::image;
use asterism_core::protocol::{Request, Response};
use tokio::sync::Mutex;

static PULL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn pull_lock() -> &'static Mutex<()> {
    PULL_LOCK.get_or_init(|| Mutex::new(()))
}

pub(crate) fn is_plane_request(request: &Request) -> bool {
    matches!(request, Request::ImageList | Request::ImagePull { .. })
}

pub(crate) async fn serve(request: Request) -> Response {
    match request {
        Request::ImageList => match tokio::task::spawn_blocking(image::catalog_rows).await {
            Ok(Ok(images)) => Response::Images { images },
            Ok(Err(error)) => error_response(error),
            Err(error) => error_response(error),
        },
        Request::ImagePull { reference } => {
            // A single daemon must not let two requests race the same
            // staging, conversion, pointer, or provenance files. The lock is
            // device-wide because OCI kernel material is shared too.
            let _guard = pull_lock().lock().await;
            let result = tokio::task::spawn_blocking(move || image::pull(&reference)).await;
            match result {
                Ok(Ok(result)) => Response::ImagePulled {
                    result: Box::new(result),
                },
                Ok(Err(error)) => error_response(error),
                Err(error) => error_response(error),
            }
        }
        other => Response::Error {
            message: format!("{other:?} is not an image request"),
        },
    }
}

fn error_response(error: impl std::fmt::Display) -> Response {
    Response::Error {
        message: format!("{error}"),
    }
}
