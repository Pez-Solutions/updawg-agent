//! How much the agent reads from the network.
//!
//! Every body is read in chunks and abandoned past a limit, so whoever
//! answers can't stream gigabytes into a daemon that runs as root, and an
//! error page can't flood the log.

/// A JSON answer from the gateway: a check-in with its jobs, an enrollment,
/// a renewal. Real ones are a few KiB.
pub(crate) const MAX_RESPONSE: usize = 4 << 20;

/// What is read of an error response, and kept of the message in it.
const MAX_ERROR_BODY: usize = 64 << 10;
const MAX_ERROR_MESSAGE: usize = 500;

/// The body, if it is no larger than `max` bytes.
///
/// # Errors
/// A larger body (by `Content-Length` or as it arrives), or one that broke
/// off, as text for the caller's own error.
pub(crate) async fn body(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, String> {
    let too_big = || format!("the response is larger than the {} KiB allowed", max / 1024);
    if response
        .content_length()
        .is_some_and(|n| n > u64::try_from(max).unwrap_or(u64::MAX))
    {
        return Err(too_big());
    }
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if out.len() + chunk.len() > max {
            return Err(too_big());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// An error response's message: its problem detail, or the start of its
/// text. Never fails; at most [`MAX_ERROR_MESSAGE`] characters.
pub(crate) async fn error_text(response: reqwest::Response) -> String {
    let body = error_body(response).await;
    if body.is_empty() {
        return "no response body".into();
    }
    message(&body)
}

/// An error response's body as text, at most [`MAX_ERROR_BODY`] bytes, for a
/// caller that looks for an error code in it. Never fails.
pub(crate) async fn error_body(mut response: reqwest::Response) -> String {
    let mut out = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        out.extend_from_slice(&chunk);
        if out.len() >= MAX_ERROR_BODY {
            out.truncate(MAX_ERROR_BODY);
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// [`crate::enroll::problem_detail`], cut to [`MAX_ERROR_MESSAGE`]
/// characters.
pub(crate) fn message(body: &str) -> String {
    let detail = crate::enroll::problem_detail(body);
    if detail.chars().count() > MAX_ERROR_MESSAGE {
        let mut cut: String = detail.chars().take(MAX_ERROR_MESSAGE).collect();
        cut.push('…');
        cut
    } else {
        detail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_message_is_cut() {
        let long = format!(r#"{{"code":"x","message":"{}"}}"#, "a".repeat(5000));
        let cut = message(&long);
        assert_eq!(cut.chars().count(), MAX_ERROR_MESSAGE + 1);
        assert!(cut.ends_with('…'));
        assert_eq!(message(r#"{"code":"x","message":"short"}"#), "short");
    }
}
