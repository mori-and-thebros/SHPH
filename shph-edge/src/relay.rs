use std::time::Duration;
use thiserror::Error;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const COPY_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("backend connection timed out")]
    BackendTimeout,
    #[error("backend connection failed: {0}")]
    Backend(#[source] io::Error),
    #[error("relay operation timed out while idle")]
    IdleTimeout,
    #[error("relay operation was cancelled")]
    Cancelled,
    #[error("opaque stream exceeded the configured limit")]
    LimitExceeded,
    #[error("opaque stream I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("relay timeout must be non-zero")]
    InvalidTimeout,
}

pub async fn connect_backend(
    endpoint: &str,
    timeout_duration: Duration,
) -> Result<TcpStream, RelayError> {
    if timeout_duration.is_zero() {
        return Err(RelayError::BackendTimeout);
    }
    let stream = timeout(timeout_duration, TcpStream::connect(endpoint))
        .await
        .map_err(|_| RelayError::BackendTimeout)?
        .map_err(RelayError::Backend)?;
    if let Err(error) = stream.set_nodelay(true) {
        tracing::debug!(error = %error, "failed to enable TCP_NODELAY for backend");
    }
    Ok(stream)
}

pub async fn pipe_opaque<A, B>(left: A, right: B, max_bytes: u64) -> Result<(u64, u64), RelayError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    pipe_opaque_with_timeout(left, right, max_bytes, DEFAULT_IDLE_TIMEOUT).await
}

pub(crate) async fn pipe_opaque_with_timeout<A, B>(
    left: A,
    right: B,
    max_bytes: u64,
    idle_timeout: Duration,
) -> Result<(u64, u64), RelayError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    pipe_opaque_with_cancel(
        left,
        right,
        max_bytes,
        idle_timeout,
        CancellationToken::new(),
    )
    .await
}

pub(crate) async fn pipe_opaque_with_cancel<A, B>(
    left: A,
    right: B,
    max_bytes: u64,
    idle_timeout: Duration,
    cancellation: CancellationToken,
) -> Result<(u64, u64), RelayError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if idle_timeout.is_zero() {
        return Err(RelayError::InvalidTimeout);
    }

    let (mut left_read, mut left_write) = io::split(left);
    let (mut right_read, mut right_write) = io::split(right);
    let mut left_to_right = Box::pin(forward_with_cancel(
        &mut left_read,
        &mut right_write,
        max_bytes,
        idle_timeout,
        cancellation.clone(),
    ));
    let mut right_to_left = Box::pin(forward_with_cancel(
        &mut right_read,
        &mut left_write,
        max_bytes,
        idle_timeout,
        cancellation.clone(),
    ));

    tokio::select! {
        result = &mut left_to_right => finish_first_direction(
            result,
            right_to_left,
            &cancellation,
            true,
        ).await,
        result = &mut right_to_left => finish_first_direction(
            result,
            left_to_right,
            &cancellation,
            false,
        ).await,
    }
}

async fn finish_first_direction<F>(
    first: Result<u64, RelayError>,
    second: F,
    cancellation: &CancellationToken,
    first_is_left_to_right: bool,
) -> Result<(u64, u64), RelayError>
where
    F: std::future::Future<Output = Result<u64, RelayError>>,
{
    match first {
        Ok(first_total) => match second.await {
            Ok(second_total) if first_is_left_to_right => Ok((first_total, second_total)),
            Ok(second_total) => Ok((second_total, first_total)),
            Err(error) => Err(error),
        },
        Err(error) => {
            cancellation.cancel();
            let _ = second.await;
            Err(error)
        }
    }
}

pub(crate) async fn forward_with_cancel<R, W>(
    reader: &mut R,
    writer: &mut W,
    max_bytes: u64,
    idle_timeout: Duration,
    cancellation: CancellationToken,
) -> Result<u64, RelayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if idle_timeout.is_zero() {
        return Err(RelayError::InvalidTimeout);
    }

    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    let mut total = 0u64;
    loop {
        let read = read_with_cancel(reader, &mut buffer, idle_timeout, &cancellation).await?;
        if read == 0 {
            shutdown_with_cancel(writer, idle_timeout, &cancellation).await?;
            return Ok(total);
        }

        total = total
            .checked_add(read as u64)
            .ok_or(RelayError::LimitExceeded)?;
        if total > max_bytes {
            return Err(RelayError::LimitExceeded);
        }
        write_all_with_cancel(writer, &buffer[..read], idle_timeout, &cancellation).await?;
    }
}

pub(crate) async fn read_with_cancel<R>(
    reader: &mut R,
    buffer: &mut [u8],
    idle_timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<usize, RelayError>
where
    R: AsyncRead + Unpin,
{
    if idle_timeout.is_zero() {
        return Err(RelayError::InvalidTimeout);
    }
    tokio::select! {
        _ = cancellation.cancelled() => Err(RelayError::Cancelled),
        result = timeout(idle_timeout, reader.read(buffer)) => {
            result.map_err(|_| RelayError::IdleTimeout)?.map_err(RelayError::Io)
        }
    }
}

pub(crate) async fn write_all_with_cancel<W>(
    writer: &mut W,
    buffer: &[u8],
    idle_timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<(), RelayError>
where
    W: AsyncWrite + Unpin,
{
    if idle_timeout.is_zero() {
        return Err(RelayError::InvalidTimeout);
    }
    tokio::select! {
        _ = cancellation.cancelled() => Err(RelayError::Cancelled),
        result = timeout(idle_timeout, writer.write_all(buffer)) => {
            result.map_err(|_| RelayError::IdleTimeout)?.map_err(RelayError::Io)
        }
    }
}

pub(crate) async fn shutdown_with_cancel<W>(
    writer: &mut W,
    idle_timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<(), RelayError>
where
    W: AsyncWrite + Unpin,
{
    if idle_timeout.is_zero() {
        return Err(RelayError::InvalidTimeout);
    }
    tokio::select! {
        _ = cancellation.cancelled() => Err(RelayError::Cancelled),
        result = timeout(idle_timeout, writer.shutdown()) => {
            result.map_err(|_| RelayError::IdleTimeout)?.map_err(RelayError::Io)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn pipe_preserves_half_close_in_both_directions() {
        let (mut client, relay_left) = tokio::io::duplex(128);
        let (mut backend, relay_right) = tokio::io::duplex(128);
        let relay = tokio::spawn(pipe_opaque_with_timeout(
            relay_left,
            relay_right,
            1024,
            Duration::from_secs(1),
        ));

        client.write_all(b"request").await.expect("request write");
        client.shutdown().await.expect("client half-close");

        let mut request = [0u8; 7];
        backend
            .read_exact(&mut request)
            .await
            .expect("backend request");
        assert_eq!(&request, b"request");

        let mut one = [0u8; 1];
        let backend_eof = tokio::time::timeout(Duration::from_secs(1), backend.read(&mut one))
            .await
            .expect("backend EOF timeout")
            .expect("backend EOF read");
        assert_eq!(backend_eof, 0);

        backend
            .write_all(b"response")
            .await
            .expect("response write");
        backend.shutdown().await.expect("backend half-close");

        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("client response");
        assert_eq!(response, b"response");
        assert_eq!(
            relay.await.expect("relay task").expect("relay result"),
            (7, 8)
        );
    }

    #[tokio::test]
    async fn pipe_times_out_when_both_sides_are_idle() {
        let (_client, relay_left) = tokio::io::duplex(64);
        let (_backend, relay_right) = tokio::io::duplex(64);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            pipe_opaque_with_timeout(relay_left, relay_right, 1024, Duration::from_millis(25)),
        )
        .await
        .expect("relay should not hang")
        .expect_err("idle relay must fail");
        assert!(matches!(result, RelayError::IdleTimeout));
    }

    #[tokio::test]
    async fn pipe_cancellation_stops_blocked_directions() {
        let (_client, relay_left) = tokio::io::duplex(64);
        let (_backend, relay_right) = tokio::io::duplex(64);
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(pipe_opaque_with_cancel(
            relay_left,
            relay_right,
            1024,
            Duration::from_secs(30),
            cancellation.clone(),
        ));

        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("cancelled relay should stop")
            .expect("relay task");
        assert!(matches!(result, Err(RelayError::Cancelled)));
    }

    #[tokio::test]
    async fn pipe_enforces_each_direction_limit() {
        let (mut client, relay_left) = tokio::io::duplex(128);
        let (_backend, relay_right) = tokio::io::duplex(128);
        let relay = tokio::spawn(pipe_opaque_with_timeout(
            relay_left,
            relay_right,
            3,
            Duration::from_secs(1),
        ));

        client.write_all(b"four").await.expect("client write");
        let result = tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .expect("limited relay should stop")
            .expect("relay task");
        assert!(matches!(result, Err(RelayError::LimitExceeded)));
    }

    #[tokio::test]
    async fn zero_idle_timeout_is_rejected_before_io() {
        let (_left, relay_left) = tokio::io::duplex(64);
        let (_right, relay_right) = tokio::io::duplex(64);
        let result = pipe_opaque_with_timeout(relay_left, relay_right, 1024, Duration::ZERO).await;
        assert!(matches!(result, Err(RelayError::InvalidTimeout)));
    }

    #[tokio::test]
    async fn repeated_short_sessions_finish_without_hanging() {
        let mut tasks = Vec::new();
        for _ in 0..32 {
            tasks.push(tokio::spawn(async {
                let (mut client, relay_left) = tokio::io::duplex(128);
                let (mut backend, relay_right) = tokio::io::duplex(128);
                let relay = tokio::spawn(pipe_opaque_with_timeout(
                    relay_left,
                    relay_right,
                    1024,
                    Duration::from_secs(1),
                ));

                client.write_all(b"request").await.expect("request write");
                client.shutdown().await.expect("client half-close");

                let mut request = [0u8; 7];
                backend
                    .read_exact(&mut request)
                    .await
                    .expect("backend request");
                backend
                    .write_all(b"response")
                    .await
                    .expect("response write");
                backend.shutdown().await.expect("backend half-close");

                let mut response = Vec::new();
                client
                    .read_to_end(&mut response)
                    .await
                    .expect("client response");
                assert_eq!(response, b"response");
                assert_eq!(
                    relay.await.expect("relay task").expect("relay result"),
                    (7, 8)
                );
            }));
        }

        tokio::time::timeout(Duration::from_secs(2), async {
            for task in tasks {
                task.await.expect("short session task");
            }
        })
        .await
        .expect("short sessions should all finish");
    }
}
