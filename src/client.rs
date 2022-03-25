//! The client side of Zeekoe's transport layer.

use std::convert::TryFrom;
use {
    dialectic::prelude::*,
    dialectic_reconnect::retry,
    dialectic_tokio_serde::codec::LengthDelimitedCodec,
    dialectic_tokio_serde::{RecvError, SendError},
    dialectic_tokio_serde_bincode::{length_delimited, Bincode},
    std::{io, marker::PhantomData, sync::Arc, time::Duration},
    tokio::net::TcpStream,
    tokio_rustls::{rustls, webpki::DnsName, TlsConnector},
};

use super::{channel::TransportError, handshake};

#[cfg(feature = "allow_explicit_certificate_trust")]
use {super::pem, std::path::Path};

pub use super::channel::ClientChan as Chan;
pub use dialectic_reconnect::Backoff;
pub use handshake::SessionKey;
use rustls::ServerName;

/// The type of errors returned during sessions on a client-side channel.
pub type Error = retry::RetryError<TransportError, io::Error, TransportError>;

#[cfg(all(not(debug_assertions), feature = "allow_explicit_certificate_trust"))]
compile_error!(
    "crate cannot be built for release with the `allow_explicit_certificate_trust` feature enabled"
);

/// A client for some session-typed `Protocol` which connects over TLS with a parameterizable
/// [`Backoff`] strategy for retrying lost connections.
///
///
/// The session type parameter for this type is the session from **the client's perspective.**
/// The session type parameter for this type is the session from **the client's perspective.**
#[derive(Clone)]
pub struct Client<Protocol> {
    /// The number of bytes used to represent the length field in the length-delimited encoding.
    length_field_bytes: usize,
    /// The maximum length, in bytes, of messages to permit in serialization/deserialization.
    /// Receiving or sending any larger messages will result in an error.
    max_length: usize,
    /// The backoff strategy for reconnecting to the server in the event of a connection loss.
    backoff: Backoff,
    /// The maximum permissible number of pending retries.
    max_pending_retries: usize,
    /// The timeout after which broken connections will be garbage-collected.
    timeout: Option<Duration>,
    /// Client TLS configuration.
    tls_config: rustls::ClientConfig,
    /// Client session type.
    client_session: PhantomData<fn() -> Protocol>,
}

impl<Protocol> Client<Protocol>
where
    Protocol: Session,
{
    /// Create a new [`Client`] with the specified [`Backoff`] strategy.
    ///
    /// There is no default backoff strategy, because there is no one-size-fits-all reasonable
    /// default.
    pub fn new(backoff: Backoff) -> Client<Protocol> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Client {
            length_field_bytes: 4,
            max_length: usize::MAX,
            backoff,
            tls_config,
            max_pending_retries: usize::MAX,
            timeout: None,
            client_session: PhantomData,
        }
    }
    ///
    /// The session type parameter for this type is the session from **the client's perspective.**

    /// Set the number of bytes used to represent the length field in the length-delimited encoding.
    pub fn length_field_bytes(&mut self, length_field_bytes: usize) -> &mut Self {
        self.length_field_bytes = length_field_bytes;
        self
    }

    /// Set the maximum length, in bytes, of messages to permit in serialization/deserialization.
    /// Receiving or sending any larger messages will result in an error.
    pub fn max_length(&mut self, max_length: usize) -> &mut Self {
        self.max_length = max_length;
        self
    }

    /// Set a maximum number of pending retries for all future [`Chan`]s produced by this
    /// [`Client`]: an error will be thrown if a channel auto-retries more than this number of times
    /// before the it is able to process the newly reconnected ends.
    ///
    /// Restricting this limit (the default is `usize::MAX`) prevents a potential unbounded memory
    /// leak in the case where one a protocol only ever sends or only ever receives, and encounters
    /// an unbounded number of errors.
    pub fn max_pending_retries(&mut self, max_pending_retries: usize) -> &mut Self {
        self.max_pending_retries = max_pending_retries.saturating_add(1);
        self
    }

    /// Set a timeout for recovery within all future [`Chan`]s produced by this [`Client`]: an
    /// error will be thrown if recovery from an error takes longer than the given timeout, even if
    /// the error recovery strategy specifies trying again.
    pub fn timeout(&mut self, timeout: Option<Duration>) -> &mut Self {
        self.timeout = timeout;
        self
    }

    // Only on non-release builds that explicitly request this capability via the
    // `allow_explicit_certificate_trust` feature, add the auxiliary trusted certificate to the set
    // of trusted certificates. In release builds, it is not possible for the client to trust anyone
    // other than the `webpki_roots::TLS_SERVER_ROOTS`.
    #[cfg(feature = "allow_explicit_certificate_trust")]
    pub fn trust_explicit_certificate(
        &mut self,
        trust_explicit_certificate: impl AsRef<Path>,
    ) -> Result<&mut Self, io::Error> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(&pem::read_single_certificate(trust_explicit_certificate)?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid certificate"))?;
        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        self.tls_config = tls_config;
        Ok(self)
    }

    pub async fn connect_zkchannel(
        &self,
        address: &dyn Address,
    ) -> Result<(SessionKey, Chan<Protocol>), Error> {
        let host = address.get_host();
        let port = address.get_port();
        self.connect(host, port).await
    }

    /// Connect to the given [`DnsName`] and port, returning either a connected [`Chan`] or an
    /// error if connection and all re-connection attempts failed.
    pub async fn connect(
        &self,
        host: &DnsName,
        port: u16,
    ) -> Result<(SessionKey, Chan<Protocol>), Error> {
        // Share the TLS config between all times we connect
        let tls_config = Arc::new(self.tls_config.clone());

        // Address configuration
        let length_field_bytes = self.length_field_bytes;
        let max_length = self.max_length;

        // A closure that connects to the server we want to connect to
        let connect = move |(domain, port): (DnsName, u16)| {
            let tls_config = tls_config.clone();
            async move {
                // Resolve the domain name we wish to connect to
                let address_str: &str = AsRef::as_ref(&domain);
                let mut addresses = tokio::net::lookup_host((address_str, port)).await?;

                // Attempt to connect to any of the socket addresses, succeeding on the first
                let mut connection_error = None;
                let tcp_stream = loop {
                    if let Some(address) = addresses.next() {
                        match TcpStream::connect(address).await {
                            Ok(tcp_stream) => {
                                // Session typed messages may be small; send them immediately
                                tcp_stream.set_nodelay(true)?;
                                break tcp_stream;
                            }
                            Err(e) => connection_error = Some(e),
                        }
                    } else {
                        return Err(connection_error.unwrap_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("unknown domain: {}", address_str),
                            )
                        }));
                    }
                };

                // Wrap a TCP stream in a TLS connection, then wrap that in a Dialectic channel
                let tls_connector = TlsConnector::from(tls_config);
                let tls_stream = tls_connector
                    .connect(ServerName::try_from(address_str).unwrap(), tcp_stream)
                    .await?;
                let (rx, tx) = tokio::io::split(tls_stream);
                let (tx, rx) = length_delimited(tx, rx, length_field_bytes, max_length);
                Ok((tx, rx))
            }
        };

        retry::Connector::new(
            connect,
            handshake::client::init::<_, _, TransportError>,
            handshake::client::retry::<_, _, TransportError>,
            Protocol::default(),
        )
        .recover_rx(reconnect_unless(&self.backoff, permanent_rx_error))
        .recover_tx(reconnect_unless(&self.backoff, permanent_tx_error))
        .recover_connect(reconnect_unless(&self.backoff, permanent_connect_error))
        .recover_handshake(reconnect_unless(&self.backoff, permanent_handshake_error))
        .timeout(self.timeout)
        .max_pending_retries(self.max_pending_retries)
        .connect((host.to_owned(), port))
        .await
        .map_err(|e| {
            // Convert error into general error type
            use retry::RetryError::*;
            match e {
                OriginalError(e) => match e {},
                ConnectError(e) => ConnectError(e),
                ConnectTimeout => ConnectTimeout,
                HandshakeError(e) => HandshakeError(e),
                HandshakeTimeout => HandshakeTimeout,
                HandshakeIncomplete => HandshakeIncomplete,
                NoCapacity => NoCapacity,
            }
        })
    }
}

pub trait Address: Sync {
    fn get_host(&self) -> &DnsName;
    fn get_port(&self) -> u16;
}

/// Given a backoff and a predicate on errors, return a reconnection strategy which uses that
/// backoff unless the predicate returns true. This is marginally more efficient than rebuilding the
/// backoff every time inside a closure.
fn reconnect_unless<E>(
    backoff: &Backoff,
    unless: impl Fn(&E) -> bool,
) -> impl Fn(usize, &E) -> retry::Recovery {
    let backoff = backoff.build(retry::Recovery::ReconnectAfter);
    move |retries, error| {
        if unless(error) {
            retry::Recovery::Fail
        } else {
            backoff(retries, error)
        }
    }
}

/// Determine if a given [`io::ErrorKind`] should be considered a permanent error, or if it should
/// be retried. If this predicate returns `false`, a retry is executed.
fn permanent_error_kind(error_kind: &io::ErrorKind) -> bool {
    matches!(
        error_kind,
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::AddrInUse
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::Unsupported
    )
}

/// Determine if a sending error should be considered permanent.
fn permanent_tx_error(error: &SendError<Bincode, LengthDelimitedCodec>) -> bool {
    permanent_error_kind(&match error {
        SendError::Serialize(err) => match &**err {
            bincode::ErrorKind::Io(err) => err.kind(),
            _ => return true,
        },
        SendError::Encode(err) => err.kind(),
    })
}

/// Determine if a receiving error should be considered permanent.
fn permanent_rx_error(error: &RecvError<Bincode, LengthDelimitedCodec>) -> bool {
    permanent_error_kind(&match error {
        RecvError::Deserialize(err) => match &**err {
            bincode::ErrorKind::Io(err) => err.kind(),
            _ => return true,
        },
        RecvError::Decode(err) => err.kind(),
        RecvError::Closed => return true,
    })
}

/// Determine if a connecting error should be considered permanent.
fn permanent_connect_error(error: &io::Error) -> bool {
    permanent_error_kind(&error.kind())
}

/// Determine if a handshake error should be considered permanent.
fn permanent_handshake_error(error: &TransportError) -> bool {
    match error {
        dialectic_tokio_serde::Error::Send(err) => permanent_tx_error(err),
        dialectic_tokio_serde::Error::Recv(err) => permanent_rx_error(err),
    }
}
