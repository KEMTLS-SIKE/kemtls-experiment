use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};

use mio;
use mio::net::{TcpListener, TcpStream};

#[macro_use]
extern crate log;

use std::ascii;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net;

use anyhow::{anyhow, Result};
use futures::{StreamExt, TryFutureExt};

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;

use env_logger;

use rustls;
use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
    RootCertStore, Session,
};
use rustls::internal::kems::{DEFAULT_GROUP,KeyExchange,KexAlgorithm,sike_deinit};

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

// Which mode the server operates in.
#[derive(Clone)]
enum ServerMode {
    /// Write back received bytes
    Echo,

    /// Do one read, then write a bodged HTTP response and
    /// cleanly close the connection.
    Http,

    /// Forward traffic to/from given port on localhost.
    Forward(u16),
}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: TcpListener,
    connections: HashMap<mio::Token, Connection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    mode: ServerMode,
}

impl TlsServer {
    fn new(server: TcpListener, mode: ServerMode, cfg: Arc<rustls::ServerConfig>) -> TlsServer {
        TlsServer {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            mode,
        }
    }

    fn accept(&mut self, registry: &mio::Registry) -> Result<(), io::Error> {
        loop {
            match self.server.accept() {
                Ok((socket, addr)) => {
                    debug!("Accepting new connection from {:?}", addr);
                    socket.set_nodelay(false)?; // Nagle algorithm switch

                    let tls_session = rustls::ServerSession::new(&self.tls_config);
                    let mode = self.mode.clone();

                    let token = mio::Token(self.next_id);
                    self.next_id += 1;

                    let mut connection = Connection::new(socket, token, mode, tls_session);
                    connection.register(registry);
                    self.connections
                        .insert(token, connection);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    println!(
                        "encountered error while accepting connection; err={:?}",
                        err
                    );
                    return Err(err);
                }
            }
        }
    }

    fn conn_event(&mut self, registry: &mio::Registry, event: &mio::event::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections
                .get_mut(&token)
                .unwrap()
                .ready(registry, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream, a TLS-level session, and some
/// other state/metadata.
struct Connection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    mode: ServerMode,
    tls_session: rustls::ServerSession,
    back: Option<TcpStream>,
    sent_http_response: bool,
}

/// Open a plaintext TCP-level connection for forwarded connections.
fn open_back(mode: &ServerMode) -> Option<TcpStream> {
    match *mode {
        ServerMode::Forward(ref port) => {
            let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), *port);
            let conn = TcpStream::connect(net::SocketAddr::V4(addr)).unwrap();
            Some(conn)
        }
        _ => None,
    }
}

/// This used to be conveniently exposed by mio: map EWOULDBLOCK
/// errors to something less-errory.
fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

impl Connection {
    fn new(
        socket: TcpStream,
        token: mio::Token,
        mode: ServerMode,
        tls_session: rustls::ServerSession,
    ) -> Connection {
        let back = open_back(&mode);
        Connection {
            socket,
            token,
            closing: false,
            closed: false,
            mode,
            tls_session,
            back,
            sent_http_response: false,
        }
    }

    /// We're a connection, and we have something to do.
    fn ready(&mut self, registry: &mio::Registry, ev: &mio::event::Event) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        if ev.is_readable() {
            self.do_tls_read();
            self.try_plain_read();
            self.try_back_read();
        }

        if ev.is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing {
            let _ = self
                .socket
                .shutdown(net::Shutdown::Both);
            self.close_back();
            self.closed = true;
            self.deregister(registry);
        } else {
            self.reregister(registry);
        }
    }

    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if self.back.is_some() {
            let back = self.back.as_mut().unwrap();
            back.shutdown(net::Shutdown::Both)
                .unwrap();
        }
        self.back = None;
    }

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        let rc = self
            .tls_session
            .read_tls(&mut self.socket);
        if rc.is_err() {
            let err = rc.unwrap_err();

            if let io::ErrorKind::WouldBlock = err.kind() {
                return;
            }

            error!("read error {:?}", err);
            self.closing = true;
            return;
        }

        if rc.unwrap() == 0 {
            debug!("eof");
            self.closing = true;
            return;
        }

        // Process newly-received TLS messages.
        let socket = &mut self.socket;
        let processed = self.tls_session.process_new_packets(Some(socket));

        if processed.is_err() {
            error!("cannot process packet: {:?}", processed);

            // last gasp write to send any alerts
            self.do_tls_write_and_handle_error();

            self.closing = true;
            return;
        }
    }

    fn try_plain_read(&mut self) {
        // Read and process all available plaintext.
        let mut buf = Vec::new();

        let rc = self.tls_session.read_to_end(&mut buf);
        if rc.is_err() {
            error!("plaintext read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        if !buf.is_empty() {
            debug!("plaintext read {:?}", buf.len());
            self.incoming_plaintext(&buf);
        }
    }

    fn try_back_read(&mut self) {
        if self.back.is_none() {
            return;
        }

        // Try a non-blocking read.
        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("backend read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        let maybe_len = rc.unwrap();

        // If we have a successful but empty read, that's an EOF.
        // Otherwise, we shove the data into the TLS session.
        match maybe_len {
            Some(len) if len == 0 => {
                debug!("back eof");
                self.closing = true;
            }
            Some(len) => {
                self.tls_session
                    .write_all(&buf[..len])
                    .unwrap();
            }
            None => {}
        };
    }

    /// Process some amount of received plaintext.
    fn incoming_plaintext(&mut self, buf: &[u8]) {
        match self.mode {
            ServerMode::Echo => {
                self.tls_session.write_all(buf).unwrap();
            }
            ServerMode::Http => {
                self.send_http_response_once();
            }
            ServerMode::Forward(_) => {
                self.back
                    .as_mut()
                    .unwrap()
                    .write_all(buf)
                    .unwrap();
            }
        }
    }

    fn send_http_response_once(&mut self) {
        let response =
            b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n";
        if !self.sent_http_response {
            self.tls_session
                .write_all(response)
                .unwrap();
            self.sent_http_response = true;
            self.tls_session.send_close_notify();
        }
    }

    fn tls_write(&mut self) -> io::Result<usize> {
        self.tls_session
            .write_tls(&mut self.socket)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    fn register(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .register(&mut self.socket, self.token, event_set)
            .unwrap();

        if self.back.is_some() {
            registry
                .register(
                    self.back.as_mut().unwrap(),
                    self.token,
                    mio::Interest::READABLE,
                )
                .unwrap();
        }
    }

    fn reregister(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .reregister(&mut self.socket, self.token, event_set)
            .unwrap();
    }

    fn deregister(&mut self, registry: &mio::Registry) {
        registry
            .deregister(&mut self.socket)
            .unwrap();

        if self.back.is_some() {
            registry
                .deregister(self.back.as_mut().unwrap())
                .unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self) -> mio::Interest {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

const USAGE: &'static str = "
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each
connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [options] echo
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [options] http
  tlsserver --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [options] forward <fport>
  tlsserver (--version | -v)
  tlsserver (--help | -h)

Options:
    -p, --port PORT         Listen on PORT [default: 443].
    --certs CERTFILE        Read server certificates from CERTFILE.
                            This should contain PEM-format certificates
                            in the right order (the first certificate should
                            certify KEYFILE, the last should be a root CA).
    --key KEYFILE           Read private key from KEYFILE.  This should be a RSA
                            private key or PKCS8-encoded private key, in PEM format.
    --ocsp OCSPFILE         Read DER-encoded OCSP response from OCSPFILE and staple
                            to certificate.  Optional.
    --auth CERTFILE         Enable client authentication, and accept certificates
                            signed by those roots provided in CERTFILE.
    --require-auth          Send a fatal alert if the client does not complete client
                            authentication.
    --resumption            Support session resumption.
    --tickets               Support tickets.
    --protover VERSION      Disable default TLS version list, and use
                            VERSION instead.  May be used multiple times.
    --suite SUITE           Disable default cipher suite list, and use
                            SUITE instead.  May be used multiple times.
    --proto PROTOCOL        Negotiate PROTOCOL using ALPN.
                            May be used multiple times.
    --async-encapsulation   Activate async encapsulation optimization.
    --split-encapsulation   Activate split encapsulation optimization.
    --quic                  Use Quic instead of TLS.
    --verbose               Emit log output.
    --version, -v           Show tool version.
    --help, -h              Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_echo: bool,
    cmd_http: bool,
    cmd_forward: bool,
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_certs: Option<String>,
    flag_key: Option<String>,
    flag_ocsp: Option<String>,
    flag_auth: Option<String>,
    flag_require_auth: bool,
    flag_resumption: bool,
    flag_tickets: bool,
    flag_async_encapsulation: bool,
    flag_split_encapsulation: bool,
    flag_quic: bool,
    arg_fport: Option<u16>,
}

fn find_suite(name: &str) -> Option<&'static rustls::SupportedCipherSuite> {
    for suite in &rustls::ALL_CIPHERSUITES {
        let sname = format!("{:?}", suite.suite).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(suite);
        }
    }

    None
}

fn lookup_suites(suites: &[String]) -> Vec<&'static rustls::SupportedCipherSuite> {
    let mut out = Vec::new();

    for csname in suites {
        let scs = find_suite(csname);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up ciphersuite '{}'", csname),
        }
    }

    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<rustls::ProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => rustls::ProtocolVersion::TLSv1_2,
            "1.3" => rustls::ProtocolVersion::TLSv1_3,
            _ => panic!(
                "cannot look up version '{}', valid are '1.2' and '1.3'",
                vname
            ),
        };
        out.push(version);
    }

    out
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn load_ocsp(filename: &Option<String>) -> Vec<u8> {
    let mut ret = Vec::new();

    if let &Some(ref name) = filename {
        fs::File::open(name)
            .expect("cannot open ocsp file")
            .read_to_end(&mut ret)
            .unwrap();
    }

    ret
}

fn make_config(args: &Args, config: &mut rustls::ServerConfig) -> Result<()> {
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let certs = load_certs(
        args.flag_certs
            .as_ref()
            .expect("--certs option missing"),
    );
    let privkey = load_private_key(
        args.flag_key
            .as_ref()
            .expect("--key option missing"),
    );
    let ocsp = load_ocsp(&args.flag_ocsp);
    config
        .set_single_cert_with_ocsp_and_sct(certs, privkey, ocsp, vec![])
        .expect("bad certificates/private key");

    if !args.flag_suite.is_empty() {
        config.ciphersuites = lookup_suites(&args.flag_suite);
    }

    if !args.flag_protover.is_empty() {
        config.versions = lookup_versions(&args.flag_protover);
    }

    if args.flag_resumption {
        config.set_persistence(rustls::ServerSessionMemoryCache::new(256));
    }

    if args.flag_tickets {
        config.ticketer = rustls::Ticketer::new();
    }

    config.set_protocols(
        &args
            .flag_proto
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect::<Vec<_>>()[..],
    );

    config.async_encapsulation = args.flag_async_encapsulation;
    config.split_encapsulation = args.flag_split_encapsulation;

    // Pre-compute the batch of keys, so that the first call doesn't count in the benchmark
    if config.async_encapsulation || config.split_encapsulation {
        let alg = KeyExchange::named_group_to_ecdh_alg(DEFAULT_GROUP).ok_or(anyhow!("failed to init kem"))?;
        match alg {
            KexAlgorithm::KEM(kem) => {
                kem.init()?;
            },
            _ => {
                panic!("Tried to use async keypair on a Ring Algorithm")
            }
        };
    }

    if args.flag_quic {
        config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    }

    Ok(())
}



async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;
    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            tokio::spawn(
                handle_request(stream)
                    .unwrap_or_else(move |e| error!("failed: {reason}", reason = e.to_string())),
            );
        }
        Ok(())
    }
    .await?;
    Ok(())
}

async fn handle_request(
    (mut send, recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;
    let mut escaped = String::new();
    for &x in &req[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(std::str::from_utf8(&part).unwrap());
    }
    // Execute the request
    let resp =
        b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n";

    // Write the response
    send.write_all(resp)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;
    // Gracefully terminate the stream
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    info!("complete");
    Ok(())
}

fn main() {
    let code = {
        if let Err(e) = run() {
            eprintln!("ERROR: {}", e);
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run() -> Result<()> {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let should_stop = Arc::new(AtomicBool::new(false));
    // copy to move into ctrlc handler
    let stopper = should_stop.clone();

    ctrlc::set_handler(move || {
        stopper.store(true, Ordering::Relaxed);
    }).unwrap();

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    let mut addr: net::SocketAddr = "0.0.0.0:443".parse().unwrap();
    addr.set_port(args.flag_port.unwrap_or(443));

    // Quic
    if args.flag_quic {
        let mut cfg = quinn::ServerConfigBuilder::default().build();
        // Get a mutable reference to the 'crypto' config in the 'client config'.
        let tls_cfg: &mut rustls::ServerConfig =
            std::sync::Arc::get_mut(&mut cfg.crypto).unwrap();
        make_config(&args, tls_cfg)?;

        let mut endpoint = quinn::Endpoint::builder();
        endpoint.listen(cfg);

        let (endpoint, mut incoming) = endpoint.bind(&addr)?;
        eprintln!("listening on {}", endpoint.local_addr()?);

        loop {
            if let Ok(Some(conn)) = tokio::time::timeout(std::time::Duration::from_secs(1), incoming.next()).await {
                info!("connection incoming");
            
                handle_connection(conn).unwrap_or_else(move |e| {
                    error!("connection failed: {reason}", reason = e.to_string())
                }).await;
            }

            if should_stop.load(Ordering::Relaxed) {
                break;
            }
        }
    } else {
        // TLS

        let client_auth = if args.flag_auth.is_some() {
            let roots = load_certs(args.flag_auth.as_ref().unwrap());
            let mut client_auth_roots = RootCertStore::empty();
            for root in roots {
                client_auth_roots.add(&root).unwrap();
            }
            if args.flag_require_auth {
                AllowAnyAuthenticatedClient::new(client_auth_roots)
            } else {
                AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots)
            }
        } else {
            NoClientAuth::new()
        };

        let mut config = rustls::ServerConfig::new(client_auth);

        make_config(&args, &mut config)?;

        let config = Arc::new(config);

        let mut listener = TcpListener::bind(addr).expect("cannot listen on port");
        let mut poll = mio::Poll::new().unwrap();
        poll.registry()
            .register(&mut listener, LISTENER, mio::Interest::READABLE)
            .unwrap();

        let mode = if args.cmd_echo {
            ServerMode::Echo
        } else if args.cmd_http {
            ServerMode::Http
        } else {
            ServerMode::Forward(args.arg_fport.expect("fport required"))
        };

        let mut tlsserv = TlsServer::new(listener, mode, config);

        let mut events = mio::Events::with_capacity(1024);
        let timeout = Some(Duration::from_secs(1));
        loop {
            match poll.poll(&mut events, timeout) {
                Ok(()) => (),
                Err(err) => {
                    if err.kind() == io::ErrorKind::Interrupted {
                        return Ok(());
                    } else {
                        return Err(anyhow::Error::new(err));
                    }
                }
            };

            if should_stop.load(Ordering::Relaxed) {
                break;
            }

            for event in events.iter() {
                match event.token() {
                    LISTENER => {
                        tlsserv
                            .accept(poll.registry())
                            .expect("error accepting socket");
                    }
                    _ => tlsserv.conn_event(poll.registry(), &event),
                }
            }
        }
    }

    sike_deinit();
    return Ok(())
}
