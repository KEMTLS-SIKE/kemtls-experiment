use std::process;
use std::sync::{Arc, Mutex};

use mio;
use mio::net::TcpStream;

use std::collections;
use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::str;

use anyhow::{anyhow, Result};
use futures::executor;

use env_logger;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;

use ct_logs;
use rustls;
use webpki;
use webpki_roots;

use rustls::Session;
use rustls::internal::kems::{DEFAULT_GROUP,KeyExchange,KexAlgorithm,sike_deinit};

const CLIENT: mio::Token = mio::Token(0);

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_session: rustls::ClientSession,
}

impl TlsClient {
    fn new(
        sock: TcpStream,
        hostname: webpki::DNSNameRef<'_>,
        cfg: Arc<rustls::ClientConfig>,
    ) -> TlsClient {
        TlsClient {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_session: rustls::ClientSession::new(&cfg, hostname),
        }
    }

    fn ready(&mut self, ev: &mio::event::Event) -> bool{
        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() {
            self.do_read();
        }

        if ev.is_writable() {
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            if self.clean_closure {
                return true;
            } else {
                println!("Unclean exit");
                process::exit(1);
            }
        }
        false
    }

    fn read_source_to_end(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tls_session
            .write_all(&buf)
            .unwrap();
        Ok(len)
    }

    /// We're ready to do a read.
    fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        let rc = self
            .tls_session
            .read_tls(&mut self.socket);
        if rc.is_err() {
            let error = rc.unwrap_err();
            if error.kind() == io::ErrorKind::WouldBlock {
                return;
            }
            println!("TLS read error: {:?}", error);
            self.closing = true;
            return;
        }

        // If we're ready but there's no data: EOF.
        if rc.unwrap() == 0 {
            println!("EOF");
            self.closing = true;
            self.clean_closure = true;
            return;
        }

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.

        let socket = &mut self.socket;
        let processed = self.tls_session.process_new_packets(Some(socket));
        if processed.is_err() {
            println!("TLS error: {:?}", processed.unwrap_err());
            self.closing = true;
            return;
        }

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        let mut plaintext = Vec::new();
        let rc = self
            .tls_session
            .read_to_end(&mut plaintext);
        if !plaintext.is_empty() {
            io::stdout()
                .write_all(&plaintext)
                .unwrap();
        }

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if rc.is_err() {
            let err = rc.unwrap_err();
            println!("Plaintext read error: {:?}", err);
            self.clean_closure = err.kind() == io::ErrorKind::ConnectionAborted;
            self.closing = true;
            return;
        }
    }

    fn do_write(&mut self) {
        self.tls_session
            .write_tls(&mut self.socket)
            .unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .register(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .reregister(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
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
        self.closing
    }
}
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_session.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_session.flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_session.read(bytes)
    }
}

/// This is an example cache for client session data.
/// It optionally dumps cached data to a file, but otherwise
/// is just in-memory.
///
/// Note that the contents of such a file are extremely sensitive.
/// Don't write this stuff to disk in production code.
struct PersistCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    filename: Option<String>,
}

impl PersistCache {
    /// Make a new cache.  If filename is Some, load the cache
    /// from it and flush changes back to that file.
    fn new(filename: &Option<String>) -> PersistCache {
        let cache = PersistCache {
            cache: Mutex::new(collections::HashMap::new()),
            filename: filename.clone(),
        };
        if cache.filename.is_some() {
            cache.load();
        }
        cache
    }

    /// If we have a filename, save the cache contents to it.
    fn save(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::Codec;

        if self.filename.is_none() {
            return;
        }

        let mut file =
            fs::File::create(self.filename.as_ref().unwrap()).expect("cannot open cache file");

        for (key, val) in self.cache.lock().unwrap().iter() {
            let mut item = Vec::new();
            let key_pl = PayloadU16::new(key.clone());
            let val_pl = PayloadU16::new(val.clone());
            key_pl.encode(&mut item);
            val_pl.encode(&mut item);
            file.write_all(&item).unwrap();
        }
    }

    /// We have a filename, so replace the cache contents from it.
    fn load(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::{Codec, Reader};

        let mut file = match fs::File::open(self.filename.as_ref().unwrap()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut cache = self.cache.lock().unwrap();
        cache.clear();
        let mut rd = Reader::init(&data);

        while rd.any_left() {
            let key_pl = PayloadU16::read(&mut rd).unwrap();
            let val_pl = PayloadU16::read(&mut rd).unwrap();
            cache.insert(key_pl.0, val_pl.0);
        }
    }
}

impl rustls::StoresClientSessions for PersistCache {
    /// put: insert into in-memory cache, and perhaps persist to disk.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache
            .lock()
            .unwrap()
            .insert(key, value);
        self.save();
        true
    }

    /// get: from in-memory cache
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache
            .lock()
            .unwrap()
            .get(key)
            .cloned()
    }
}

const USAGE: &'static str = "
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

If --cafile is not supplied, a built-in set of CA certificates
are used from the webpki-roots crate.

Usage:
  tlsclient [options] [--suite SUITE ...] [--proto PROTO ...] <hostname>
  tlsclient (--version | -v)
  tlsclient (--help | -h)

Options:
    -p, --port PORT       Connect to PORT [default: 443].
    --loops NUM           How many iterations
    --http                Send a basic HTTP GET request for /.
    --cafile CAFILE       Read root certificates from CAFILE.
    --auth-key KEY        Read client authentication key from KEY.
    --auth-certs CERTS    Read client authentication certificates from CERTS.
                          CERTS must match up with KEY.
    --cached-certs CERTS  Read known server certificates from CERTS
    --protover VERSION    Disable default TLS version list, and use
                          VERSION instead.  May be used multiple times.
    --suite SUITE         Disable default cipher suite list, and use
                          SUITE instead.  May be used multiple times.
    --proto PROTOCOL      Send ALPN extension containing PROTOCOL.
                          May be used multiple times to offer several protocols.
    --cache CACHE         Save session cache to file CACHE.
    --no-tickets          Disable session ticket support.
    --no-sni              Disable server name indication support.
    --insecure            Disable certificate verification.
    --verbose             Emit log output.
    --mtu MTU             Limit outgoing messages to MTU bytes.
    --async-keypair       Generate keypairs asynchronously.
    --async-encapsulate   Compute encapsulate asynchronously.
    --quic                Use quic instead of TLS.
    --version, -v         Show tool version.
    --help, -h            Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_http: bool,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_mtu: Option<usize>,
    flag_cafile: Option<String>,
    flag_cache: Option<String>,
    flag_cached_certs: Option<String>,
    flag_no_tickets: bool,
    flag_no_sni: bool,
    flag_insecure: bool,
    flag_auth_key: Option<String>,
    flag_auth_certs: Option<String>,
    arg_hostname: String,
    flag_loops: Option<usize>,
    flag_async_keypair: bool,
    flag_async_encapsulate: bool,
    flag_quic: bool,
}

// TODO: um, well, it turns out that openssl s_client/s_server
// that we use for testing doesn't do ipv6.  So we can't actually
// test ipv6 and hence kill this.
fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

/// Find a ciphersuite with the given name
fn find_suite(name: &str) -> Option<&'static rustls::SupportedCipherSuite> {
    for suite in &rustls::ALL_CIPHERSUITES {
        let sname = format!("{:?}", suite.suite).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(suite);
        }
    }

    None
}

/// Make a vector of ciphersuites named in `suites`
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

fn load_key_and_cert(config: &mut rustls::ClientConfig, keyfile: &str, certsfile: &str) {
    let certs = load_certs(certsfile);
    let privkey = load_private_key(keyfile);

    config
        .set_single_client_cert(certs, privkey)
        .expect("invalid certificate or private key");
}

#[cfg(feature = "dangerous_configuration")]
mod danger {
    use super::rustls;
    use webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _roots: &rustls::RootCertStore,
            _presented_certs: &[rustls::Certificate],
            _dns_name: webpki::DNSNameRef<'_>,
            _ocsp: &[u8],
        ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
fn apply_dangerous_options(args: &Args, cfg: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }
}

#[cfg(not(feature = "dangerous_configuration"))]
fn apply_dangerous_options(args: &Args, _: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        panic!("This build does not support --insecure.");
    }
}

/// Build a `ClientConfig` from our arguments
fn make_config(args: &Args, config: &mut rustls::ClientConfig) -> Result<()> {
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    if !args.flag_suite.is_empty() {
        config.ciphersuites = lookup_suites(&args.flag_suite);
    }

    if !args.flag_protover.is_empty() {
        config.versions = lookup_versions(&args.flag_protover);
    }

    if args.flag_cached_certs.is_some() {
        config.known_certificates = load_certs(&args.flag_cached_certs.as_ref().unwrap());
    }

    if args.flag_cafile.is_some() {
        let cafile = args.flag_cafile.as_ref().unwrap();

        let certfile = fs::File::open(&cafile).expect("Cannot open CA file");
        let mut reader = BufReader::new(certfile);
        config
            .root_store
            .add_pem_file(&mut reader)
            .unwrap();
    } else {
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.ct_logs = Some(&ct_logs::LOGS);
    }

    if args.flag_no_tickets {
        config.enable_tickets = false;
    }

    if args.flag_no_sni {
        config.enable_sni = false;
    }

    let persist = Arc::new(PersistCache::new(&args.flag_cache));

    config.set_protocols(
        &args
            .flag_proto
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect::<Vec<_>>()[..],
    );
    config.set_persistence(persist);
    config.set_mtu(&args.flag_mtu);

    apply_dangerous_options(args, config);

    if args.flag_auth_key.is_some() || args.flag_auth_certs.is_some() {
        load_key_and_cert(
            config,
            args.flag_auth_key
                .as_ref()
                .expect("must provide --auth-key with --auth-certs"),
            args.flag_auth_certs
                .as_ref()
                .expect("must provide --auth-certs with --auth-key"),
        );
    }

    config.async_keypair = args.flag_async_keypair;
    config.async_encapsulate = args.flag_async_encapsulate;

    // Pre-compute the batch of keys, so that the first call doesn't count in the benchmark
    if config.async_keypair {
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

/// Parse some arguments, then make a TLS client connection
/// somewhere.
#[tokio::main]
async fn main() -> Result<()> {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

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
    let num_loops = args.flag_loops.unwrap_or(1);

    let port = args.flag_port.unwrap_or(443);
    let addr = lookup_ipv4(args.arg_hostname.as_str(), port);


    let httpreq = format!("GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
                    close\r\nAccept-Encoding: identity\r\n\r\n",
                    args.arg_hostname);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(&args.arg_hostname).unwrap();


    if args.flag_quic {
        let mut cfg = quinn::ClientConfigBuilder::default().build();
        // Get a mutable reference to the 'crypto' config in the 'client config'.
        let tls_cfg: &mut rustls::ClientConfig =
            std::sync::Arc::get_mut(&mut cfg.crypto).unwrap();
        make_config(&args, tls_cfg)?;

        for i in 0..num_loops {
            println!("Connecting to server for iteration {} of {}", i, num_loops);


            // Quic Connection

            let mut endpoint = quinn::Endpoint::builder();
            endpoint.default_client_config(cfg.clone());

            // Create an IPv4 endpoint
            let (endpoint, _) = endpoint.bind(&"0.0.0.0:0".parse().unwrap())?;

            let host = args.arg_hostname.as_str();

            let new_conn = executor::block_on(endpoint
                .connect(&addr, host)?
            ).map_err(|e| anyhow!("failed to connect: {}", e))?;
            let quinn::NewConnection {
                connection: conn, ..
            } = new_conn;
            let (mut send, recv) = executor::block_on(conn
                .open_bi()).map_err(|e| anyhow!("failed to open stream: {}", e))?;

            executor::block_on(send.write_all(httpreq.as_bytes()))?;
            executor::block_on(send.finish())?;
            executor::block_on(recv
                .read_to_end(usize::max_value()))?;

            conn.close(0u32.into(), b"done");

            // Give the server a fair chance to receive the close packet
            executor::block_on(endpoint.wait_idle());
        }
    } else {
        let mut config = rustls::ClientConfig::new();
        Arc::new(make_config(&args, &mut config));
        let config = Arc::new(config);

        // TLS Connection
        for i in 0..num_loops {
            println!("Connecting to server for iteration {} of {}", i, num_loops);

            let sock = TcpStream::connect(addr)?;
            sock.set_nodelay(false)?;  // Nagle algorithm switch (false is default)
            let mut tlsclient = TlsClient::new(sock, dns_name, config.clone());

            if args.flag_http {
                tlsclient.write_all(httpreq.as_bytes())?;
            } else {
                let mut stdin = io::stdin();
                tlsclient.read_source_to_end(&mut stdin)?;
            }

            let mut poll = mio::Poll::new()?;
            let mut events = mio::Events::with_capacity(1024);
            tlsclient.register(poll.registry());

            'outer: loop {
                poll.poll(&mut events, None)?;

                for ev in events.iter() {
                    let stop = tlsclient.ready(&ev);
                    tlsclient.reregister(poll.registry());
                    if stop {
                        break 'outer;
                    }
                }
            }
        }
    }

    sike_deinit();
    Ok(())
}
