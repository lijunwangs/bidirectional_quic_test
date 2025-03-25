use {
    anyhow::{Context, Error, Result},
    bytes::Bytes,
    quinn::{
        crypto::rustls::{QuicClientConfig, QuicServerConfig},
        Connection, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig,
    },
    rustls::{
        crypto::ring::cipher_suite,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    },
    std::{
        array, fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
    structopt::StructOpt,
    tokio::{
        runtime::Runtime,
        task::{self, JoinHandle},
        time::{self, sleep_until, Instant as AsyncInstant},
    },
    tracing::*,
};

const PACKET_SIZE: usize = 1000;

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "quic_bidir_test")]
struct Opt {
    /// Run only the server
    #[structopt(long)]
    server_only: bool,

    /// Run only the client
    #[structopt(long)]
    client_only: bool,

    /// Server address (IP:port) for client mode
    #[structopt(long, default_value = "0.0.0.0:11228")]
    server_address: String,

    /// Number of sender threads
    #[structopt(long, default_value = "4")]
    num_threads: usize,

    /// Number of packets per sender thread
    #[structopt(long, default_value = "10000")]
    num_packets: usize,

    /// Number of endpoints on server side
    #[structopt(long, default_value = "8")]
    num_endpoints: usize,

    /// Server certificate
    #[structopt(long)]
    cert: Option<PathBuf>,

    /// Server key
    #[structopt(long)]
    key: Option<PathBuf>,
}

struct Server {
    #[allow(dead_code)]
    runtime: Runtime,

    handles: Vec<JoinHandle<Result<(), Error>>>,
    local_address: SocketAddr,
}

impl Server {
    fn create_server(opt: &Opt, addr: SocketAddr) -> Self {
        let runtime = rt("quicbench".to_string());
        let _guard = runtime.enter();

        let endpoints =
            setup_server(&opt, addr, opt.num_endpoints).expect("Failed to create server");
        let mut handles = Vec::new();
        let total_received = Arc::new(AtomicUsize::new(0));

        tokio::spawn(report_stats(total_received.clone()));

        let local_address = endpoints[0].local_addr().unwrap();
        for endpoint in endpoints {
            let task = tokio::spawn(run_server(endpoint, total_received.clone()));
            handles.push(task);
        }

        Self {
            runtime,
            handles,
            local_address,
        }
    }

    async fn join(self) {
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}
#[tokio::main]
async fn main() {
    let mut opt = Opt::from_args();
    tracing_subscriber::fmt::init();

    match (opt.server_only, opt.client_only) {
        (true, false) => {
            let addr = opt
                .server_address
                .parse::<SocketAddr>()
                .expect("Exepected correct server address in IP:port format"); // SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

            let server = Server::create_server(&opt, addr);
            server.join().await;
        }
        (false, true) => {
            let _ = run_client(&opt).await;
        }
        _ => {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            opt.server_address = addr.to_string();

            let server = Server::create_server(&opt, addr);

            opt.server_address = server.local_address.to_string();
            time::sleep(Duration::from_secs(1)).await;
            let _ = run_client(&opt).await;
            server.join().await;
        }
    }
}

async fn report_stats(total_received: Arc<AtomicUsize>) {
    let mut last_datapoint = AsyncInstant::now();
    loop {
        if last_datapoint.elapsed().as_secs() >= 5 {
            let total_received = total_received.swap(0, Ordering::Relaxed);
            info!("Received packets: {total_received}");
            last_datapoint = AsyncInstant::now();
        }
        sleep_until(last_datapoint.checked_add(Duration::from_secs(5)).unwrap()).await;
    }
}

async fn run_server(endpoint: Endpoint, total_received: Arc<AtomicUsize>) -> Result<()> {
    info!("Server listening on {}", endpoint.local_addr().unwrap());

    while let Some(handshake) = endpoint.accept().await {
        info!(
            "Got incoming connection from {:?}",
            handshake.remote_address()
        );
        let total_received = total_received.clone();
        tokio::spawn(async move {
            if let Err(e) = server_handle_connection(handshake, total_received).await {
                info!("connection lost: {:#}", e);
            }
        });
    }

    Ok(())
}

async fn server_handle_connection(
    handshake: quinn::Incoming,
    total_received: Arc<AtomicUsize>,
) -> Result<()> {
    let connection = handshake.await.context("handshake failed")?;
    info!("{} connected", connection.remote_address());
    tokio::try_join!(drive_stream(connection.clone(), total_received),)?;
    Ok(())
}

async fn drive_stream(
    connection: quinn::Connection,
    total_received: Arc<AtomicUsize>,
) -> Result<()> {
    loop {
        let result = connection.accept_uni().await;
        match result {
            Ok(mut stream) => {
                let mut chunks: [Bytes; 4] = array::from_fn(|_| Bytes::new());

                let mut has_failure = false;
                loop {
                    let result = stream.read_chunks(&mut chunks).await;
                    match result {
                        Ok(chunk) => match chunk {
                            Some(n_chunks) => {
                                let chunks = chunks.iter().take(n_chunks).cloned();
                                let n_chunks = chunks.len();
                                if n_chunks == 0 {
                                    break;
                                }
                            }
                            None => {
                                break;
                            }
                        },
                        Err(err) => {
                            has_failure = true;
                            error!("Had failure : {err:?}");
                            break;
                        }
                    }
                }
                if !has_failure {
                    total_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    debug!("Received a stream!");
                }
            }
            Err(err) => {
                info!(
                    "Got error {err:?} for connection from {:?}",
                    connection.remote_address()
                );
                break;
            }
        }
    }
    Ok(())
}

async fn drive_datagram(
    connection: quinn::Connection,
    total_received: Arc<AtomicUsize>,
) -> Result<()> {
    loop {
        let result = connection.read_datagram().await;
        match result {
            Ok(_) => {
                total_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!("Received a datagram!");
            }
            Err(err) => {
                info!(
                    "Got error {err:?} for connection from {:?}",
                    connection.remote_address()
                );
                break;
            }
        }
    }
    Ok(())
}

async fn run_client(opt: &Opt) -> Result<()> {
    let mut server_addr: SocketAddr = opt
        .server_address
        .parse()
        .expect("Invalid server address format");

    if server_addr.ip().is_unspecified() {
        server_addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        //server_addr.set_ip(IpAddr::V4(Ipv4Addr::new(145, 40, 90, 189)));
    }
    info!("Connecting to server {server_addr:?}");
    let endpoints = setup_client(opt.num_threads).expect("Failed to create client");

    let packet = vec![0; PACKET_SIZE];
    let start = Instant::now();

    let mut conns: Vec<Connection> = Vec::default();
    let total_sent = Arc::new(AtomicUsize::default());
    let total_received_responses = Arc::new(AtomicUsize::new(0));
    for i in 0..opt.num_threads {
        let conn = endpoints[i]
            .connect(server_addr, "localhost")
            .expect("Failed to connect")
            .await
            .expect("Connection failed");
        conns.push(conn.clone());
        let packet = packet.clone();
        let num_packets = opt.num_packets;
        let total_sent = total_sent.clone();
        let total_received_responses = total_received_responses.clone();
        let conn_t = conn.clone();
        task::spawn(async move {
            for _ in 0..num_packets {
                let mut stream = conn.open_uni().await.unwrap();
                let result = stream.write_all(&packet).await;

                match result {
                    Ok(_) => {
                        total_sent.fetch_add(1, Ordering::Relaxed);
                        trace!("Sent stream?");
                        task::yield_now().await;

                        
                    }
                    Err(err) => {
                        error!("Send stream error {err:?}");
                    }
                }
            }
        });
        tokio::spawn(drive_datagram(conn_t, total_received_responses.clone()));
    }

    let duration = start.elapsed().as_secs_f64();
    let total_sent = total_sent.load(Ordering::Relaxed);
    info!(
        "Sent (written to buffer) {} packets in {:.2} seconds ({:.2} packets/sec)",
        total_sent,
        duration,
        total_sent as f64 / duration
    );

    // the following give the async sent datagrams to be sent out actually.
    for i in 0..opt.num_threads {
        endpoints[i].wait_idle().await;
    }
    Ok(())
}

pub fn rt(name: String) -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .thread_name(name)
        .enable_all()
        .build()
        .unwrap()
}

fn setup_server(
    opt: &Opt,
    addr: SocketAddr,
    count: usize,
) -> Result<Vec<Endpoint>, Box<dyn std::error::Error>> {
    let (key, cert) = match (&opt.key, &opt.cert) {
        (Some(key), Some(cert)) => {
            let key = fs::read(key).context("reading key")?;
            let cert = fs::read(cert).expect("reading cert");
            (
                PrivatePkcs8KeyDer::from(key),
                rustls_pemfile::certs(&mut cert.as_ref())
                    .collect::<Result<_, _>>()
                    .context("parsing cert")?,
            )
        }
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (
                PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
                vec![CertificateDer::from(cert.cert)],
            )
        }
    };

    let default_provider = rustls::crypto::ring::default_provider();
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: [
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ]
        .into(),
        ..default_provider
    };

    let mut crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key.into())
        .unwrap();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    let crypto = Arc::new(QuicServerConfig::try_from(crypto)?);

    let mut transport_config = TransportConfig::default();
    transport_config.datagram_receive_buffer_size(Some(PACKET_SIZE * 1024 * 1024));

    let mut server_config = ServerConfig::with_crypto(crypto);
    server_config.transport = Arc::new(transport_config);

    let mut endpoints = Vec::new();

    let (_port, mut sockets) = solana_net_utils::multi_bind_in_range(
        addr.ip(),
        (addr.port(), addr.port() + count as u16),
        count,
    )
    .unwrap();

    for socket in sockets.drain(..) {
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config.clone()),
            socket,
            Arc::new(TokioRuntime),
        )?;
        endpoints.push(endpoint);
    }

    Ok(endpoints)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn setup_client(count: usize) -> Result<Vec<Endpoint>, Box<dyn std::error::Error>> {
    info!("Setting up client");
    let default_provider = rustls::crypto::ring::default_provider();
    let provider = Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: [
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ]
        .into(),
        ..default_provider
    });

    let mut transport_config = TransportConfig::default();
    transport_config.datagram_send_buffer_size(PACKET_SIZE * 1024 * 1024);

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    info!("Setting up QuicClientConfig...");

    let crypto = Arc::new(QuicClientConfig::try_from(crypto)?);

    let mut client_config = quinn::ClientConfig::new(crypto);

    client_config.transport_config(Arc::new(transport_config));

    info!("Creating client endpoint...");

    let mut endpoints = Vec::new();

    for _ in 0..count {
        let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
        endpoint.set_default_client_config(client_config.clone());
        endpoints.push(endpoint);
    }
    Ok(endpoints)
}
