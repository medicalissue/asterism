//! Runnable two-role proof for `asterism_core::remote_gpu`.
//!
//! Start `provider` on one device-role and `guest` on the other. The proof
//! transport is intentionally restricted to loopback; the production adapter
//! belongs on the authenticated orbit mesh.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use asterism_core::remote_gpu::{
    self as gpu, AbiRange, BufferRange, ErrorCode, Reply, Request, Response,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        usage();
        bail!("choose the provider or guest role");
    }
    let role = args.remove(0);
    match role.as_str() {
        "provider" => provider(&args),
        "guest" => guest(&args),
        "-h" | "--help" | "help" => {
            usage();
            Ok(())
        }
        other => {
            usage();
            bail!("unknown role {other:?}")
        }
    }
}

fn usage() {
    eprintln!(
        "remote_gpu_proof provider [--listen 127.0.0.1:0] --ready-file PATH\n\
         remote_gpu_proof guest --connect ADDR --guest-root PATH \
         [--elements 65536] [--iterations 12]"
    );
}

fn provider(args: &[String]) -> Result<()> {
    let listen = option(args, "--listen").unwrap_or("127.0.0.1:0");
    let listen = listen.parse::<SocketAddr>().context("parsing --listen")?;
    require_loopback(listen.ip(), "provider listener")?;
    let ready_file = PathBuf::from(required(args, "--ready-file")?);

    let listener = TcpListener::bind(listen).with_context(|| format!("binding {listen}"))?;
    let address = listener.local_addr()?;
    require_loopback(address.ip(), "bound provider listener")?;
    fs::write(&ready_file, format!("{address}\n"))
        .with_context(|| format!("writing provider address to {}", ready_file.display()))?;
    println!("provider_device=gpu-provider");
    println!("provider_listen={address}");
    println!("proof_transport=loopback_only");

    let (mut stream, peer) = listener.accept().context("accepting proof consumer")?;
    require_loopback(peer.ip(), "provider peer")?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut provider = gpu::Provider::reference("gpu-provider");

    loop {
        let request: Request = read_line(&mut reader).context("reading consumer request")?;
        let closing = matches!(&request, Request::Close { .. });
        let reply = provider.handle(request);
        write_line(&mut stream, &reply).context("writing provider reply")?;
        if closing {
            break;
        }
    }
    Ok(())
}

fn guest(args: &[String]) -> Result<()> {
    let address = required(args, "--connect")?
        .parse::<SocketAddr>()
        .context("parsing --connect")?;
    require_loopback(address.ip(), "guest connection")?;
    let guest_root = PathBuf::from(required(args, "--guest-root")?);
    let elements = parsed_u64(args, "--elements", 65_536)?;
    let iterations = parsed_u64(args, "--iterations", 12)?;
    if elements == 0 || iterations == 0 {
        bail!("--elements and --iterations must be non-zero");
    }
    let bytes = elements
        .checked_mul(4)
        .context("element byte count overflow")?;
    if bytes > gpu::Limits::default().max_copy_bytes {
        bail!(
            "{} f32 elements need {bytes} bytes, above the proof copy limit of {}",
            elements,
            gpu::Limits::default().max_copy_bytes
        );
    }

    let device = project_device(&guest_root)?;
    // The operation under proof: ordinary guest code opens its local path.
    let opened = File::open(&device)
        .with_context(|| format!("opening projected guest device {}", device.display()))?;
    if opened.metadata()?.len() == 0 {
        bail!("projected device marker is empty");
    }

    let mut client = Client::connect(address)?;
    let Response::SessionOpened {
        abi,
        session,
        capabilities,
    } = client.exchange(Request::Hello {
        versions: AbiRange::ours(),
        consumer: "linux-guest".into(),
    })?
    else {
        bail!("provider did not open a session")
    };
    client.session = session;

    let lhs = client.allocate(bytes)?;

    // Security proof 1: sequence 1 already allocated lhs. Reusing it is a
    // replay and must not create a second allocation or advance the session.
    let replay = client.exchange_reply(Request::Allocate {
        session: client.session.clone(),
        sequence: 1,
        bytes,
    })?;
    expect_error(replay, ErrorCode::InvalidSequence, "replay")?;

    let rhs = client.allocate(bytes)?;
    let output = client.allocate(bytes)?;

    // Security proof 2: checked offset + size, with a valid allocation ID.
    // This is sequence 4 and is consumed even though the range is rejected.
    let output_tail = BufferRange {
        allocation: output.clone(),
        offset: bytes - 2,
        bytes: 4,
    };
    let out_of_bounds = client.call_reply(|session, sequence| Request::Write {
        session,
        sequence,
        destination: output_tail,
        data: vec![0; 4],
    })?;
    expect_error(out_of_bounds, ErrorCode::OutOfBounds, "out-of-bounds write")?;

    let descriptor = gpu::vector_add_workload();
    let workload_pin = descriptor.content_blake3.clone();
    let loaded = client.call(|session, sequence| Request::LoadWorkload {
        session,
        sequence,
        descriptor,
        image: gpu::VECTOR_ADD_PTX.as_bytes().to_vec(),
    })?;
    if !matches!(&loaded, Response::WorkloadLoaded { content_blake3, .. } if content_blake3 == &workload_pin)
    {
        bail!("provider did not load the pinned vector-add workload");
    }

    let lhs_values = (0..elements)
        .map(|i| (i as f32) * 0.25 - 32.0)
        .collect::<Vec<_>>();
    let rhs_values = (0..elements)
        .map(|i| ((i % 97) as f32) * -0.5 + 11.0)
        .collect::<Vec<_>>();
    let expected = lhs_values
        .iter()
        .zip(&rhs_values)
        .map(|(a, b)| a + b)
        .collect::<Vec<_>>();
    let lhs_bytes = encode_f32(&lhs_values);
    let rhs_bytes = encode_f32(&rhs_values);

    let lhs_range = whole(&lhs, bytes);
    let rhs_range = whole(&rhs, bytes);
    let output_range = whole(&output, bytes);
    let mut round_trips = Vec::with_capacity(iterations as usize);
    let mut provider_launches = Vec::with_capacity(iterations as usize);
    let measured = Instant::now();

    for _ in 0..iterations {
        let iteration = Instant::now();
        client.call(|session, sequence| Request::Write {
            session,
            sequence,
            destination: lhs_range.clone(),
            data: lhs_bytes.clone(),
        })?;
        client.call(|session, sequence| Request::Write {
            session,
            sequence,
            destination: rhs_range.clone(),
            data: rhs_bytes.clone(),
        })?;
        let launch = client.call(|session, sequence| Request::LaunchVectorAdd {
            session,
            sequence,
            workload_pin: workload_pin.clone(),
            lhs: lhs_range.clone(),
            rhs: rhs_range.clone(),
            output: output_range.clone(),
            elements,
        })?;
        let Response::Launched {
            provider_elapsed_ns,
            ..
        } = launch
        else {
            bail!("provider did not report a launch")
        };
        provider_launches.push(Duration::from_nanos(provider_elapsed_ns));
        let response = client.call(|session, sequence| Request::Read {
            session,
            sequence,
            source: output_range.clone(),
        })?;
        let Response::Data { data, .. } = response else {
            bail!("provider did not return memory")
        };
        let actual = decode_f32(&data)?;
        if actual != expected {
            let mismatch = actual
                .iter()
                .zip(&expected)
                .position(|(actual, expected)| actual != expected)
                .unwrap_or(actual.len().min(expected.len()));
            bail!("vector-add result differs at element {mismatch}");
        }
        round_trips.push(iteration.elapsed());
    }
    let wall = measured.elapsed();

    for allocation in [&lhs, &rhs, &output] {
        client.call(|session, sequence| Request::Free {
            session,
            sequence,
            allocation: allocation.clone(),
        })?;
    }
    client.call(|session, sequence| Request::Close { session, sequence })?;

    let transferred = bytes as f64 * 3.0 * iterations as f64;
    let mib_per_second = transferred / (1024.0 * 1024.0) / wall.as_secs_f64();
    println!("consumer_device=linux-guest");
    println!("guest_visible_device=/dev/nvidia0");
    println!("opened_projection={}", device.display());
    println!("projection_kind=guest_root_regular_file_proof");
    println!("remote_gpu_abi={abi}");
    println!("provider_device={}", capabilities.device_name);
    let executor = match capabilities.executor {
        gpu::Executor::Cuda => "cuda",
        gpu::Executor::Reference => "reference",
    };
    println!("executor={executor}");
    println!("semantic_boundary={}", capabilities.semantic_boundary);
    println!(
        "limit_max_allocation_bytes={}",
        capabilities.limits.max_allocation_bytes
    );
    println!(
        "limit_max_session_bytes={}",
        capabilities.limits.max_session_bytes
    );
    println!(
        "limit_max_provider_bytes={}",
        capabilities.limits.max_provider_bytes
    );
    println!(
        "limit_max_copy_bytes={}",
        capabilities.limits.max_copy_bytes
    );
    println!(
        "limit_max_launch_bytes={}",
        capabilities.limits.max_launch_bytes
    );
    println!(
        "limit_max_allocations={}",
        capabilities.limits.max_allocations
    );
    println!("limit_max_sessions={}", capabilities.limits.max_sessions);
    println!("workload_name={}", gpu::VECTOR_ADD_WORKLOAD_NAME);
    println!("workload_pin={workload_pin}");
    println!("elements={elements}");
    println!("iterations={iterations}");
    println!("result=verified");
    println!("security_replay=refused_invalid_sequence");
    println!("security_out_of_bounds=refused_out_of_bounds");
    println!("e2e_p50_us={}", percentile_us(&round_trips, 50));
    println!("e2e_p95_us={}", percentile_us(&round_trips, 95));
    println!(
        "provider_launch_p50_us={}",
        percentile_us(&provider_launches, 50)
    );
    println!("measured_throughput_mib_s={mib_per_second:.2}");
    println!("transparent_open_path=yes");
    println!("transparent_memory_and_launch=cuda_semantic_subset");
    println!("transparent_raw_syscalls=no");
    println!("transparent_raw_nvidia_ioctls=no");
    println!("transparent_driver_mmap_and_events=no");
    println!("hardware_cuda_executed=false");
    println!("production_transport=authenticated_encrypted_orbit_mesh_required");
    Ok(())
}

struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    session: String,
    sequence: u64,
}

impl Client {
    fn connect(address: SocketAddr) -> Result<Self> {
        let writer = TcpStream::connect_timeout(&address, Duration::from_secs(10))
            .with_context(|| format!("connecting to GPU provider {address}"))?;
        writer.set_read_timeout(Some(Duration::from_secs(30)))?;
        writer.set_write_timeout(Some(Duration::from_secs(30)))?;
        let reader = BufReader::new(writer.try_clone()?);
        Ok(Self {
            reader,
            writer,
            session: String::new(),
            sequence: 0,
        })
    }

    fn allocate(&mut self, bytes: u64) -> Result<String> {
        let response = self.call(|session, sequence| Request::Allocate {
            session,
            sequence,
            bytes,
        })?;
        let Response::Allocated { allocation, .. } = response else {
            bail!("provider did not return an allocation")
        };
        Ok(allocation)
    }

    fn call(&mut self, make: impl FnOnce(String, u64) -> Request) -> Result<Response> {
        self.call_reply(make)?.into_result().map_err(Into::into)
    }

    fn call_reply(&mut self, make: impl FnOnce(String, u64) -> Request) -> Result<Reply> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("call sequence exhausted")?;
        self.exchange_reply(make(self.session.clone(), self.sequence))
    }

    fn exchange(&mut self, request: Request) -> Result<Response> {
        self.exchange_reply(request)?
            .into_result()
            .map_err(Into::into)
    }

    fn exchange_reply(&mut self, request: Request) -> Result<Reply> {
        write_line(&mut self.writer, &request).context("writing GPU request")?;
        read_line(&mut self.reader).context("reading GPU reply")
    }
}

fn project_device(guest_root: &Path) -> Result<PathBuf> {
    let directory = guest_root.join("dev");
    fs::create_dir_all(&directory)
        .with_context(|| format!("creating guest device directory {}", directory.display()))?;
    let path = directory.join("nvidia0");
    let mut projected = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("projecting {}", path.display()))?;
    projected.write_all(b"asterism remote GPU ABI 1\n")?;
    projected.flush()?;
    Ok(path)
}

fn whole(allocation: &str, bytes: u64) -> BufferRange {
    BufferRange {
        allocation: allocation.into(),
        offset: 0,
        bytes,
    }
}

fn encode_f32(values: &[f32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn decode_f32(bytes: &[u8]) -> Result<Vec<f32>> {
    if !bytes.len().is_multiple_of(4) {
        bail!("provider returned {} bytes for f32 memory", bytes.len());
    }
    Ok(bytes
        .chunks(4)
        .map(|chunk| f32::from_le_bytes(chunk.try_into().expect("four-byte chunk")))
        .collect())
}

fn expect_error(reply: Reply, expected: ErrorCode, what: &str) -> Result<()> {
    match reply {
        Reply::Error { error } if error.code == expected => Ok(()),
        Reply::Error { error } => bail!("{what} returned {:?}, expected {expected:?}", error.code),
        Reply::Ok { response } => bail!("{what} unexpectedly succeeded: {response:?}"),
    }
}

fn percentile_us(samples: &[Duration], percentile: usize) -> u128 {
    let mut micros = samples.iter().map(Duration::as_micros).collect::<Vec<_>>();
    micros.sort_unstable();
    let index = ((micros.len() - 1) * percentile).div_ceil(100);
    micros[index]
}

fn require_loopback(ip: IpAddr, what: &str) -> Result<()> {
    if !ip.is_loopback() {
        bail!("{what} must be loopback, not {ip}; production uses the authenticated orbit mesh");
    }
    Ok(())
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str> {
    option(args, name).with_context(|| format!("missing required {name}"))
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|at| args.get(at + 1))
        .map(String::as_str)
}

fn parsed_u64(args: &[String], name: &str, default: u64) -> Result<u64> {
    match option(args, name) {
        Some(value) => value.parse().with_context(|| format!("parsing {name}")),
        None => Ok(default),
    }
}

fn read_line<T: DeserializeOwned>(reader: &mut impl BufRead) -> Result<T> {
    let frame = read_frame(reader)?;
    let text = std::str::from_utf8(&frame).context("GPU peer sent a non-UTF-8 frame")?;
    serde_json::from_str(text).with_context(|| format!("GPU peer sent {:?}", truncate(text)))
}

/// Bound memory before parsing unauthenticated or session-scoped input.
fn read_frame(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            bail!("GPU peer closed the connection before a frame ended");
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let would_be = frame.len() + newline.unwrap_or(chunk.len());
        if would_be > gpu::MAX_WIRE_FRAME_BYTES {
            bail!(
                "GPU peer sent more than {} bytes before ending a frame",
                gpu::MAX_WIRE_FRAME_BYTES
            );
        }
        if let Some(at) = newline {
            frame.extend_from_slice(&chunk[..at]);
            reader.consume(at + 1);
            return Ok(frame);
        }
        let taken = chunk.len();
        frame.extend_from_slice(chunk);
        reader.consume(taken);
    }
}

fn write_line(writer: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let mut frame = serde_json::to_vec(value)?;
    if frame.len() > gpu::MAX_WIRE_FRAME_BYTES {
        bail!(
            "encoded GPU frame is {} bytes, above the {} byte limit",
            frame.len(),
            gpu::MAX_WIRE_FRAME_BYTES
        );
    }
    frame.push(b'\n');
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

fn truncate(text: &str) -> String {
    match text.char_indices().nth(160) {
        None => text.into(),
        Some((at, _)) => format!("{}…", &text[..at]),
    }
}
