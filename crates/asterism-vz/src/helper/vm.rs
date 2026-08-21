//! The Virtualization.framework half of the helper.
//!
//! Lifted from `crates/asterism-vz-spike/src/boot.rs`, which is where every
//! comment below was paid for (see `docs/VZ-SPIKE-NOTES.md`).
//!
//! ## Threading, which is the whole difficulty
//!
//! `VZVirtualMachine` is bound to a serial dispatch queue at init, and
//! *every* property read and method call must happen on that queue;
//! callbacks — the start completion block, every delegate method — are
//! delivered on it too. `initWithConfiguration:` binds to the **main**
//! queue, so all VZ work in this process happens on the main thread, and
//! the main thread's job is to pump its run loop so the framework can
//! deliver.
//!
//! Nothing in this file is `Send`, and that is the framework rather than an
//! accident of the bindings. It is also why the control socket and the
//! address prober live on their own threads: blocking this one wedges the
//! guest (spike landmine 9 — a starved main queue stops answering ACPI
//! shutdown altogether).

use std::cell::Cell;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AllocAnyThread, DefinedClass, MainThreadOnly};
use objc2_foundation::{
    MainThreadMarker, NSArray, NSDate, NSError, NSFileHandle, NSObject, NSObjectProtocol,
    NSRunLoop, NSString, NSURL,
};
use objc2_virtualization::{
    VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
    VZDiskSynchronizationMode, VZEFIBootLoader, VZEFIVariableStore,
    VZEFIVariableStoreInitializationOptions, VZEntropyDeviceConfiguration,
    VZFileHandleSerialPortAttachment, VZGenericPlatformConfiguration, VZMACAddress,
    VZMemoryBalloonDeviceConfiguration, VZNATNetworkDeviceAttachment,
    VZNetworkBlockDeviceStorageDeviceAttachment,
    VZNetworkBlockDeviceStorageDeviceAttachmentDelegate, VZNetworkDevice,
    VZNetworkDeviceConfiguration, VZSerialPortConfiguration, VZSocketDeviceConfiguration,
    VZStorageDeviceConfiguration, VZVirtioBlockDeviceConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtioSocketDeviceConfiguration,
    VZVirtioTraditionalMemoryBalloonDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration, VZVirtualMachineDelegate, VZVirtualMachineState,
};

use asterism_vz::{Config, Disk, State, StopReason};

/// Shared between the delegate object and the run loop. `Rc`, not `Arc`:
/// both live on the queue the VM is bound to, and nothing here crosses a
/// thread boundary.
#[derive(Default)]
pub struct Signals {
    stopped: Cell<bool>,
    reason: std::cell::RefCell<Option<StopReason>>,
    /// Set when a network attachment drops. VZ reports this per boot and it
    /// is otherwise completely silent.
    net_disconnects: Cell<u32>,
    /// The NBD delegate can report this more than once: the first callback
    /// is the initial connection and later callbacks are transparent
    /// reconnects after recoverable failures.
    nbd_connections: Cell<u32>,
    /// Only non-recoverable NBD failures arrive here. Recoverable failures
    /// are intentionally left to VZ's built-in reconnect loop.
    nbd_terminal_errors: Cell<u32>,
}

impl Signals {
    fn record(&self, reason: StopReason) {
        self.stopped.set(true);
        if self.reason.borrow().is_none() {
            *self.reason.borrow_mut() = Some(reason);
        }
    }

    pub fn stopped(&self) -> bool {
        self.stopped.get()
    }

    pub fn reason(&self) -> Option<StopReason> {
        self.reason.borrow().clone()
    }

    pub fn net_disconnects(&self) -> u32 {
        self.net_disconnects.get()
    }
}

define_class!(
    // Delegate methods arrive on the VM's queue, which is the main queue,
    // so declaring the class `MainThreadOnly` matches reality and lets
    // objc2 enforce it at compile time.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "AsterismVzDelegate"]
    #[ivars = Rc<Signals>]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl VZVirtualMachineDelegate for Delegate {
        #[unsafe(method(guestDidStopVirtualMachine:))]
        fn guest_did_stop(&self, _vm: &VZVirtualMachine) {
            self.ivars().record(StopReason::GuestStopped);
        }

        #[unsafe(method(virtualMachine:didStopWithError:))]
        fn did_stop_with_error(&self, _vm: &VZVirtualMachine, error: &NSError) {
            self.ivars().record(StopReason::Failed {
                message: error.localizedDescription().to_string(),
            });
        }

        #[unsafe(method(virtualMachine:networkDevice:attachmentWasDisconnectedWithError:))]
        fn net_disconnected(
            &self,
            _vm: &VZVirtualMachine,
            _dev: &VZNetworkDevice,
            _error: &NSError,
        ) {
            let n = self.ivars().net_disconnects.get();
            self.ivars().net_disconnects.set(n + 1);
        }
    }
);

struct NbdDelegateIvars {
    signals: Rc<Signals>,
    uri: String,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "AsterismVzNbdDelegate"]
    #[ivars = NbdDelegateIvars]
    struct NbdDelegate;

    unsafe impl NSObjectProtocol for NbdDelegate {}

    unsafe impl VZNetworkBlockDeviceStorageDeviceAttachmentDelegate for NbdDelegate {
        #[unsafe(method(attachmentWasConnected:))]
        fn attachment_was_connected(
            &self,
            _attachment: &VZNetworkBlockDeviceStorageDeviceAttachment,
        ) {
            let previous = self.ivars().signals.nbd_connections.get();
            self.ivars().signals.nbd_connections.set(previous + 1);
            eprintln!(
                "astd-vz: NBD {} to {}",
                if previous == 0 {
                    "connected"
                } else {
                    "reconnected"
                },
                self.ivars().uri
            );
        }

        #[unsafe(method(attachment:didEncounterError:))]
        fn attachment_did_encounter_error(
            &self,
            _attachment: &VZNetworkBlockDeviceStorageDeviceAttachment,
            error: &NSError,
        ) {
            let n = self.ivars().signals.nbd_terminal_errors.get();
            self.ivars().signals.nbd_terminal_errors.set(n + 1);
            eprintln!(
                "astd-vz: NBD attachment {} entered a non-recoverable state: {}",
                self.ivars().uri,
                error.localizedDescription()
            );
        }
    }
);

fn url(path: &Path) -> Retained<NSURL> {
    NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()))
}

fn vz_err(e: Retained<NSError>) -> anyhow::Error {
    anyhow!("{}", e.localizedDescription())
}

/// Percent-encode one free-text NBD URI component according to RFC 3986.
///
/// Encoding all bytes outside the unreserved set is deliberately stricter
/// than necessary. In particular it keeps an export's `/`, `?`, and `#`
/// as data rather than allowing them to change the URI's structure.
fn uri_component(value: &str) -> Result<String> {
    if value.contains('\0') {
        bail!("an NBD URI component cannot contain NUL");
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    Ok(encoded)
}

/// The standard NBD URI for a Unix-domain-socket transport.
fn nbd_unix_uri(socket: &Path, export: &str) -> Result<String> {
    let socket = socket.to_str().with_context(|| {
        format!(
            "the NBD socket path {} is not valid UTF-8",
            socket.display()
        )
    })?;
    Ok(format!(
        "nbd+unix:///{export}?socket={socket}",
        export = uri_component(export)?,
        socket = uri_component(socket)?,
    ))
}

fn network_url(value: &str) -> Result<Retained<NSURL>> {
    NSURL::initWithString(NSURL::alloc(), &NSString::from_str(value))
        .ok_or_else(|| anyhow!("{value:?} is not a URL"))
}

/// Construct one VZ NBD device and keep its weak delegate alive.
///
/// VZ itself owns the reconnect policy: a timeout or recoverable transport
/// error schedules another attempt and later calls `attachmentWasConnected:`
/// again. The helper must not tear down or replace the attachment in that
/// window; retaining the delegate alongside the VM is the entire policy.
unsafe fn nbd_device(
    uri: String,
    readonly: bool,
    signals: &Rc<Signals>,
    mtm: MainThreadMarker,
    delegates: &mut Vec<Retained<NbdDelegate>>,
) -> Result<Retained<VZStorageDeviceConfiguration>> {
    let url = network_url(&uri)?;
    VZNetworkBlockDeviceStorageDeviceAttachment::validateURL_error(&url)
        .map_err(vz_err)
        .with_context(|| format!("validating NBD URI {uri}"))?;
    let attachment = VZNetworkBlockDeviceStorageDeviceAttachment::initWithURL_timeout_forcedReadOnly_synchronizationMode_error(
        VZNetworkBlockDeviceStorageDeviceAttachment::alloc(),
        &url,
        30.0,
        readonly,
        VZDiskSynchronizationMode::Full,
    )
    .map_err(vz_err)
    .with_context(|| format!("creating NBD attachment {uri}"))?;
    let delegate = {
        let this = NbdDelegate::alloc(mtm).set_ivars(NbdDelegateIvars {
            signals: signals.clone(),
            uri,
        });
        let this: Retained<NbdDelegate> = msg_send![super(this), init];
        this
    };
    attachment.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    delegates.push(delegate);

    let dev = VZVirtioBlockDeviceConfiguration::initWithAttachment(
        VZVirtioBlockDeviceConfiguration::alloc(),
        &Retained::into_super(attachment),
    );
    Ok(Retained::into_super(dev))
}

/// A running guest plus everything that has to outlive it.
pub struct Machine {
    vm: Retained<VZVirtualMachine>,
    /// The VM holds its delegate *weakly* (`@property(weak)`), so dropping
    /// this would silently stop every callback. This field is the entire
    /// reason `Machine` owns it (spike landmine 4).
    _delegate: Retained<Delegate>,
    /// NBD attachment delegates are weak properties too. There is one per
    /// disk and each must survive for the entire VM lifetime so reconnect
    /// and terminal-error callbacks do not silently disappear.
    _nbd_delegates: Vec<Retained<NbdDelegate>>,
    /// Same story: VZ does not retain the file descriptors behind the
    /// serial attachment's file handles, so the `File`s have to live as
    /// long as the VM does.
    _console_files: Vec<std::fs::File>,
    pub signals: Rc<Signals>,
}

/// Translate the config into a validated `VZVirtualMachineConfiguration`.
///
/// # Safety
/// Must run on the main thread (see the module note).
unsafe fn build_config(
    config: &Config,
    mac: &VZMACAddress,
    console_files: &mut Vec<std::fs::File>,
    nbd_delegates: &mut Vec<Retained<NbdDelegate>>,
    signals: &Rc<Signals>,
    mtm: MainThreadMarker,
) -> Result<Retained<VZVirtualMachineConfiguration>> {
    let vm_config = VZVirtualMachineConfiguration::new();

    vm_config.setCPUCount(config.cpus as usize);
    vm_config.setMemorySize(u64::from(config.mem_mib) * 1024 * 1024);
    // `into_super` rather than `downcast_ref().retain()`: every concrete VZ
    // device type is a direct subclass of the abstract type its setter
    // wants, so the upcast is infallible and free (spike landmine 2).
    vm_config.setPlatform(&Retained::into_super(VZGenericPlatformConfiguration::new()));

    // ---- boot loader ---------------------------------------------------
    // EFI with a persistent variable store. The store is what remembers the
    // boot entry the guest's GRUB installed, so it is created once and
    // reused; a fresh store every boot sends the firmware back to scanning
    // for a fallback bootloader (spike landmine 5).
    let boot = VZEFIBootLoader::new();
    let vars = if config.efi_vars.exists() {
        VZEFIVariableStore::initWithURL(VZEFIVariableStore::alloc(), &url(&config.efi_vars))
    } else {
        VZEFIVariableStore::initCreatingVariableStoreAtURL_options_error(
            VZEFIVariableStore::alloc(),
            &url(&config.efi_vars),
            VZEFIVariableStoreInitializationOptions::empty(),
        )
        .map_err(vz_err)
        .context("creating the EFI variable store")?
    };
    boot.setVariableStore(Some(&vars));
    vm_config.setBootLoader(Some(&Retained::into_super(boot)));

    // ---- storage -------------------------------------------------------
    // Root first, seed second, extra disks after: cloud-init finds the
    // NoCloud source by its `cidata` volume label rather than by device
    // order, so the ordering is a convention for humans reading `lsblk`.
    //
    // Caching and synchronization are set explicitly rather than left to
    // the convenience initialiser. With the defaults, the spike twice
    // produced a guest that came back from a *clean* shutdown with
    // "EXT4-fs (vda1): orphan cleanup on readonly fs" and then an
    // "iget: checksum invalid" abort: the guest's flushes were not reaching
    // the file. `Full` is the mode that maps a guest barrier onto real
    // permanent storage, and it is the only honest choice for a backend
    // holding someone's agent workload (spike landmine 10).
    let mut disks: Vec<Retained<VZStorageDeviceConfiguration>> = Vec::new();
    let attach = |path: &Path, readonly: bool| -> Result<Retained<VZStorageDeviceConfiguration>> {
        if !path.exists() {
            bail!("{} is not there to attach", path.display());
        }
        let attachment =
            VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &url(path),
                readonly,
                VZDiskImageCachingMode::Cached,
                VZDiskImageSynchronizationMode::Full,
            )
            .map_err(vz_err)
            .with_context(|| format!("attaching {}", path.display()))?;
        let dev = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &Retained::into_super(attachment),
        );
        Ok(Retained::into_super(dev))
    };
    disks.push(attach(&config.root, false)?);
    disks.push(attach(&config.seed, true)?);
    for disk in &config.extra_disks {
        match disk {
            Disk::File { path, readonly } => disks.push(attach(path, *readonly)?),
            Disk::Nbd { url, readonly } => disks.push(nbd_device(
                url.clone(),
                *readonly,
                signals,
                mtm,
                nbd_delegates,
            )?),
            Disk::NbdUnix {
                socket,
                export,
                readonly,
            } => {
                disks.push(nbd_device(
                    nbd_unix_uri(socket, export)?,
                    *readonly,
                    signals,
                    mtm,
                    nbd_delegates,
                )?);
            }
        }
    }
    vm_config.setStorageDevices(&NSArray::from_retained_slice(&disks));

    // ---- network -------------------------------------------------------
    // NAT needs no entitlement approval; bridged would need the restricted
    // com.apple.vm.networking. The MAC is pinned rather than random because
    // it is the only key into /var/db/dhcpd_leases (spike landmine 8).
    let net = VZVirtioNetworkDeviceConfiguration::new();
    net.setAttachment(Some(&Retained::into_super(
        VZNATNetworkDeviceAttachment::new(),
    )));
    net.setMACAddress(mac);
    let nets: Vec<Retained<VZNetworkDeviceConfiguration>> = vec![Retained::into_super(net)];
    vm_config.setNetworkDevices(&NSArray::from_retained_slice(&nets));

    // ---- serial console ------------------------------------------------
    // VZ's only serial device is a virtio console, which the guest sees as
    // /dev/hvc0 — never ttyS0 or ttyAMA0 (spike landmine 6). Guest-to-host
    // bytes go straight into console.log, which is the file `ast logs`
    // already knows how to read. The host-to-guest direction gets the read
    // end of /dev/null: an attachment with no reading handle is legal, but
    // leaves the guest's tty without a peer.
    if let Some(dir) = config.console.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&config.console)
        .with_context(|| format!("opening {}", config.console.display()))?;
    let stdin_side = std::fs::File::open("/dev/null")?;
    // closeOnDealloc: false — the `File`s in `console_files` own these fds.
    let write_h = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        log.as_raw_fd(),
        false,
    );
    let read_h = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        stdin_side.as_raw_fd(),
        false,
    );
    console_files.push(log);
    console_files.push(stdin_side);

    let attachment =
        VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
            VZFileHandleSerialPortAttachment::alloc(),
            Some(&read_h),
            Some(&write_h),
        );
    let serial = VZVirtioConsoleDeviceSerialPortConfiguration::new();
    serial.setAttachment(Some(&Retained::into_super(attachment)));
    let serials: Vec<Retained<VZSerialPortConfiguration>> = vec![Retained::into_super(serial)];
    vm_config.setSerialPorts(&NSArray::from_retained_slice(&serials));

    // ---- vsock ---------------------------------------------------------
    // Present but unused: this is the control channel a guest agent will
    // use, and the answer to the lease-file guesswork the address prober
    // does today (spike landmine 8's "better:"). Attaching the device now
    // costs nothing, needs no guest cooperation, and means the plumbing is
    // already in every guest by the time there is an agent to talk to.
    let vsock: Vec<Retained<VZSocketDeviceConfiguration>> = vec![Retained::into_super(
        VZVirtioSocketDeviceConfiguration::new(),
    )];
    vm_config.setSocketDevices(&NSArray::from_retained_slice(&vsock));

    // ---- odds and ends -------------------------------------------------
    // Entropy is not optional in practice: without virtio-rng a Debian
    // guest stalls for tens of seconds seeding sshd's host keys on first
    // boot, which is exactly the wait `ast up` is measured on.
    let rng: Vec<Retained<VZEntropyDeviceConfiguration>> = vec![Retained::into_super(
        VZVirtioEntropyDeviceConfiguration::new(),
    )];
    vm_config.setEntropyDevices(&NSArray::from_retained_slice(&rng));

    let balloon: Vec<Retained<VZMemoryBalloonDeviceConfiguration>> = vec![Retained::into_super(
        VZVirtioTraditionalMemoryBalloonDeviceConfiguration::new(),
    )];
    vm_config.setMemoryBalloonDevices(&NSArray::from_retained_slice(&balloon));

    vm_config
        .validateWithError()
        .map_err(vz_err)
        .context("VZVirtualMachineConfiguration rejected the configuration")?;
    Ok(vm_config)
}

/// Build the VM and start it. Returns once VZ reports the machine started.
///
/// # Safety
/// Must be called on the main thread.
pub unsafe fn start(config: &Config) -> Result<Machine> {
    if !VZVirtualMachine::isSupported() {
        bail!("Virtualization.framework reports this host cannot run VMs");
    }
    let mtm = MainThreadMarker::new()
        .ok_or_else(|| anyhow!("the VZ helper must build its VM on the main thread"))?;

    let mac = VZMACAddress::initWithString(VZMACAddress::alloc(), &NSString::from_str(&config.mac))
        .ok_or_else(|| anyhow!("{} is not a valid MAC address", config.mac))?;

    let signals = Rc::new(Signals::default());
    let mut console_files = Vec::new();
    let mut nbd_delegates = Vec::new();
    let vm_config = build_config(
        config,
        &mac,
        &mut console_files,
        &mut nbd_delegates,
        &signals,
        mtm,
    )?;

    // No queue argument: `initWithConfiguration:` binds the VM to the main
    // queue, so callbacks arrive when the loop below pumps it.
    let vm = VZVirtualMachine::initWithConfiguration(VZVirtualMachine::alloc(), &vm_config);

    let delegate = {
        let this = Delegate::alloc(mtm).set_ivars(signals.clone());
        let this: Retained<Delegate> = msg_send![super(this), init];
        this
    };
    vm.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));

    // The start completion block is delivered on the VM's queue. `Cell` in
    // an `Rc` is enough because that queue is this thread.
    let outcome: Rc<Cell<Option<bool>>> = Rc::new(Cell::new(None));
    let message: Rc<std::cell::RefCell<String>> = Rc::default();
    let handler = {
        let outcome = outcome.clone();
        let message = message.clone();
        RcBlock::new(move |err: *mut NSError| {
            if let Some(err) = unsafe { err.as_ref() } {
                *message.borrow_mut() = err.localizedDescription().to_string();
                outcome.set(Some(false));
            } else {
                outcome.set(Some(true));
            }
        })
    };
    vm.startWithCompletionHandler(&handler);

    // Pump until the completion block fires. Without this it never runs: it
    // is queued on the main queue and nothing else is draining it (spike
    // landmine 3).
    let deadline = Instant::now() + Duration::from_secs(30);
    while outcome.get().is_none() {
        if Instant::now() > deadline {
            bail!("VZ never called the start completion handler");
        }
        pump(Duration::from_millis(50));
    }
    if outcome.get() == Some(false) {
        let why = message.borrow().clone();
        // The failures a user can actually fix, named.
        if why.contains("not supported") || why.to_lowercase().contains("entitle") {
            bail!(
                "{why} — this usually means {} is not code-signed with {} and {}: \
                 run scripts/sign-vz.sh",
                asterism_vz::HELPER_BIN,
                asterism_vz::ENTITLEMENT,
                asterism_vz::NETWORK_CLIENT_ENTITLEMENT,
            );
        }
        bail!("startWithCompletionHandler failed: {why}");
    }

    Ok(Machine {
        vm,
        _delegate: delegate,
        _nbd_delegates: nbd_delegates,
        _console_files: console_files,
        signals,
    })
}

/// Run the main run loop for `slice`, letting VZ deliver its callbacks.
///
/// Every wait in this process goes through here rather than
/// `thread::sleep`: sleeping on the main thread starves the queue the VM is
/// bound to, and the guest simply stops making progress (spike landmine 9).
pub fn pump(slice: Duration) {
    let until = NSDate::dateWithTimeIntervalSinceNow(slice.as_secs_f64());
    NSRunLoop::mainRunLoop().runUntilDate(&until);
}

impl Machine {
    /// # Safety
    /// Main thread only.
    pub unsafe fn state(&self) -> State {
        match self.vm.state() {
            VZVirtualMachineState::Stopped => State::Stopped,
            VZVirtualMachineState::Running => State::Running,
            VZVirtualMachineState::Paused => State::Paused,
            VZVirtualMachineState::Starting => State::Starting,
            VZVirtualMachineState::Stopping => State::Stopping,
            _ => State::Error,
        }
    }

    /// ACPI shutdown request, then the forced stop if the guest will not
    /// take it. The framework's equivalent of QMP `system_powerdown`
    /// followed by SIGKILL — and, unlike killing a process, the answer here
    /// comes back through the delegate, so the caller learns *how* the
    /// guest went down.
    ///
    /// # Safety
    /// Main thread only.
    pub unsafe fn graceful_stop(&self, budget: Duration) -> StopReason {
        // Already gone: a guest that powered itself off between the request
        // arriving and us acting on it is a clean stop, not a failure.
        if let Some(reason) = self.signals.reason() {
            return reason;
        }
        if self.vm.canRequestStop() {
            match self.vm.requestStopWithError() {
                Ok(()) => {
                    let until = Instant::now() + budget;
                    while !self.signals.stopped() && Instant::now() < until {
                        pump(Duration::from_millis(100));
                    }
                    if let Some(reason) = self.signals.reason() {
                        return reason;
                    }
                }
                Err(e) => {
                    eprintln!("astd-vz: requestStop refused: {}", e.localizedDescription());
                }
            }
        }
        self.force_stop()
    }

    /// `stopWithCompletionHandler:` — the power cord.
    ///
    /// # Safety
    /// Main thread only.
    pub unsafe fn force_stop(&self) -> StopReason {
        if !self.vm.canStop() {
            return self.signals.reason().unwrap_or(StopReason::Forced);
        }
        let done = Rc::new(Cell::new(false));
        let handler = {
            let done = done.clone();
            RcBlock::new(move |_e: *mut NSError| done.set(true))
        };
        self.vm.stopWithCompletionHandler(&handler);
        let until = Instant::now() + Duration::from_secs(10);
        while !done.get() && Instant::now() < until {
            pump(Duration::from_millis(100));
        }
        StopReason::Forced
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_nbd_uri_preserves_free_text_as_data() {
        let uri = nbd_unix_uri(
            Path::new("/tmp/asterism volume?#.sock"),
            "team/working set?#한글",
        )
        .unwrap();
        assert_eq!(
            uri,
            "nbd+unix:///team%2Fworking%20set%3F%23%ED%95%9C%EA%B8%80?\
             socket=%2Ftmp%2Fasterism%20volume%3F%23.sock"
        );
    }

    #[test]
    fn apple_accepts_and_constructs_standard_nbd_attachments_without_connecting() {
        let uri = nbd_unix_uri(Path::new("/tmp/asterism-nbd.sock"), "volume").unwrap();
        for uri in [&uri, "nbd://127.0.0.1:10809/volume"] {
            let url = network_url(uri).unwrap();
            // Apple's validator and initializer are purely local: the NBD
            // connection is deferred until VM start, so this test needs
            // neither a server nor entitlements.
            unsafe {
                VZNetworkBlockDeviceStorageDeviceAttachment::validateURL_error(&url).unwrap();
                let attachment = VZNetworkBlockDeviceStorageDeviceAttachment::initWithURL_timeout_forcedReadOnly_synchronizationMode_error(
                    VZNetworkBlockDeviceStorageDeviceAttachment::alloc(),
                    &url,
                    30.0,
                    true,
                    VZDiskSynchronizationMode::Full,
                )
                .unwrap();
                assert_eq!(attachment.timeout(), 30.0);
                assert!(attachment.isForcedReadOnly());
                assert_eq!(
                    attachment.synchronizationMode(),
                    VZDiskSynchronizationMode::Full
                );
            }
        }
    }

    #[test]
    fn nbd_uri_components_refuse_nul() {
        assert!(nbd_unix_uri(Path::new("/tmp/socket"), "bad\0export").is_err());
    }
}
