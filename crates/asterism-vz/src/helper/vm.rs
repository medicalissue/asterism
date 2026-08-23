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

use std::cell::{Cell, RefCell};
use std::ffi::{c_int, c_void};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
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
    VZDirectorySharingDeviceConfiguration, VZDiskImageCachingMode,
    VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode, VZDiskSynchronizationMode,
    VZEFIBootLoader, VZEFIVariableStore, VZEFIVariableStoreInitializationOptions,
    VZEntropyDeviceConfiguration, VZFileHandleSerialPortAttachment, VZGenericPlatformConfiguration,
    VZLinuxBootLoader, VZMACAddress, VZMemoryBalloonDeviceConfiguration,
    VZNATNetworkDeviceAttachment, VZNetworkBlockDeviceStorageDeviceAttachment,
    VZNetworkBlockDeviceStorageDeviceAttachmentDelegate, VZNetworkDevice,
    VZNetworkDeviceConfiguration, VZSerialPortConfiguration, VZSharedDirectory,
    VZSingleDirectoryShare, VZSocketDeviceConfiguration, VZStorageDeviceConfiguration,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceSerialPortConfiguration,
    VZVirtioEntropyDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
    VZVirtioSocketDeviceConfiguration, VZVirtioTraditionalMemoryBalloonDeviceConfiguration,
    VZVirtualMachine, VZVirtualMachineConfiguration, VZVirtualMachineDelegate,
    VZVirtualMachineState,
};

use asterism_vz::{Config, Disk, State, StopReason, StorageError};

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
    /// The first of those failures, kept whole. Once this is set the guest
    /// is running on a disk that is not there, and the run loop takes it
    /// down — see [`Machine::state`] and `main`.
    storage_failure: std::cell::RefCell<Option<StorageError>>,
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

    /// `attachmentWasConnected:` — the initial connect, and every
    /// transparent reconnect after a *recoverable* failure. Telemetry and
    /// nothing else: the guest never noticed, so neither does the state.
    fn note_nbd_connected(&self, uri: &str) {
        let previous = self.nbd_connections.get();
        self.nbd_connections.set(previous + 1);
        eprintln!(
            "astd-vz: NBD {} to {uri}",
            if previous == 0 {
                "connected"
            } else {
                "reconnected"
            },
        );
    }

    /// `attachment:didEncounterError:` — the end of that disk. Apple: "the
    /// NBD client will be in a non-functional state after this method is
    /// invoked", and there is no API to re-attach one under a running VM.
    ///
    /// Counting it and carrying on was the bug this replaces: the guest
    /// went on writing into a device that would never take a byte again,
    /// and `info` went on saying `running`.
    fn note_storage_failure(&self, uri: &str, message: String) {
        self.nbd_terminal_errors
            .set(self.nbd_terminal_errors.get() + 1);
        eprintln!("astd-vz: NBD attachment {uri} entered a non-recoverable state: {message}");
        // First one wins: it is the failure that killed the guest, and
        // anything after it is fallout from the same loss.
        let mut slot = self.storage_failure.borrow_mut();
        if slot.is_none() {
            *slot = Some(StorageError {
                uri: uri.to_owned(),
                message,
            });
        }
    }

    /// How many times a network disk connected — one for the first
    /// connection, one more for each transparent reconnect after it.
    pub fn nbd_connections(&self) -> u32 {
        self.nbd_connections.get()
    }

    /// How many attachments have failed for good. Distinct from
    /// [`Signals::nbd_connections`] by construction: a reconnect is
    /// recoverable and this never sees one.
    pub fn nbd_terminal_errors(&self) -> u32 {
        self.nbd_terminal_errors.get()
    }

    /// The failure that ends this guest, if one has happened.
    pub fn storage_failure(&self) -> Option<StorageError> {
        self.storage_failure.borrow().clone()
    }
}

/// What `info` should say, given what VZ says and whether a disk has gone.
///
/// The framework has no state for "running, but on a disk that is not
/// there": `VZVirtualMachineState` stays `Running` after the NBD client
/// gives up. So the helper substitutes one. It reports [`State::Error`]
/// rather than a new state of its own because an `astd` older than this
/// change cannot parse a new one — it would fail the whole `Info`, fall
/// back to "is the pid alive", and answer *running* for exactly the guest
/// this exists to stop reporting as healthy.
fn reported_state(vm: State, storage_failed: bool) -> State {
    match storage_failed && vm.is_live() {
        true => State::Error,
        // Once VZ agrees the machine is down, its own answer is the more
        // precise one.
        false => vm,
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
            let ivars = self.ivars();
            ivars.signals.note_nbd_connected(&ivars.uri);
        }

        #[unsafe(method(attachment:didEncounterError:))]
        fn attachment_did_encounter_error(
            &self,
            _attachment: &VZNetworkBlockDeviceStorageDeviceAttachment,
            error: &NSError,
        ) {
            let ivars = self.ivars();
            ivars
                .signals
                .note_storage_failure(&ivars.uri, error.localizedDescription().to_string());
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
    /// The guest's virtio socket device, taken off the running VM once.
    ///
    /// `socketDevices` is a property of the *machine*, not of the
    /// configuration, so it only exists after `init`. Held because every
    /// connect goes through it, and dropping it would mean asking the VM
    /// for it again on every attempt.
    socket_device: Option<Retained<VZVirtioSocketDevice>>,
    /// A connect that has been asked for and not yet answered.
    ///
    /// VZ's connect is asynchronous and its completion block arrives on
    /// this queue, so the run loop asks for one and picks the answer up on
    /// a later turn ([`Machine::take_connect`]) rather than pumping in
    /// place for it. Pumping in place would be *safe* — the guest keeps
    /// running — but nothing would be draining the control socket's jobs
    /// for the length of it, and a daemon asking `info` during a boot would
    /// time out.
    connecting: RefCell<Option<Rc<RefCell<Option<Connected>>>>>,
    /// The connection a session is running on, kept alive for exactly as
    /// long as that session is.
    ///
    /// VZ closes the connection's descriptor when this object is released.
    /// The session thread works on a *duplicate* of it, so the socket
    /// itself would survive — but holding the object is what keeps the
    /// framework's own accounting honest, and dropping it is how a session
    /// that has ended is actually torn down.
    connection: RefCell<Option<Retained<VZVirtioSocketConnection>>>,
    pub signals: Rc<Signals>,
}

/// What a completed connect leaves behind: the framework's connection
/// object, which must stay on this queue, and a descriptor of our own,
/// which need not.
type Connected = Result<(Retained<VZVirtioSocketConnection>, RawFd), String>;

/// Make an owned copy of a descriptor VZ gave us and prove that it is still
/// a socket before handing it to the agent thread.
///
/// A restarted guest can race `connectToPort:`: the completion may carry a
/// non-negative descriptor whose number has already been reused. `dup` only
/// proves that the number is currently open; `SO_TYPE` also proves that it is
/// a socket. Keeping the duplicate in `OwnedFd` while checking it makes the
/// rejected path close its copy immediately.
fn duplicate_socket_fd(fd: RawFd) -> Result<RawFd, String> {
    let copy = unsafe { dup(fd) };
    if copy == -1 {
        return Err(format!(
            "could not duplicate the connection's descriptor (fd {fd}): {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `dup` returned a new descriptor owned by this process.
    let copy = unsafe { OwnedFd::from_raw_fd(copy) };
    socket_type(copy.as_raw_fd()).map_err(|err| {
        format!(
            "VZ returned a stale guest-agent descriptor (fd {fd}, duplicated as {}): \
             checking SO_TYPE failed: {err}",
            copy.as_raw_fd(),
        )
    })?;
    Ok(copy.into_raw_fd())
}

/// Ask the kernel whether `fd` is a socket without changing its state.
fn socket_type(fd: RawFd) -> std::io::Result<c_int> {
    let mut kind = 0;
    let mut len = std::mem::size_of_val(&kind) as SockLen;
    // SAFETY: the pointers name writable local storage for the duration of
    // this call, and the constants are the Darwin socket ABI values.
    let result = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_TYPE,
            (&mut kind as *mut c_int).cast::<c_void>(),
            &mut len,
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(kind)
    }
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
    match &config.direct_kernel {
        Some(direct) => {
            if !direct.kernel.exists() {
                bail!("{} is not there to boot", direct.kernel.display());
            }
            let boot = VZLinuxBootLoader::initWithKernelURL(
                VZLinuxBootLoader::alloc(),
                &url(&direct.kernel),
            );
            boot.setCommandLine(&NSString::from_str(&direct.cmdline));
            if let Some(initrd) = &direct.initrd {
                if !initrd.exists() {
                    bail!("{} is not there to boot", initrd.display());
                }
                boot.setInitialRamdiskURL(Some(&url(initrd)));
            }
            vm_config.setBootLoader(Some(&Retained::into_super(boot)));
        }
        None => {
            // EFI with a persistent variable store. The store is what
            // remembers the boot entry the guest's GRUB installed, so it is
            // created once and reused (spike landmine 5).
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
        }
    }

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
    // A directly booted OCI rootfs has no cloud-init and therefore no seed.
    // Cloud images keep the historical root/seed ordering.
    if config.direct_kernel.is_none() {
        disks.push(attach(&config.seed, true)?);
    }
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

    // ---- directory shares ---------------------------------------------
    // One virtiofs device per mounted directory. Its tag is the same stable
    // tag the seed wrote as `What=`, while the framework owns the entire
    // host side of the transport. These are writable because directory
    // volumes currently have no read-only mode in the product model.
    let mut shares: Vec<Retained<VZDirectorySharingDeviceConfiguration>> = Vec::new();
    for share in &config.shares {
        if !share.path.is_dir() {
            bail!("{} is not a directory to share", share.path.display());
        }
        let tag = NSString::from_str(&share.tag);
        VZVirtioFileSystemDeviceConfiguration::validateTag_error(&tag)
            .map_err(vz_err)
            .with_context(|| format!("validating virtiofs tag {:?}", share.tag))?;

        let directory = VZSharedDirectory::initWithURL_readOnly(
            VZSharedDirectory::alloc(),
            &url(&share.path),
            false,
        );
        let single =
            VZSingleDirectoryShare::initWithDirectory(VZSingleDirectoryShare::alloc(), &directory);
        let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
            VZVirtioFileSystemDeviceConfiguration::alloc(),
            &tag,
        );
        device.setShare(Some(&Retained::into_super(single)));
        shares.push(Retained::into_super(device));
    }
    vm_config.setDirectorySharingDevices(&NSArray::from_retained_slice(&shares));

    // ---- network -------------------------------------------------------
    // An empty list is how a container utility VM gets no uplink. Merely
    // skipping DHCP discovery would still leave a NAT attachment available
    // to a privileged workload. Ordinary VMs retain the historical NAT NIC.
    let mut nets: Vec<Retained<VZNetworkDeviceConfiguration>> = Vec::new();
    if config.network_enabled {
        // NAT needs no entitlement approval; bridged would need the restricted
        // com.apple.vm.networking. The MAC is pinned rather than random because
        // it is the only key into /var/db/dhcpd_leases (spike landmine 8).
        let net = VZVirtioNetworkDeviceConfiguration::new();
        net.setAttachment(Some(&Retained::into_super(
            VZNATNetworkDeviceAttachment::new(),
        )));
        net.setMACAddress(mac);
        nets.push(Retained::into_super(net));
    }
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
    // The guest's control channel: point-to-point, on no network, and the
    // answer to the lease-file guesswork the address prober does (spike
    // landmine 8's "better:"). The agent at the other end of it is put
    // there by the seed; see `asterism_vz::guest`. A guest that has no
    // agent simply never answers on the port, which costs it nothing.
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

    // `socketDevices` is on the machine rather than on the configuration,
    // so this is the first moment it exists. One device was configured, so
    // there is one here; a guest built by some future path without one gets
    // `None` and the fallback discovery, rather than a panic.
    let socket_device = vm
        .socketDevices()
        .to_vec()
        .into_iter()
        .find_map(|device| device.downcast::<VZVirtioSocketDevice>().ok())
        .or_else(|| {
            eprintln!("astd-vz: this guest has no virtio socket device — no guest agent");
            None
        });

    Ok(Machine {
        vm,
        _delegate: delegate,
        _nbd_delegates: nbd_delegates,
        _console_files: console_files,
        socket_device,
        connecting: RefCell::new(None),
        connection: RefCell::new(None),
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
    /// What to tell the daemon about this guest.
    ///
    /// Not simply `VZVirtualMachine.state`: a guest whose disk has failed
    /// for good still reads as `Running` there, and answering `running` to
    /// `info` is what let a permanently broken guest look healthy. See
    /// [`reported_state`].
    ///
    /// # Safety
    /// Main thread only.
    pub unsafe fn state(&self) -> State {
        reported_state(self.vm_state(), self.signals.storage_failure().is_some())
    }

    /// VZ's own answer, untouched.
    ///
    /// # Safety
    /// Main thread only.
    unsafe fn vm_state(&self) -> State {
        match self.vm.state() {
            VZVirtualMachineState::Stopped => State::Stopped,
            VZVirtualMachineState::Running => State::Running,
            VZVirtualMachineState::Paused => State::Paused,
            VZVirtualMachineState::Starting => State::Starting,
            VZVirtualMachineState::Stopping => State::Stopping,
            _ => State::Error,
        }
    }

    /// Ask the guest to power down and return immediately.
    ///
    /// [`Machine::graceful_stop`] pumps the run loop until the guest
    /// answers, which is right when the daemon is waiting on the other end
    /// of a `stop`. It is wrong when the helper takes the guest down on its
    /// own: nothing is draining the control socket's jobs during that wait,
    /// so `info` would time out for the whole budget and the daemon would
    /// fall back to the pid — and call a dying guest running. Requesting
    /// without waiting leaves the run loop free to keep answering.
    ///
    /// Returns whether VZ took the request; `false` means only
    /// [`Machine::force_stop`] is left.
    ///
    /// # Safety
    /// Main thread only.
    pub unsafe fn request_stop(&self) -> bool {
        if !self.vm.canRequestStop() {
            return false;
        }
        match self.vm.requestStopWithError() {
            Ok(()) => true,
            Err(e) => {
                eprintln!("astd-vz: requestStop refused: {}", e.localizedDescription());
                false
            }
        }
    }

    /// Ask for a connection to the guest agent's port.
    ///
    /// Returns as soon as VZ has taken the request; the answer arrives on
    /// this queue and is picked up by [`Machine::take_connect`]. A guest
    /// with no agent listening is the ordinary case while one boots — that
    /// is an error to retry, not one to report.
    ///
    /// # Safety
    /// Main thread only.
    pub unsafe fn start_connect(&self, port: u32) -> Result<()> {
        let device = self
            .socket_device
            .as_ref()
            .ok_or_else(|| anyhow!("this guest has no virtio socket device"))?;
        if self.connecting.borrow().is_some() {
            bail!("a connect to vsock port {port} is already in flight");
        }
        if self.connection.borrow().is_some() {
            bail!("this guest already has an agent connection open");
        }

        // Filled by the completion block, which VZ delivers on this same
        // queue — so `Rc` and `RefCell` are enough, as they are for the
        // start handler above.
        let slot: Rc<RefCell<Option<Connected>>> = Rc::default();
        let handler = {
            let slot = slot.clone();
            RcBlock::new(
                move |conn: *mut VZVirtioSocketConnection, err: *mut NSError| {
                    let outcome = match unsafe { err.as_ref() } {
                        Some(err) => Err(err.localizedDescription().to_string()),
                        None => match unsafe { Retained::retain(conn) } {
                            None => Err("VZ reported neither a connection nor an error".to_owned()),
                            Some(conn) => {
                                // Duped rather than borrowed: VZ closes its own
                                // descriptor when this object is released, and
                                // the session thread must not be reading a
                                // descriptor somebody else can close. `dup`
                                // alone is not enough after a quick guest-agent
                                // restart: a stale descriptor number can already
                                // name something else by this point.
                                duplicate_socket_fd(conn.fileDescriptor()).map(|fd| (conn, fd))
                            }
                        },
                    };
                    *slot.borrow_mut() = Some(outcome);
                },
            )
        };
        device.connectToPort_completionHandler(port, &handler);
        *self.connecting.borrow_mut() = Some(slot);
        Ok(())
    }

    /// The answer to that connect, once VZ has given one.
    ///
    /// `None` while it is still in flight, and `None` when none was asked
    /// for. The descriptor in an `Ok` belongs to the caller; the connection
    /// object behind it is kept here until [`Machine::close_agent`].
    ///
    /// # Safety
    /// Main thread only.
    pub unsafe fn take_connect(&self) -> Option<Result<RawFd>> {
        let slot = self.connecting.borrow().clone()?;
        let outcome = slot.borrow_mut().take()?;
        *self.connecting.borrow_mut() = None;
        Some(match outcome {
            Err(why) => Err(anyhow!("connecting to the guest agent: {why}")),
            Ok((conn, fd)) => {
                *self.connection.borrow_mut() = Some(conn);
                Ok(fd)
            }
        })
    }

    /// Has a connect been asked for and not yet answered?
    pub fn connect_in_flight(&self) -> bool {
        self.connecting.borrow().is_some()
    }

    /// Release the connection a finished session was running on.
    ///
    /// # Safety
    /// Main thread only.
    pub unsafe fn close_agent(&self) {
        if let Some(conn) = self.connection.borrow_mut().take() {
            conn.close();
        }
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

// `dup(2)`, declared here rather than taking on `libc` for one symbol — the
// same call `main.rs` makes for `setsid` and `asterism_core::cow` makes for
// `clonefile`.
extern "C" {
    fn dup(fd: c_int) -> c_int;
    fn getsockopt(
        socket: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        value_len: *mut SockLen,
    ) -> c_int;
}

// Darwin's `socklen_t`, `SOL_SOCKET`, and `SO_TYPE`. Kept here with `dup`
// rather than adding libc solely for these two FFI calls.
type SockLen = u32;
const SOL_SOCKET: c_int = 0xffff;
const SO_TYPE: c_int = 0x1008;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_descriptor_must_still_be_a_socket() {
        use std::fs::File;
        use std::os::unix::net::UnixStream;

        let (socket, _) = UnixStream::pair().unwrap();
        let copy = duplicate_socket_fd(socket.as_raw_fd()).unwrap();
        // SAFETY: `duplicate_socket_fd` returns a fresh descriptor owned by
        // this test. This also proves the accepted path stays usable.
        let copy = unsafe { OwnedFd::from_raw_fd(copy) };
        assert!(socket_type(copy.as_raw_fd()).is_ok());

        // `dup` succeeds for this descriptor, but it is not a socket. This
        // is the stale-number case a fast guest-agent restart can create;
        // reject it before the session thread reaches `setsockopt`.
        let not_a_socket = File::open("/dev/null").unwrap();
        let error = duplicate_socket_fd(not_a_socket.as_raw_fd()).unwrap_err();
        assert!(error.contains("checking SO_TYPE failed"), "{error}");
    }

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

    /// The two NBD callbacks mean opposite things, and the difference is
    /// the whole of this fix: a reconnect is bookkeeping, a
    /// `didEncounterError:` is the disk never coming back.
    #[test]
    fn a_reconnect_is_telemetry_and_a_terminal_error_ends_the_guest() {
        let uri = "nbd+unix:///team%2Fdata?socket=%2Ftmp%2Fv.sock";
        let signals = Signals::default();

        // First connect, then a transparent reconnect after something
        // recoverable. VZ retried; the guest never noticed.
        signals.note_nbd_connected(uri);
        signals.note_nbd_connected(uri);
        assert_eq!(signals.nbd_connections(), 2);
        assert_eq!(signals.nbd_terminal_errors(), 0);
        assert!(signals.storage_failure().is_none());
        assert!(!signals.stopped(), "a reconnect is not a death");
        assert_eq!(
            reported_state(State::Running, signals.storage_failure().is_some()),
            State::Running,
            "and the guest is still healthy while VZ is reconnecting"
        );

        signals.note_storage_failure(uri, "Connection reset by peer".into());
        assert_eq!(signals.nbd_terminal_errors(), 1);
        assert_eq!(
            signals.nbd_connections(),
            2,
            "no reconnect follows this one"
        );
        let failure = signals.storage_failure().expect("the disk is gone");
        assert_eq!(failure.uri, uri);
        assert_eq!(failure.message, "Connection reset by peer");

        // The first loss is the one that killed the guest; later noise from
        // the same dead attachment does not overwrite it, but is counted.
        signals.note_storage_failure(uri, "Broken pipe".into());
        assert_eq!(signals.nbd_terminal_errors(), 2);
        assert_eq!(
            signals.storage_failure().unwrap().message,
            "Connection reset by peer"
        );
    }

    /// A guest VZ still calls `Running` must not be reported as running
    /// once its disk has failed — that is the state a supervisor would sit
    /// on forever while the guest writes into nothing.
    #[test]
    fn no_live_state_survives_a_lost_disk() {
        for live in [
            State::Starting,
            State::Running,
            State::Paused,
            State::Stopping,
        ] {
            assert_eq!(reported_state(live, false), live, "healthy: VZ's answer");
            assert_eq!(reported_state(live, true), State::Error);
            assert!(!reported_state(live, true).is_live());
        }
        // Once VZ agrees, its answer is the more precise one and stands.
        assert_eq!(reported_state(State::Stopped, true), State::Stopped);
        assert_eq!(reported_state(State::Error, true), State::Error);
    }

    #[test]
    fn nbd_uri_components_refuse_nul() {
        assert!(nbd_unix_uri(Path::new("/tmp/socket"), "bad\0export").is_err());
    }
}
