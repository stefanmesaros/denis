//! Windows Service wrapper: `denis service install|uninstall|start|stop`, and the Service
//! Control Manager's own entry point (`denis service run`, never invoked by a person).
//!
//! **UNVERIFIED on a real Windows machine** — written against `windows-service`'s documented API
//! and checked only by `cargo check`/`clippy --target x86_64-pc-windows-gnu`, exactly like every
//! other Windows-only piece in this codebase before it was run for real (see WINDOWS.md, whose own
//! standard this follows: nothing here is called "done" from a cross-compile alone).
//!
//! Deliberately a thin wrapper, not a reimplementation of the engine's startup inside the SCM's
//! own callback: the service supervises `denis.exe run <args>` as an ordinary **child process**
//! (the same pattern NSSM and countless other "run this CLI tool as a service" wrappers use).
//! This keeps the well-tested `denis run` code path completely untouched — nothing here can
//! regress it — and the service adds only what a service actually needs beyond that: a control
//! handler the SCM understands, and somewhere to send the child's output now that there is no
//! systemd journal (a plain log file next to the executable, see `log_file`).
//!
//! The account this runs as is a deliberate open question, not an oversight: see WINDOWS.md's
//! "What is genuinely missing" item 1 for the researched recommendation (a dedicated low-privilege
//! virtual service account, `NT SERVICE\denis`, not `LocalSystem`) — `install` below defaults to
//! whatever `sc.exe`/the Services console lets an administrator choose, since setting a service's
//! log-on account programmatically at creation time is exactly the kind of untested path this
//! module avoids until it can be run for real.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType,
    ServiceState, ServiceStatus, ServiceType, ServiceControl, ServiceControlAccept,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "denis";
const SERVICE_DISPLAY_NAME: &str = "DENIS Network Asset Discovery";

/// Where the arguments given to `service install -- <run args>` are kept, so `service run` (which
/// the SCM invokes with no arguments of its own) knows what to launch. A JSON array next to the
/// executable, not a single string: storing it pre-split avoids re-parsing shell quoting for an
/// argument that itself contains spaces (a `--tls-names` value, say).
fn args_file() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name("service-args.json"))
}

/// Where the supervised `denis run` child's stdout/stderr go: there is no systemd journal here.
fn log_file() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name("service.log"))
}

/// Register the service (does not start it — see `start`). Stores `run_args` for `service run` to
/// use every time the SCM launches it, so reinstalling is never needed just to change a flag;
/// running `install` again first (it refuses if already installed — uninstall, then reinstall) is.
pub fn install(run_args: &[String]) -> Result<()> {
    fs::write(args_file()?, serde_json::to_vec(run_args)?).context("writing service-args.json next to the executable")?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let exe = std::env::current_exe()?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("service"), OsString::from("run")],
        dependencies: vec![],
        // LocalSystem by default (windows-service's own default when unset): see this module's own
        // doc comment on why a narrower account is the eventual goal but not set here yet.
        account_name: None,
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
    let _ = service.set_description("Network asset discovery, fingerprinting and anomaly detection.");
    println!("service installed (not started - run: denis service start)");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    let _ = fs::remove_file(args_file()?);
    println!("service uninstalled");
    Ok(())
}

pub fn start() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[] as &[&std::ffi::OsStr])?;
    println!("service start requested");
    Ok(())
}

pub fn stop() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop()?;
    println!("service stop requested");
    Ok(())
}

windows_service::define_windows_service!(ffi_service_main, service_main);

/// The actual entry point when the SCM launches `denis.exe service run`. Blocks until the service
/// stops; never returns on success in the way an interactive command would.
pub fn run_dispatcher() -> Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        // Nowhere else to report this: the SCM already believes we are starting, and stdout goes
        // nowhere useful under the SCM. Best effort only - if this write also fails, there is
        // genuinely no channel left to explain why.
        if let Ok(p) = log_file() {
            let _ = fs::write(p.with_file_name("service-error.log"), format!("denis service failed to start: {e:#}\n"));
        }
    }
}

fn run_service() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    let set_status = |state: ServiceState, exit_code: ServiceExitCode, wait_hint: Duration| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if matches!(state, ServiceState::Running) { ServiceControlAccept::STOP } else { ServiceControlAccept::empty() },
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        });
    };
    set_status(ServiceState::StartPending, ServiceExitCode::Win32(0), Duration::from_secs(5));

    let run_args: Vec<String> = serde_json::from_slice(&fs::read(args_file()?).context("reading service-args.json: was this service installed with `denis service install`?")?)?;
    let exe = std::env::current_exe()?;
    let out = fs::File::create(log_file()?)?;
    let err = out.try_clone()?;
    let mut child: Child = Command::new(&exe).arg("run").args(&run_args).stdout(Stdio::from(out)).stderr(Stdio::from(err)).spawn().context("starting the supervised `denis run` process")?;

    set_status(ServiceState::Running, ServiceExitCode::Win32(0), Duration::from_secs(0));

    // Wait for whichever comes first: a Stop control from the SCM, or the child exiting on its
    // own (a crash, or `denis run` refusing bad arguments at start-up).
    loop {
        if shutdown_rx.recv_timeout(Duration::from_millis(500)).is_ok() {
            set_status(ServiceState::StopPending, ServiceExitCode::Win32(0), Duration::from_secs(5));
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        if let Some(status) = child.try_wait()? {
            let code = status.code().unwrap_or(1) as u32;
            set_status(ServiceState::StopPending, ServiceExitCode::ServiceSpecific(code), Duration::from_secs(1));
            break;
        }
    }
    set_status(ServiceState::Stopped, ServiceExitCode::Win32(0), Duration::from_secs(0));
    Ok(())
}
