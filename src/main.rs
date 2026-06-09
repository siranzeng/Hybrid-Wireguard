#![allow(unused)]
#![cfg_attr(feature = "unstable", feature(test))]

#[cfg(any(
    all(feature = "hybrid", feature = "post_quantum"),
    all(feature = "hybrid", feature = "hybrid_new"),
    all(feature = "hybrid_new", feature = "post_quantum")
))]
compile_error!("Features hybrid, hybrid_new and post_quantum are mutually exclusive");

extern crate alloc;

#[cfg(feature = "profiler")]
extern crate cpuprofiler;

#[cfg(feature = "profiler")]
use cpuprofiler::PROFILER;

mod benchmarks;
mod configuration;
mod configuration_hybrid;
mod configuration_hybrid_new;
mod configuration_pq_star;
mod platform;
mod wireguard;
mod wireguard_hybrid;
mod wireguard_hybrid_new;
mod wireguard_pq_star;

#[cfg(target_os = "linux")]
mod util;

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::process::exit;
#[cfg(target_os = "linux")]
use std::thread;

#[cfg(target_os = "linux")]
use platform::tun::{PlatformTun, Status};
#[cfg(target_os = "linux")]
use platform::uapi::{BindUAPI, PlatformUAPI};
#[cfg(target_os = "linux")]
use platform::*;

#[cfg(target_os = "linux")]
use crate::benchmarks::benchmarks::wireguard_benchmarks;

#[cfg(feature = "hybrid")]
use configuration_hybrid::uapi;
#[cfg(feature = "hybrid")]
use configuration_hybrid::Configuration;
#[cfg(feature = "hybrid")]
use configuration_hybrid::WireGuardConfig;
#[cfg(feature = "hybrid")]
use wireguard_hybrid::WireGuard;

#[cfg(feature = "hybrid_new")]
use configuration_hybrid_new::uapi;
#[cfg(feature = "hybrid_new")]
use configuration_hybrid_new::Configuration;
#[cfg(feature = "hybrid_new")]
use configuration_hybrid_new::WireGuardConfig;
#[cfg(feature = "hybrid_new")]
use wireguard_hybrid_new::WireGuard;

#[cfg(feature = "post_quantum")]
use configuration_pq_star::uapi;
#[cfg(feature = "post_quantum")]
use configuration_pq_star::Configuration;
#[cfg(feature = "post_quantum")]
use configuration_pq_star::WireGuardConfig;
#[cfg(feature = "post_quantum")]
use wireguard_pq_star::WireGuard;

#[cfg(all(
    not(feature = "hybrid"),
    not(feature = "hybrid_new"),
    not(feature = "post_quantum")
))]
use configuration::uapi;
#[cfg(all(
    not(feature = "hybrid"),
    not(feature = "hybrid_new"),
    not(feature = "post_quantum")
))]
use configuration::Configuration;
#[cfg(all(
    not(feature = "hybrid"),
    not(feature = "hybrid_new"),
    not(feature = "post_quantum")
))]
use configuration::WireGuardConfig;
#[cfg(all(
    not(feature = "hybrid"),
    not(feature = "hybrid_new"),
    not(feature = "post_quantum")
))]
use wireguard::WireGuard;

#[cfg(feature = "profiler")]
fn profiler_stop() {
    println!("Stopping profiler");
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(not(feature = "profiler"))]
fn profiler_stop() {}

#[cfg(feature = "profiler")]
fn profiler_start(name: &str) {
    use std::path::Path;

    // find first available path to save profiler output
    let mut n = 0;
    loop {
        let path = format!("./{}-{}.profile", name, n);
        if !Path::new(path.as_str()).exists() {
            println!("Starting profiler: {}", path);
            PROFILER.lock().unwrap().start(path).unwrap();
            break;
        };
        n += 1;
    }
}

fn help() {
    println!("Arguments:");
    println!("--help, -h => print help");
    println!("--bench, -b => execute benchmarks for wireguard, pq-wireguard and hybrid wireguard. Must be followed by an integer for nb. of handshake executions");
    println!("--foreground, -f => foreground from original wireguard implementation");
    println!("--disable-drop-privileges => from original wireguard implementation");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i].eq("--help") | args[i].eq("-h") {
            help();
            return;
        }
        if args[i].eq("--bench") | args[i].eq("-b") {
            if i + 1 == args.len() {
                panic!("nb. of executions is required when running benchmarks. Run with -h or --help for arguments listing.");
            }
            let nb_executions = args[i + 1].parse::<u32>().unwrap_or_else(|_| {
                panic!("nb. of executions argument is required when running benchmarks and must be an integer. Run with -h or --help for arguments listing.")
            });
            crate::benchmarks::benchmarks::wireguard_benchmarks(nb_executions);
            return;
        }
        i += 1;
    }
    eprintln!("The TUN/UAPI runtime entry point is only available on Linux. Use -b/--bench for protocol benchmarks on this platform.");
}

#[cfg(target_os = "linux")]
fn main() {
    // parse command line arguments
    let mut name = None;
    let mut drop_privileges = true;
    let mut foreground = false;
    let args: Vec<String> = env::args().collect();
    let mut nb_executions: u32 = 0;

    if args.len() < 2 {
        panic!("need at least one argument to run. Run with -h or --help for arguments listing.");
    }
    let mut i: usize = 1;
    while i < args.len() {
        if args[i].eq("--help") | args[i].eq("-h") {
            help();
            return;
        }
        if args[i].eq("--foreground") | args[i].eq("-f") {
            foreground = true;
            i += 1;
        } else if args[i].eq("--disable-drop-privileges") {
            drop_privileges = false;
            i += 1;
        } else if args[i].eq("--bench") | args[i].eq("-b") {
            if i + 1 == args.len() {
                panic!("nb. of executions is required when running benchmarks. Run with -h or --help for arguments listing.");
            }
            match args[i+1].parse::<u32>() {
                Ok(n) => nb_executions = n,
                Err(_) => panic!("nb. of executions argument is required when running benchmarks and must be an integer. Run with -h or --help for arguments listing."),
            }
            i += 2
        } else {
            name = Some(args[i].to_owned());
            i += 1;
        }
    }

    if nb_executions > 0 {
        wireguard_benchmarks(nb_executions);
        return;
    }

    // for arg in args {
    //     match arg.as_str() {
    //         "--foreground" | "-f" => {
    //             foreground = true;
    //         }
    //         "--disable-drop-privileges" => {
    //             drop_privileges = false;
    //         }
    //         dev => name = Some(dev.to_owned()),
    //     }
    // }

    // unwrap device name
    let name = match name {
        None => {
            eprintln!("No device name supplied");
            exit(-1);
        }
        Some(name) => name,
    };

    // create UAPI socket
    let uapi = plt::UAPI::bind(name.as_str()).unwrap_or_else(|e| {
        eprintln!("Failed to create UAPI listener: {}", e);
        exit(-2);
    });

    // create TUN device
    let (mut readers, writer, status) = plt::Tun::create(name.as_str()).unwrap_or_else(|e| {
        eprintln!("Failed to create TUN device: {}", e);
        exit(-3);
    });

    // drop privileges
    if drop_privileges {
        match util::drop_privileges() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to drop privileges: {}", e);
                exit(-4);
            }
        }
    }

    // daemonize to background
    if !foreground {
        match util::daemonize() {
            Ok(_) => (),
            Err(e) => {
                eprintln!("Failed to daemonize: {}", e);
                exit(-5);
            }
        }
    }

    // start logging
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");

    log::info!("Starting {} WireGuard device.", name);

    // start profiler (if enabled)
    #[cfg(feature = "profiler")]
    profiler_start(name.as_str());

    // create WireGuard device
    let wg: WireGuard<plt::Tun, plt::UDP> = WireGuard::new(writer);

    // add all Tun readers
    while let Some(reader) = readers.pop() {
        wg.add_tun_reader(reader);
    }

    // wrap in configuration interface
    let cfg = WireGuardConfig::new(wg.clone());

    // start Tun event thread
    {
        let cfg = cfg.clone();
        let mut status = status;
        thread::spawn(move || loop {
            match status.event() {
                Err(e) => {
                    log::info!("Tun device error {}", e);
                    profiler_stop();
                    exit(0);
                }
                Ok(tun::TunEvent::Up(mtu)) => {
                    log::info!("Tun up (mtu = {})", mtu);
                    let _ = cfg.up(mtu); // TODO: handle
                }
                Ok(tun::TunEvent::Down) => {
                    log::info!("Tun down");
                    cfg.down();
                }
            }
        });
    }

    // start UAPI server
    thread::spawn(move || loop {
        // accept and handle UAPI config connections
        match uapi.connect() {
            Ok(mut stream) => {
                let cfg = cfg.clone();
                thread::spawn(move || {
                    uapi::handle(&mut stream, &cfg);
                });
            }
            Err(err) => {
                log::info!("UAPI connection error: {}", err);
                profiler_stop();
                exit(-1);
            }
        }
    });

    // block until all tun readers closed
    wg.wait();
    profiler_stop();
}
