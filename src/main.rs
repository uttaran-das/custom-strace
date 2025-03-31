use std::{
    env, io,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{exit, Command},
};

use nix::{
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <executable> [args]", args[0]);
        exit(1);
    }

    let target_executable = &args[1];
    let target_args = &args[2..];

    // {:?} is a placeholder for displaying a value using its Debug trait (developer-friendly, shows structure).
    println!(
        "---> Running command: {} {:?}",
        target_executable, target_args
    );

    let mut cmd = Command::new(target_executable);
    cmd.args(target_args);

    // The code is wrapped in an unsafe block because ptrace is a low-level system call that can violate Rust's safety guarantees if misused.
    unsafe {
        // This runs after fork() but before exec() in Unix terms.
        cmd.pre_exec(|| {
            println!("[Child] Executing PTRACE_TRACME...");
            // Note that pre_exec requires an unsafe block because it runs in a context where many standard library functions (like memory allocation) are unsafe to call. However, ptrace::traceme itself is generally safe here.
            match ptrace::traceme() {
                Ok(()) => {
                    println!("[Child] PTRACE_TRACEME successful");
                    Ok(())
                }
                Err(e) => {
                    eprintln!("[Child] PTRACE_TRACEME failed: {}", e);
                    Err(io::Error::new(io::ErrorKind::Other, e))
                }
            }
        });
    }

    // Spawn the child process
    // `spawn()` starts the child but doesn't wait for it yet.
    // It returns a Result<Child, io::Error>.
    let child_result = cmd.spawn();

    match child_result {
        Ok(mut child) => {
            let child_pid = Pid::from_raw(child.id() as i32);
            println!("---> Spawned child process with PID: {}", child_pid);

            // Wait for the child to stop due to PTRACE_TRACEME
            println!("[Parent] Waiting for child {} to signal...", child_pid);
            match waitpid(Some(child_pid), None) {
                // None options = wait for any state change
                Ok(WaitStatus::Stopped(pid, Signal::SIGTRAP)) => {
                    // This is the expected stop after PTRACE_TRACEME + execve
                    println!(
                        "[Parent] Received initial SIGTRAP from child {}. Attaching successful",
                        pid
                    );
                }
                Ok(WaitStatus::Exited(pid, status)) => {
                    eprintln!(
                        "[Parent] Child {} exited ({}) unexpectedly during PTRACE_TRACEME setup.",
                        pid, status
                    );
                    exit(1);
                }
                Ok(WaitStatus::Signaled(pid, signal, _)) => {
                    eprintln!("[Parent] Child {} terminated by signal ({}) unexpectedly during PTRACE_TRACEME setup.", pid, signal);
                    exit(1);
                }
                Ok(other_status) => {
                    eprintln!(
                        "[Parent] Unexpected wait status from child {}: {:?}",
                        child_pid, other_status
                    );
                    let _ = child.kill();
                    exit(1);
                }
                Err(e) => {
                    eprintln!("[Parent] error waiting for child {}: {}", child_pid, e);
                    let _ = child.kill();
                    exit(1);
                }
            }

            // Tell the child to continue (it's currently stopped)
            println!("[Parent] Resuming child process {}...", child_pid);
            if let Err(e) = ptrace::cont(child_pid, None) {
                // None signal = don't inject a signal
                eprintln!("[Parent] Failed to continue child {}: {}", child_pid, e);
                let _ = child.kill();
                exit(1);
            }

            // Wait for the child process to actually finish execution
            // `wait()` blocks the current (parent) process until the child finishes.
            // It returns a Result<ExitStatus, io::Error>.
            println!("[Parent] Waiting for child {} to terminate...", child_pid);
            match child.wait() {
                Ok(exit_status) => {
                    println!("---> Child process finished.");
                    if exit_status.success() {
                        println!("---> Child exit status: Success ({})", exit_status);
                        exit(exit_status.code().unwrap_or(0));
                    } else {
                        // Check if it exited due to a signal (Unix-specific)
                        if let Some(signal) = exit_status.signal() {
                            eprintln!(
                                "---> Child exit status: Terminated by signal {} ({})",
                                signal, exit_status
                            );
                            /*
                            Why 128 + signal?
                                In Unix, exit codes are 8-bit values (0-255).

                                By convention, 128 + signal_number is used to indicate that a process died due to a signal. This helps distinguish between normal exits (0-127) and signal-induced exits (129-255).
                             */
                            exit(128 + signal);
                        } else {
                            eprintln!("---> Child exit status: Failure ({})", exit_status);
                            exit(exit_status.code().unwrap_or(1));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error waiting for child process {}: {}", child.id(), e);
                    exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Error spawning executable '{}': {}", target_executable, e);
            exit(1);
        }
    }
}
