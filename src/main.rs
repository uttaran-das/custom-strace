use std::{
    env,
    os::unix::process::ExitStatusExt,
    process::{exit, Command},
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

    // Spawn the child process
    // `spawn()` starts the child but doesn't wait for it yet.
    // It returns a Result<Child, io::Error>.
    let child_result = cmd.spawn();

    match child_result {
        Ok(mut child) => {
            println!("---> Spawned child process with PID: {}", child.id());

            // Wait for the child process to exit
            // `wait()` blocks the current (parent) process until the child finishes.
            // It returns a Result<ExitStatus, io::Error>.
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
