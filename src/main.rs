use std::{
    collections::HashMap,
    env,
    os::unix::process::CommandExt,
    process::{exit, Command},
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    libc,
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};

#[cfg(target_arch = "x86_64")]
use syscalls::Sysno;

#[derive(Debug, Default, Clone)] // Added Default and Clone
struct SyscallStats {
    calls: u64,
    errors: u64,
    total_duration: Duration,
}

// --- Error Check Helper (x86_64 specific) ---
#[cfg(target_arch = "x86_64")]
fn is_error(return_value: u64) -> bool {
    // On x86_64 Linux, syscalls return -errno on error.
    // The range is typically -4095 to -1.
    let val = return_value as i64;
    val < 0 && val >= -4095
}

// --- Helper function for Syscall Stop Logic ---
#[cfg(target_arch = "x86_64")] // specific to x86_64
fn handle_syscall_stop(
    pid: Pid,
    summarize_mode: bool,
    syscall_stats: &mut HashMap<Sysno, SyscallStats>,
    syscall_entry_time: &mut Option<Instant>,
    current_syscall: &mut Option<Sysno>,
) {
    match ptrace::getregs(pid) {
        Ok(regs) => {
            // Determine if entering or exiting based on stored state
            let is_entering = syscall_entry_time.is_none();

            if is_entering {
                // --- Syscall Entry ---
                let syscall_no_i32 = regs.orig_rax as usize;
                if let Some(syscall) = Sysno::new(syscall_no_i32) {
                    *current_syscall = Some(syscall); // Store current syscall
                    *syscall_entry_time = Some(Instant::now()); // Record entry time

                    if summarize_mode {
                        // Update call count
                        syscall_stats.entry(syscall).or_default().calls += 1;
                    } else {
                        // Print standard entry trace
                        let name = syscall.name();
                        eprintln!(
                            "[PID {}] > {} ({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                            pid, name, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9
                        );
                    }
                } else {
                    // Unknown syscall number
                    *current_syscall = None;
                    *syscall_entry_time = None; // Reset state
                    if !summarize_mode {
                        eprintln!(
                            "[PID {}] > UNKNOWN({}) ({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                            pid,
                            syscall_no_i32,
                            regs.rdi,
                            regs.rsi,
                            regs.rdx,
                            regs.r10,
                            regs.r8,
                            regs.r9
                        );
                    }
                    // Decide if you want to count unknown syscalls in summary - skipping for now
                }
            } else {
                // --- Syscall Exit ---
                let exit_time = Instant::now();
                let return_value = regs.rax;

                if let (Some(entry_time), Some(syscall)) =
                    (syscall_entry_time.take(), current_syscall.take())
                {
                    let duration = exit_time.duration_since(entry_time);
                    let is_err = is_error(return_value);

                    if summarize_mode {
                        // Update duration and errors
                        let stats = syscall_stats.entry(syscall).or_default();
                        stats.total_duration += duration;
                        if is_err {
                            stats.errors += 1;
                        }
                    } else {
                        // Print standard exit trace
                        eprintln!(
                            "[PID {}] < returning {:#x} ({}) {}",
                            pid,
                            return_value,
                            return_value as i64,
                            if is_err { "ERROR" } else { "" }
                        );
                    }
                } else {
                    // Exit without matching entry - state mismatch?
                    if !summarize_mode {
                        eprintln!(
                            "[PID {}] < SYSCALL EXIT (no matching entry?) returning {:#x}",
                            pid, return_value
                        );
                    }
                    // Reset state anyway
                    *syscall_entry_time = None;
                    *current_syscall = None;
                }
            } // end if is_entering / else
        } // end Ok(regs)
        Err(e) => {
            if let Errno::ESRCH = e {
                // Can't print here easily without access to summarize_mode,
                // The caller loop should handle the break.
                // We just need to ensure state is reset maybe? Or let the loop break.
                eprintln!(
                    "!!! Child process {} exited during getregs (reported in handle_syscall_stop).",
                    pid
                );
                // Reset state just in case loop doesn't break immediately. Should be handled by caller break.
                *syscall_entry_time = None;
                *current_syscall = None;
            } else {
                eprintln!(
                    "!!! ptrace::getregs failed inside handle_syscall_stop: {}",
                    e
                );
                // Reset state if getregs fails mid-syscall?
                *syscall_entry_time = None;
                *current_syscall = None;
            }
        }
    } // end match getregs
}

// Define a dummy handler for non-x86_64 to satisfy the compiler
#[cfg(not(target_arch = "x86_64"))]
fn handle_syscall_stop(
    pid: Pid,
    summarize_mode: bool,
    _syscall_stats: &mut HashMap<Sysno, SyscallStats>,
    syscall_entry_time: &mut Option<Instant>,
    current_syscall: &mut Option<Sysno>,
) {
    // Clear state if on unsupported arch to avoid infinite loop
    *syscall_entry_time = None;
    *current_syscall = None;
    if !summarize_mode {
        eprintln!("[PID {}] Syscall stop on unsupported architecture", pid);
    }
}

// --- Helper function to print the summary ---
fn print_summary(stats: &HashMap<Sysno, SyscallStats>, total_duration_hint: Duration) {
    if stats.is_empty() {
        println!("No system calls were traced.");
        return;
    }

    let mut sorted_stats: Vec<(Sysno, SyscallStats)> = stats
        .iter()
        .map(|(sysno, stat)| (*sysno, stat.clone())) // Cloning data for sorting
        .collect();

    // Sorting by total duration descending
    sorted_stats.sort_by(|a, b| b.1.total_duration.cmp(&a.1.total_duration));

    // Calculating total time spent *in* syscalls (sum of durations)
    let total_syscall_time: Duration = sorted_stats.iter().map(|(_, s)| s.total_duration).sum();
    let total_calls: u64 = sorted_stats.iter().map(|(_, s)| s.calls).sum();
    let total_errors: u64 = sorted_stats.iter().map(|(_, s)| s.errors).sum();

    println!(
        "{:>6} {:>11} {:>11} {:>9} {:>9} {}", // Adjusted spacing
        "% time", "seconds", "usecs/call", "calls", "errors", "syscall"
    );
    println!("------ ----------- ----------- --------- --------- ----------------");

    for (sysno, stat) in &sorted_stats {
        let time_percent = if !total_syscall_time.is_zero() {
            (stat.total_duration.as_secs_f64() / total_syscall_time.as_secs_f64()) * 100.0
        } else {
            0.0
        };

        let usecs_per_call = if stat.calls > 0 {
            stat.total_duration.as_micros() as f64 / stat.calls as f64 // Using f64 for division
        } else {
            0.0
        };

        // Handle potential errors column display
        let error_str = if stat.errors > 0 {
            format!("{}", stat.errors)
        } else {
            "".to_string() // Empty string if no errors
        };

        let name = sysno.name();

        println!(
            "{:>6.2} {:>11.6} {:>11.0} {:>9} {:>9} {}", // Adjusted spacing and precision
            time_percent,
            stat.total_duration.as_secs_f64(),
            usecs_per_call,
            stat.calls,
            error_str,
            name
        );
    }

    println!("------ ----------- ----------- --------- --------- ----------------");
    println!(
        "{:>6} {:>11.6} {:>11} {:>9} {:>9} total", // Adjusted spacing
        "100.00",
        total_syscall_time.as_secs_f64(),
        "", // No average usecs/call for total
        total_calls,
        total_errors
    );
    println!(
        "Total program execution time: {:.6} seconds",
        total_duration_hint.as_secs_f64()
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // --- Argument Parsing ---
    let mut summarize_mode = false;
    let mut executable_index = 1; // Index of the executable in args

    if args.len() >= 2 && args[1] == "-c" {
        summarize_mode = true;
        executable_index = 2; // Executable is now the 3rd arg (index 2)
        println!("---> Summary mode enabled (-c)");
    }

    if args.len() < executable_index + 1 {
        eprintln!("Usage: {} [-c] <executable> [args...]", args[0]);
        exit(1);
    }

    let target_executable = &args[executable_index];
    let target_args = &args[executable_index + 1..];

    if !summarize_mode {
        eprintln!(
            "---> Running command: {} {:?}",
            target_executable, target_args
        );
    }

    let mut cmd = Command::new(target_executable);
    cmd.args(target_args);

    let process_start_time = Instant::now(); // For overall timing

    // The code is wrapped in an unsafe block because ptrace is a low-level system call that can violate Rust's safety guarantees if misused.
    unsafe {
        // This runs after fork() but before exec() in Unix terms.
        cmd.pre_exec(|| {
            ptrace::traceme().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        });
    }

    // Spawn the child process
    // `spawn()` starts the child but doesn't wait for it yet.
    // It returns a Result<Child, io::Error>.
    let mut child = cmd.spawn().expect("Failed to spawn child.");
    let child_pid = Pid::from_raw(child.id() as i32);

    if !summarize_mode {
        eprintln!("---> Spawned child with PID: {}", child_pid);
    }

    match waitpid(Some(child_pid), None) {
        // None options = wait for any state change
        Ok(WaitStatus::Stopped(pid, Signal::SIGTRAP)) => {
            // This is the expected stop after PTRACE_TRACEME + execve
            if !summarize_mode {
                eprintln!(
                    "---> Child {} stopped for initial trace setup. Setting options...",
                    pid
                );
            }
            // PTRACE_O_TRACESYSGOOD makes syscalls traps deliver (SIGTRAP | 0x80)
            ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;
            if !summarize_mode {
                eprintln!("---> Options set. Continuing child...");
            }
        }
        Ok(status) => {
            eprintln!(
                "!!! Initial waitpid failed: Expected SIGTRAP, got {:?}",
                status
            );
            let _ = child.kill();
            exit(1);
        }
        Err(e) => {
            eprintln!("!!! Initial waitpid failed. {}", e);
            let _ = child.kill();
            exit(1);
        }
    }

    // --- Data structures for Summary Mode ---
    let mut syscall_stats: HashMap<Sysno, SyscallStats> = HashMap::new();
    let mut syscall_entry_time: Option<Instant> = None; // Track entry time for current syscall
    let mut current_syscall: Option<Sysno> = None; // Track Sysno between entry and exit

    // Main tracing loop

    loop {
        // Tell the kernel to continue the child but stop at the next syscall entry or exit
        if let Err(e) = ptrace::syscall(child_pid, None) {
            eprintln!("!!! ptrace::syscall failed: {}", e);
            // Check if the process still exists
            if let Errno::ESRCH = e {
                if !summarize_mode {
                    eprintln!("---> Child process {} exited before syscall.", child_pid);
                }
                break; // Process exited, break loop cleanly
            } else {
                eprintln!("!!! ptrace::syscall failed: {}", e);
                // Attempt recovery might be complex, maybe just break
                eprintln!("!!! Error during ptrace::syscall, stopping trace loop.");
                let _ = child.kill(); // Best effort cleanup
                break; // Exit loop on ptrace error
            }
        }

        // Wait for the child to stop again
        let wait_status = match waitpid(child_pid, None) {
            Ok(status) => status,
            Err(e) => {
                if let Errno::ESRCH = e {
                    if !summarize_mode {
                        eprintln!("---> Child process {} exited before waitpid.", child_pid);
                    }
                } else {
                    eprintln!("!!! waitpid failed during loop: {}", e);
                    eprintln!("!!! Unrecoverable error during waitpid, stopping trace loop.");
                    let _ = child.kill(); // Best effort cleanup
                }
                break; // Exit loop on waitpid error or ESRCH
            }
        };

        match wait_status {
            // Did the child exit?
            WaitStatus::Exited(pid, status) => {
                if !summarize_mode {
                    eprintln!("---> Child {} exited normally with status {}", pid, status);
                }
                break;
            }
            // Was the child terminated by a signal?
            WaitStatus::Signaled(pid, signal, core_dumped) => {
                if !summarize_mode {
                    eprintln!(
                        "---> Child {} terminated by signal {} (core_dumped={})",
                        pid, signal, core_dumped
                    );
                }
                break;
            }

            WaitStatus::Stopped(pid, signal) => {
                // Check if it's the specific signal generated by PTRACE_O_TRACESYSGOOD
                let is_syscall_trap_signal = signal as i32 == (libc::SIGTRAP | 0x80);

                if is_syscall_trap_signal {
                    // It's a syscall stop identified by the signal
                    handle_syscall_stop(
                        pid,
                        summarize_mode,
                        &mut syscall_stats,
                        &mut syscall_entry_time,
                        &mut current_syscall,
                    );
                    // Check if getregs failed and indicated process exit (hacky check)
                    if let Err(Errno::ESRCH) = ptrace::getregs(pid) {
                        if !summarize_mode {
                            eprintln!("---> Child process exited during getregs (detected after handle_syscall_stop). Breaking loop.");
                        }
                        break;
                    }
                } else {
                    // Stopped by a different signal
                    if !summarize_mode {
                        eprintln!("[PID {}] Stopped by signal: {}", pid, signal);
                    }
                    // Reset any pending syscall state if interrupted by another signal
                    syscall_entry_time = None;
                    current_syscall = None;
                }
            }

            WaitStatus::PtraceSyscall(pid) => {
                // This status inherently means it's a syscall stop
                handle_syscall_stop(
                    pid,
                    summarize_mode,
                    &mut syscall_stats,
                    &mut syscall_entry_time,
                    &mut current_syscall,
                );
                // Check if getregs failed and indicated process exit (hacky check)
                if let Err(Errno::ESRCH) = ptrace::getregs(pid) {
                    if !summarize_mode {
                        eprintln!("---> Child process exited during getregs (detected after handle_syscall_stop). Breaking loop.");
                    }
                    break;
                }
            }

            other_status => {
                if !summarize_mode {
                    eprintln!(
                        "[PID {}] Unexpected wait status encountered: {:?}",
                        child_pid, other_status
                    );
                }
                // Maybe break here? Continuing might be unsafe depending on the status.
                // Resetting state just in case.
                syscall_entry_time = None;
                current_syscall = None;
            }
        }
    }

    let process_end_time = Instant::now();
    let total_program_duration = process_end_time.duration_since(process_start_time);

    if !summarize_mode {
        eprintln!("---> Tracing finished.");
    } else {
        // --- Print Summary Table ---
        print_summary(&syscall_stats, total_program_duration);
    }

    // Ensure the child process is reaped
    let _ = child.kill(); // Send SIGKILL, ignore error if already exited

    Ok(())
}
