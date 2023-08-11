extern crate sysinfo;
use process_memory::{Pid, TryIntoProcessHandle, ProcessHandle};

use sysinfo::{ProcessExt, System, SystemExt, AsU32};

pub fn get_pid(process_name: &str) -> Option<Pid> {
    let mut system = System::new();
    system.refresh_processes();

    for (pid, process) in system.processes() {
        let cmds = process.cmd();
        for cmd in cmds {
            if cmd.contains(process_name) {
                println!("Found process: {} with pid: {}", process_name, pid);

                let casted_process_pid = pid.as_u32() as Pid;
                return Some(casted_process_pid);    
            }
        }
    }

    None
}

pub fn array_of_bytes_scan(process_handle: &ProcessHandle, target_sequence: &[Option<u8>], start_address: usize, end_address: usize) -> Result<Option<usize>> {
    // Determine the chunk size for scanning (e.g., 1024 bytes)
    let chunk_size = 1024;
    let mut buffer = vec![0; chunk_size];

    // Iterate through the memory range
    for address in (start_address..end_address).step_by(chunk_size) {
        // Read a chunk of memory into the buffer
        process_handle.copy_address(address, &mut buffer)?;

        // Iterate through the buffer and compare to the target sequence
        for i in 0..(chunk_size - target_sequence.len()) {
            if target_sequence.iter().enumerate().all(|(j, &target_byte)| {
                target_byte.map_or(true, |target_byte| target_byte == buffer[i + j])
            }) {
                // Found the sequence, return the address
                return Ok(Some(address + i));
            }
        }
    }

    // Sequence not found, return None
    Ok(None)
}