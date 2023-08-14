extern crate sysinfo;
use process_memory::{Pid, TryIntoProcessHandle, ProcessHandle, CopyAddress, DataMember, Memory, PutAddress};
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, thread::current};
use std::thread;

use sysinfo::{ProcessExt, System, SystemExt, AsU32};

#[cfg(windows)]
extern crate winapi;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};

#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
extern crate mach;
#[cfg(target_os = "macos")]
use mach::kern_return::KERN_SUCCESS;
use mach::port::{mach_port_name_t, MACH_PORT_NULL};
use mach::traps::mach_task_self;
use mach::vm_region::{vm_region_basic_info_data_t, vm_region_info_t, VM_REGION_BASIC_INFO_64};
use mach::message::mach_msg_type_number_t;


pub struct ProcessConfig {
    pub base_address: usize,
    pub pid: Pid
}

fn get_base_address(process_id: u32) -> Option<usize> {
    #[cfg(windows)]
    {
        use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameA};
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
        use winapi::um::winnt::PROCESS_VM_READ;
        use std::ptr::null_mut;

        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id)
        };

        if handle.is_null() {
            return None;
        }

        let mut h_mod = null_mut();
        let mut cb_needed = 0;
        unsafe {
            if EnumProcessModules(handle, &mut h_mod, std::mem::size_of_val(&h_mod) as u32, &mut cb_needed) == 0 {
                return None;
            }
        }

        // h_mod now contains the base address of the first module, which is typically the executable itself.
        Some(h_mod as usize)
    }

    #[cfg(target_os = "linux")]
    {
        let file = File::open(format!("/proc/{}/maps", process_id)).ok()?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line.ok()?;
            if line.ends_with("r-xp") {
                let address_range = line.split('-').next().unwrap();
                return Some(usize::from_str_radix(address_range, 16).unwrap());
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        match get_base_address_mac(process_id as i32) {
            Some(base_address) => Some(base_address),
            None => None
        }
    }
}

#[cfg(target_os = "macos")]
pub fn get_base_address_mac(pid: i32) -> Option<usize> {

    use libc::mach_port_t;
    let mut task: mach_port_name_t = MACH_PORT_NULL;
    let kr = unsafe { mach::traps::task_for_pid(mach_task_self(), pid, &mut task) };

    if kr != KERN_SUCCESS {
        println!("Failed to get task for PID");
        return None;
    }

    let mut address: mach::vm_types::mach_vm_address_t = 1; // Starting from 1 to skip the null page
    let mut size: mach::vm_types::mach_vm_size_t = 0;
    let mut object_name: mach_port_t = MACH_PORT_NULL;
    let mut count: mach_msg_type_number_t = VM_REGION_BASIC_INFO_64 as u32;
    let mut info: vm_region_basic_info_data_t = Default::default();
    let mut region_count = 0;
    let mut first_region_begin: mach::vm_types::vm_address_t = 0;
    let mut flag = 0;

    while flag == 0 {
        let kret = unsafe {
            mach::vm::mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info as *mut _ as vm_region_info_t,
                &mut count,
                &mut object_name,
            )
        };
        if kret == KERN_SUCCESS {
            if region_count == 0 {
                first_region_begin = address as usize;
                region_count += 1;
            }
            address += size;
        } else {
            flag = 1;
        }
    }
    
    println!("Found base address: {:X}", first_region_begin);
    Some(first_region_begin)
}

// the target godmode sequence of bytes.
// we want to search the baldur's gate 3 process for this array of bytes.
pub fn get_godmode_target_sequence() -> Vec<Option<u8>> {
    let pattern = vec![
        Some(0x48), Some(0x8B), Some(0x05), None, None, None, None,
        Some(0x80), Some(0xB8), None, None, None, None, Some(0x00),
        Some(0x74), None, Some(0xBA), Some(0x01), Some(0x00), Some(0x00),
        Some(0x00),
    ];

    pattern
}

pub fn get_process_config(process_name: &str) -> Option<ProcessConfig> {
    let mut system = System::new();
    system.refresh_processes();

    for (pid, process) in system.processes() {
        let cmds = process.cmd();
        for cmd in cmds {
            if cmd.contains(process_name) {
                println!("Found process: {} with pid: {}", process_name, pid);

                let pid_num = pid.as_u32();
                let base_address = get_base_address(pid_num).unwrap();

                let casted_process_pid = pid.as_u32() as Pid;

                return Some(
                    ProcessConfig {
                        base_address,
                        pid: casted_process_pid
                    }
                );    
            }
        }
    }

    None
}

// pub fn array_of_bytes_scan(process_handle: &ProcessHandle, target_sequence: &[Option<u8>]) -> Result<Option<usize>> {
//     // Determine the chunk size for scanning (e.g., 1024 bytes)
//     let chunk_size = 1024;
//     let mut buffer = vec![0; chunk_size];

//     // Iterate through the memory range
//     for address in (start_address..end_address).step_by(chunk_size) {
//         // Read a chunk of memory into the buffer
//         process_handle.copy_address(address, &mut buffer)?;

//         // Iterate through the buffer and compare to the target sequence
//         for i in 0..(chunk_size - target_sequence.len()) {
//             if target_sequence.iter().enumerate().all(|(j, &target_byte)| {
//                 target_byte.map_or(true, |target_byte| target_byte == buffer[i + j])
//             }) {
//                 // Found the sequence, return the address
//                 return Ok(Some(address + i));
//             }
//         }
//     }

//     // Sequence not found, return None
//     Ok(None)
// }

pub fn inject_bytes_at_address(base_address: usize, process: Pid) {
    let process_handle = process.try_into_process_handle().unwrap();
    let base_address: usize = 0x1A97B9B94A0;
    
    let maximum_health_address = base_address + 0x50;
    let mut max_health_buffer = [0u8; 4]; // Assuming maximum health is stored as 4 bytes

    process_handle.copy_address(maximum_health_address, &mut max_health_buffer).unwrap();

    let current_health_address = base_address + 0x48;
    
    process_handle.put_address(current_health_address, &max_health_buffer);
}

// pub fn enable_godmode(base_address: usize, target_sequence: Vec<Option<u8>>, process: Pid) -> Result<(), std::io::Error> {
//     // Define the chunk size for reading memory
//     let chunk_size = 10 * 1024 * 1024; // 10 MB
//     let overlap = target_sequence.len() - 1;

//     // 64 bit process search range
//     let search_range_start = 0x0000_0000_0000_1000;
//     let search_range_end = 0x0000_7FFF_FFFF_FFFF;

//     // Number of threads
//     let num_threads = 8;
//     let segment_size = 12_100_000_000 / 8;

//     println!("{} segment size", segment_size);

//     // Shared flag to indicate if the pattern has been found
//     let found_flag = Arc::new(AtomicBool::new(false));

//     // Channel to send the result back to the main thread
//     let (sender, receiver) = std::sync::mpsc::channel();

//     // Spawn threads
//     let mut handles = vec![];
//     for t in 0..num_threads {
//         let process_handle = process.try_into_process_handle().unwrap();

//         let start = search_range_start + segment_size * t;
//         let end = if t == num_threads - 1 { search_range_end } else { start + segment_size - 1 };
//         let target_sequence = target_sequence.clone();
//         let found_flag = Arc::clone(&found_flag);
//         let sender = sender.clone();

//         let handle = thread::spawn(move || {
//             for addr in (start..=end).step_by(chunk_size) {
//                 // Check if the pattern has already been found in another thread
//                 if found_flag.load(Ordering::SeqCst) {
//                     break;
//                 }

//                 // Determine the read size and start address, considering the overlap
//                 let read_start = if addr == start { addr } else { addr - overlap };

//                 let mut buffer = vec![0; chunk_size + overlap]; 
//                 if process_handle.copy_address(read_start, &mut buffer).is_ok() {
//                     let buffer_start = if addr == start { 0 } else { overlap };
//                     let buffer_end = buffer.len();
                    
//                     for i in buffer_start..(buffer_end - target_sequence.len()) {
//                         if target_sequence.iter().enumerate().all(|(j, &byte)| {
//                             byte.map_or(true, |b| b == buffer[i + j])
//                         }) {
//                             let injection_offset = 0x18; // Injection offset
//                             let injection_address = base_address + addr + i + injection_offset;

//                             // Send result to main thread
//                             sender.send(injection_address).unwrap();
//                             found_flag.store(true, Ordering::SeqCst);
//                             return;
//                         } else {
//                             // println!("No match at address: {:X}", base_address + addr + i);
//                         }
//                     }
//                 }
//             }
//         });

//         handles.push(handle);
//     }

//     // Wait for threads to finish and receive the result
//     for handle in handles {
//         handle.join().unwrap();
//     }

//     if let Ok(injection_address) = receiver.try_recv() {
//         // Create a DataMember to write the value
//         let process_handle = process.try_into_process_handle().unwrap();
//         let data_member = DataMember::<u32>::new_offset(process_handle, vec![injection_address as usize]);
//         let value_to_write: u32 = 1; // Adjust this value

//         println!("Found godmode target sequence at address: {:X}", injection_address);
//         println!("Writing value: {} to address: {:X}", value_to_write, injection_address);
//         data_member.write(&value_to_write)?;

//         Ok(())
//     } else {
//         Err(std::io::Error::new(std::io::ErrorKind::Other, "Pattern not found"))
//     }
// }

