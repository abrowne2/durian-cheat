use process_memory::{Memory, DataMember, TryIntoProcessHandle, Pid, ProcessHandle, Architecture};

pub mod memory_utils;
use memory_utils::{get_process_config};

use crate::memory_utils::ProcessConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let baldurs_gate_process = "bg3_dx11.exe";

    let process_config: ProcessConfig = get_process_config(baldurs_gate_process).unwrap();
    let handle = process_config.pid.try_into_process_handle().unwrap();

    // sequence of bytes we need to look for to get godmode.
    let godmode_target_sequence = memory_utils::get_godmode_target_sequence();
    memory_utils::inject_bytes_at_address(process_config.base_address, process_config.pid);

    Ok(())
}
