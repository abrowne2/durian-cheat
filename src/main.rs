use process_memory::{Memory, DataMember, TryIntoProcessHandle, Pid, ProcessHandle, Architecture};

pub mod memory_utils;
use memory_utils::{get_pid};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let baldurs_gate_process = "bg3_dx11.exe";

    let baldur_pid: Pid = get_pid(baldurs_gate_process).unwrap();
    let handle = baldur_pid.try_into_process_handle().unwrap();

    // let target_godmode_sequence 

    println!("Inside here");

    Ok(())
}
