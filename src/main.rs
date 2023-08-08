use process_memory::{Memory, DataMember, TryIntoProcessHandle, Pid, ProcessHandle, Architecture};

pub mod memory_utils;
use memory_utils::{get_pid};

fn main() {
    let baldurs_gate_process = "Arc";

    let baldur_pid: Pid = get_pid(baldurs_gate_process).unwrap();
    let handle = baldur_pid.try_into_process_handle().unwrap();

    println!("Inside here");
}
