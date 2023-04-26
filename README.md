# rust-proc-injection
Injecting shellcode into a running process using PTRACE. Two implementations using pure libc bindings and using nix crate.

# Usage
1. `cargo build --release --bin [libc/nix]`
2. `python3 victim.py`
3. `sudo ./target/release/[libc/nix] [Victim-PID]`

![rust-proc-injection](https://user-images.githubusercontent.com/45213563/234577780-103bdc46-e450-4161-b8b2-edc7f569a943.png)

# License
MIT License
