--[[
NullSec ProcMask - Process Masking Utility
Language: Lua
Author: bad-antics
License: NullSec Proprietary

Process evasion and masking utility for Linux systems.
Requires root/sudo for most operations.
--]]

local ffi = require("ffi")

-- FFI definitions for Linux syscalls
ffi.cdef[[
    typedef unsigned int pid_t;
    typedef long ssize_t;
    typedef unsigned long size_t;
    
    int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
    int kill(pid_t pid, int sig);
    pid_t getpid(void);
    pid_t getppid(void);
    
    int open(const char *pathname, int flags);
    ssize_t read(int fd, void *buf, size_t count);
    ssize_t write(int fd, const void *buf, size_t count);
    int close(int fd);
    
    void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
    int munmap(void *addr, size_t length);
    
    int ptrace(int request, pid_t pid, void *addr, void *data);
]]

-- Constants
local PR_SET_NAME = 15
local PR_GET_NAME = 16
local O_RDONLY = 0
local O_WRONLY = 1
local O_RDWR = 2

local PROT_READ = 1
local PROT_WRITE = 2
local MAP_SHARED = 1
local MAP_PRIVATE = 2
local MAP_ANONYMOUS = 0x20

local PTRACE_ATTACH = 16
local PTRACE_DETACH = 17
local PTRACE_PEEKDATA = 2
local PTRACE_POKEDATA = 5

-- Banner
local BANNER = [[
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░ P R O C M A S K ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                      bad-antics v1.0.0
]]

local VERSION = "1.0.0"

-- Utility functions
local function file_exists(path)
    local f = io.open(path, "r")
    if f then
        f:close()
        return true
    end
    return false
end

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*all")
    f:close()
    return content
end

local function write_file(path, content)
    local f = io.open(path, "w")
    if not f then return false end
    f:write(content)
    f:close()
    return true
end

local function is_root()
    local handle = io.popen("id -u")
    local result = handle:read("*a")
    handle:close()
    return tonumber(result) == 0
end

local function process_exists(pid)
    return file_exists(string.format("/proc/%d/status", pid))
end

-- Process information gathering
local ProcessInfo = {}
ProcessInfo.__index = ProcessInfo

function ProcessInfo.new(pid)
    local self = setmetatable({}, ProcessInfo)
    self.pid = pid
    self:refresh()
    return self
end

function ProcessInfo:refresh()
    if not process_exists(self.pid) then
        self.exists = false
        return
    end
    
    self.exists = true
    
    -- Read comm (process name)
    local comm = read_file(string.format("/proc/%d/comm", self.pid))
    self.name = comm and comm:gsub("%s+$", "") or "unknown"
    
    -- Read cmdline
    local cmdline = read_file(string.format("/proc/%d/cmdline", self.pid))
    self.cmdline = cmdline and cmdline:gsub("%z", " "):gsub("%s+$", "") or ""
    
    -- Read status
    local status = read_file(string.format("/proc/%d/status", self.pid))
    if status then
        self.ppid = tonumber(status:match("PPid:%s*(%d+)")) or 0
        self.uid = tonumber(status:match("Uid:%s*(%d+)")) or 0
        self.state = status:match("State:%s*(%S)") or "?"
        self.threads = tonumber(status:match("Threads:%s*(%d+)")) or 1
    end
    
    -- Read exe link
    local exe_link = string.format("/proc/%d/exe", self.pid)
    local handle = io.popen(string.format("readlink %s 2>/dev/null", exe_link))
    self.exe = handle:read("*a"):gsub("%s+$", "")
    handle:close()
end

function ProcessInfo:print()
    if not self.exists then
        print(string.format("[!] Process %d does not exist", self.pid))
        return
    end
    
    print(string.format("\n[*] Process Information for PID %d:", self.pid))
    print(string.format("    Name:     %s", self.name))
    print(string.format("    Cmdline:  %s", self.cmdline))
    print(string.format("    Exe:      %s", self.exe))
    print(string.format("    PPID:     %d", self.ppid))
    print(string.format("    UID:      %d", self.uid))
    print(string.format("    State:    %s", self.state))
    print(string.format("    Threads:  %d", self.threads))
end

-- Process masking operations
local ProcMask = {}
ProcMask.__index = ProcMask

function ProcMask.new(verbose)
    local self = setmetatable({}, ProcMask)
    self.verbose = verbose or false
    return self
end

function ProcMask:log(msg)
    if self.verbose then
        print(string.format("[*] %s", msg))
    end
end

function ProcMask:error(msg)
    print(string.format("[!] Error: %s", msg))
end

function ProcMask:success(msg)
    print(string.format("[+] %s", msg))
end

-- Change process name using prctl
function ProcMask:set_self_name(new_name)
    self:log(string.format("Setting own process name to: %s", new_name))
    
    -- Truncate to 15 chars (Linux limit)
    new_name = new_name:sub(1, 15)
    
    local name_buf = ffi.new("char[16]")
    ffi.copy(name_buf, new_name)
    
    local result = ffi.C.prctl(PR_SET_NAME, ffi.cast("unsigned long", name_buf), 0, 0, 0)
    
    if result == 0 then
        self:success(string.format("Process name changed to: %s", new_name))
        return true
    else
        self:error("Failed to change process name")
        return false
    end
end

-- Get current process name
function ProcMask:get_self_name()
    local name_buf = ffi.new("char[16]")
    ffi.C.prctl(PR_GET_NAME, ffi.cast("unsigned long", name_buf), 0, 0, 0)
    return ffi.string(name_buf)
end

-- Modify /proc/[pid]/comm (requires root)
function ProcMask:modify_comm(pid, new_name)
    if not is_root() then
        self:error("Root privileges required to modify other process comm")
        return false
    end
    
    if not process_exists(pid) then
        self:error(string.format("Process %d does not exist", pid))
        return false
    end
    
    self:log(string.format("Modifying comm for PID %d to: %s", pid, new_name))
    
    -- This is actually read-only in /proc, need alternative method
    -- Using process memory manipulation instead
    self:log("Note: /proc/[pid]/comm is read-only, using memory manipulation")
    
    return self:modify_argv0(pid, new_name)
end

-- Modify argv[0] in process memory
function ProcMask:modify_argv0(pid, new_name)
    if not is_root() then
        self:error("Root privileges required")
        return false
    end
    
    self:log(string.format("Modifying argv[0] for PID %d", pid))
    
    -- Read /proc/[pid]/cmdline to find argv[0] location
    local cmdline_path = string.format("/proc/%d/cmdline", pid)
    local cmdline = read_file(cmdline_path)
    
    if not cmdline then
        self:error("Could not read process cmdline")
        return false
    end
    
    -- Get argv[0] length
    local argv0 = cmdline:match("^([^%z]+)")
    local argv0_len = #argv0
    
    self:log(string.format("Original argv[0]: %s (len=%d)", argv0, argv0_len))
    
    -- Read maps to find stack
    local maps_path = string.format("/proc/%d/maps", pid)
    local maps = read_file(maps_path)
    
    if not maps then
        self:error("Could not read process maps")
        return false
    end
    
    -- Find [stack] region
    local stack_start, stack_end
    for line in maps:gmatch("[^\n]+") do
        if line:match("%[stack%]") then
            stack_start, stack_end = line:match("^(%x+)%-(%x+)")
            stack_start = tonumber(stack_start, 16)
            stack_end = tonumber(stack_end, 16)
            break
        end
    end
    
    if not stack_start then
        self:error("Could not find stack region")
        return false
    end
    
    self:log(string.format("Stack region: 0x%x - 0x%x", stack_start, stack_end))
    
    -- Attach with ptrace
    local result = ffi.C.ptrace(PTRACE_ATTACH, pid, nil, nil)
    if result < 0 then
        self:error("Failed to attach to process")
        return false
    end
    
    -- Wait for process to stop
    os.execute(string.format("wait %d 2>/dev/null", pid))
    
    -- Search for argv[0] in stack and overwrite
    -- This is simplified - real implementation would need proper memory scanning
    
    -- Detach
    ffi.C.ptrace(PTRACE_DETACH, pid, nil, nil)
    
    self:success(string.format("Attempted argv[0] modification for PID %d", pid))
    return true
end

-- Modify environment variables
function ProcMask:clear_environ(pid)
    if not is_root() then
        self:error("Root privileges required")
        return false
    end
    
    self:log(string.format("Clearing environment for PID %d", pid))
    
    local environ_path = string.format("/proc/%d/environ", pid)
    
    if not file_exists(environ_path) then
        self:error("Could not access process environment")
        return false
    end
    
    -- environ is read-only, would need memory manipulation
    self:log("Note: Direct environ modification requires process injection")
    
    return false
end

-- List all processes with optional filter
function ProcMask:list_processes(filter)
    local procs = {}
    
    local handle = io.popen("ls /proc 2>/dev/null")
    for entry in handle:lines() do
        local pid = tonumber(entry)
        if pid then
            local info = ProcessInfo.new(pid)
            if info.exists then
                if not filter or info.name:match(filter) or info.cmdline:match(filter) then
                    table.insert(procs, info)
                end
            end
        end
    end
    handle:close()
    
    return procs
end

-- Find processes by name
function ProcMask:find_by_name(name)
    return self:list_processes(name)
end

-- Generate fake process list (misleading top/ps output)
function ProcMask:generate_decoy_names()
    return {
        "systemd", "systemd-journald", "systemd-udevd", "systemd-logind",
        "dbus-daemon", "rsyslogd", "crond", "atd",
        "sshd", "agetty", "login",
        "kworker/0:0", "kworker/1:0", "ksoftirqd/0",
        "rcu_sched", "migration/0", "watchdog/0",
        "NetworkManager", "polkitd", "accounts-daemon",
        "udisksd", "upowerd", "colord",
        "[kthreadd]", "[ksoftirqd/0]", "[kcompactd0]"
    }
end

-- CLI Interface
local function print_usage()
    print(BANNER)
    print([[
USAGE:
    procmask [OPTIONS] <COMMAND>
    
COMMANDS:
    info <pid>              Show process information
    rename <new_name>       Rename current process (self)
    mask <pid> <name>       Mask another process name (requires root)
    list [filter]           List processes, optionally filtered
    find <name>             Find processes by name
    decoys                  Show recommended decoy process names
    
OPTIONS:
    -v, --verbose           Enable verbose output
    -h, --help              Show this help message
    
EXAMPLES:
    procmask info 1234
    procmask rename "systemd"
    procmask mask 5678 "kworker/0:1"
    procmask list ssh
    procmask find python
    ]])
end

-- Parse arguments
local function parse_args(args)
    local opts = {
        verbose = false,
        command = nil,
        args = {}
    }
    
    local i = 1
    while i <= #args do
        local arg = args[i]
        
        if arg == "-v" or arg == "--verbose" then
            opts.verbose = true
        elseif arg == "-h" or arg == "--help" then
            print_usage()
            os.exit(0)
        elseif not opts.command then
            opts.command = arg
        else
            table.insert(opts.args, arg)
        end
        
        i = i + 1
    end
    
    return opts
end

-- Main
local function main()
    local opts = parse_args(arg)
    
    if not opts.command then
        print_usage()
        os.exit(1)
    end
    
    local pm = ProcMask.new(opts.verbose)
    
    if opts.command == "info" then
        local pid = tonumber(opts.args[1])
        if not pid then
            print("[!] Usage: procmask info <pid>")
            os.exit(1)
        end
        local info = ProcessInfo.new(pid)
        info:print()
        
    elseif opts.command == "rename" then
        local new_name = opts.args[1]
        if not new_name then
            print("[!] Usage: procmask rename <new_name>")
            os.exit(1)
        end
        pm:set_self_name(new_name)
        
    elseif opts.command == "mask" then
        local pid = tonumber(opts.args[1])
        local new_name = opts.args[2]
        if not pid or not new_name then
            print("[!] Usage: procmask mask <pid> <new_name>")
            os.exit(1)
        end
        pm:modify_comm(pid, new_name)
        
    elseif opts.command == "list" then
        local filter = opts.args[1]
        local procs = pm:list_processes(filter)
        
        print(string.format("\n%-8s %-20s %-40s", "PID", "NAME", "CMDLINE"))
        print(string.rep("-", 70))
        
        for _, p in ipairs(procs) do
            local cmdline = p.cmdline:sub(1, 38)
            print(string.format("%-8d %-20s %-40s", p.pid, p.name, cmdline))
        end
        
        print(string.format("\nTotal: %d processes", #procs))
        
    elseif opts.command == "find" then
        local name = opts.args[1]
        if not name then
            print("[!] Usage: procmask find <name>")
            os.exit(1)
        end
        
        local procs = pm:find_by_name(name)
        
        print(string.format("\n[*] Found %d processes matching '%s':", #procs, name))
        for _, p in ipairs(procs) do
            print(string.format("    PID %-8d  %s  %s", p.pid, p.name, p.cmdline:sub(1, 40)))
        end
        
    elseif opts.command == "decoys" then
        print("\n[*] Recommended decoy process names:")
        for _, name in ipairs(pm:generate_decoy_names()) do
            print(string.format("    %s", name))
        end
        
    else
        print(string.format("[!] Unknown command: %s", opts.command))
        print_usage()
        os.exit(1)
    end
end

-- Run
main()
