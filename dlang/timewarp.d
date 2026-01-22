/**
 * NullSec TimeWarp - Timestamp Manipulation Tool
 * Language: D
 * Author: bad-antics
 * License: NullSec Proprietary
 *
 * Anti-forensics tool for manipulating file timestamps.
 * Supports MACB (Modified, Accessed, Changed, Birth) timestamps.
 */

import std.stdio;
import std.file;
import std.datetime;
import std.getopt;
import std.algorithm;
import std.array;
import std.string;
import std.conv;
import std.random;
import std.path;
import core.sys.posix.sys.stat;
import core.sys.posix.utime;
import core.stdc.time;

enum VERSION = "1.0.0";

immutable string BANNER = `
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░ T I M E W A R P ░░░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                      bad-antics v` ~ VERSION ~ `
`;

/// File timestamp information
struct FileTimestamps {
    string path;
    SysTime accessTime;
    SysTime modifyTime;
    SysTime statusChangeTime;  // ctime - metadata change
    
    void print() {
        writefln("  File: %s", path);
        writefln("  Access Time (atime): %s", accessTime.toSimpleString());
        writefln("  Modify Time (mtime): %s", modifyTime.toSimpleString());
        writefln("  Status Change (ctime): %s", statusChangeTime.toSimpleString());
    }
}

/// Get file timestamps
FileTimestamps getTimestamps(string path) {
    if (!exists(path)) {
        throw new Exception("File not found: " ~ path);
    }
    
    stat_t statbuf;
    if (stat(path.toStringz(), &statbuf) != 0) {
        throw new Exception("Failed to stat file: " ~ path);
    }
    
    FileTimestamps ts;
    ts.path = path;
    ts.accessTime = SysTime(unixTimeToStdTime(statbuf.st_atime));
    ts.modifyTime = SysTime(unixTimeToStdTime(statbuf.st_mtime));
    ts.statusChangeTime = SysTime(unixTimeToStdTime(statbuf.st_ctime));
    
    return ts;
}

/// Set file timestamps (atime and mtime only - ctime cannot be directly set)
void setTimestamps(string path, SysTime accessTime, SysTime modifyTime) {
    if (!exists(path)) {
        throw new Exception("File not found: " ~ path);
    }
    
    utimbuf times;
    times.actime = cast(time_t)(accessTime.toUnixTime());
    times.modtime = cast(time_t)(modifyTime.toUnixTime());
    
    if (utime(path.toStringz(), &times) != 0) {
        throw new Exception("Failed to set timestamps for: " ~ path);
    }
}

/// Parse datetime string
SysTime parseDateTime(string dtStr) {
    // Supported formats:
    // "2024-01-15 14:30:00"
    // "2024-01-15T14:30:00"
    // "2024-01-15"
    
    dtStr = dtStr.replace("T", " ");
    
    try {
        if (dtStr.length == 10) {
            // Date only
            auto parts = dtStr.split("-");
            return SysTime(DateTime(
                parts[0].to!int,
                parts[1].to!int,
                parts[2].to!int,
                0, 0, 0
            ));
        } else {
            // Date and time
            auto dateParts = dtStr[0..10].split("-");
            auto timeParts = dtStr[11..$].split(":");
            return SysTime(DateTime(
                dateParts[0].to!int,
                dateParts[1].to!int,
                dateParts[2].to!int,
                timeParts[0].to!int,
                timeParts.length > 1 ? timeParts[1].to!int : 0,
                timeParts.length > 2 ? timeParts[2].to!int : 0
            ));
        }
    } catch (Exception e) {
        throw new Exception("Invalid datetime format: " ~ dtStr ~ 
            "\nUse: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS");
    }
}

/// Generate random timestamp within range
SysTime randomTimestamp(SysTime start, SysTime end) {
    auto startUnix = start.toUnixTime();
    auto endUnix = end.toUnixTime();
    
    if (endUnix <= startUnix) {
        return start;
    }
    
    auto randomUnix = uniform(startUnix, endUnix);
    return SysTime(unixTimeToStdTime(randomUnix));
}

/// Process files recursively
void processRecursive(string path, void delegate(string) processor) {
    if (isFile(path)) {
        processor(path);
    } else if (isDir(path)) {
        foreach (entry; dirEntries(path, SpanMode.breadth)) {
            processor(entry.name);
        }
    }
}

/// Clone timestamps from reference file
void cloneTimestamps(string source, string target, bool verbose) {
    auto srcTs = getTimestamps(source);
    
    if (verbose) {
        writefln("[*] Cloning timestamps from: %s", source);
        writefln("[*] Target: %s", target);
    }
    
    setTimestamps(target, srcTs.accessTime, srcTs.modifyTime);
    
    if (verbose) {
        writefln("[+] Timestamps cloned successfully");
    }
}

/// Match all files in directory to reference
void matchDirectory(string dir, string reference, bool verbose) {
    auto refTs = getTimestamps(reference);
    
    int count = 0;
    processRecursive(dir, (string path) {
        try {
            setTimestamps(path, refTs.accessTime, refTs.modifyTime);
            count++;
            if (verbose) {
                writefln("[+] %s", path);
            }
        } catch (Exception e) {
            if (verbose) {
                writefln("[!] Failed: %s - %s", path, e.msg);
            }
        }
    });
    
    writefln("[+] Modified %d files", count);
}

/// Randomize timestamps within range
void randomizeTimestamps(string path, SysTime start, SysTime end, bool recursive, bool verbose) {
    void process(string file) {
        try {
            auto newAtime = randomTimestamp(start, end);
            auto newMtime = randomTimestamp(start, end);
            
            // Ensure mtime <= atime (logical constraint)
            if (newMtime > newAtime) {
                auto temp = newAtime;
                newAtime = newMtime;
                newMtime = temp;
            }
            
            setTimestamps(file, newAtime, newMtime);
            
            if (verbose) {
                writefln("[+] %s", file);
                writefln("    atime: %s", newAtime.toSimpleString());
                writefln("    mtime: %s", newMtime.toSimpleString());
            }
        } catch (Exception e) {
            if (verbose) {
                writefln("[!] Failed: %s", file);
            }
        }
    }
    
    if (recursive && isDir(path)) {
        processRecursive(path, &process);
    } else {
        process(path);
    }
}

/// Age files by specified duration
void ageFiles(string path, Duration amount, bool recursive, bool verbose) {
    void process(string file) {
        try {
            auto ts = getTimestamps(file);
            auto newAtime = ts.accessTime - amount;
            auto newMtime = ts.modifyTime - amount;
            
            setTimestamps(file, newAtime, newMtime);
            
            if (verbose) {
                writefln("[+] Aged: %s by %s", file, amount);
            }
        } catch (Exception e) {
            if (verbose) {
                writefln("[!] Failed: %s", file);
            }
        }
    }
    
    if (recursive && isDir(path)) {
        processRecursive(path, &process);
    } else {
        process(path);
    }
}

/// Touch file to current time
void touchFile(string path, bool verbose) {
    auto now = Clock.currTime();
    setTimestamps(path, now, now);
    
    if (verbose) {
        writefln("[+] Touched: %s", path);
    }
}

void main(string[] args) {
    string command;
    string target;
    string reference;
    string datetime;
    string rangeStart;
    string rangeEnd;
    string ageAmount;
    bool recursive = false;
    bool verbose = false;
    bool showHelp = false;
    
    try {
        auto helpInfo = getopt(args,
            "c|command", "Command: show, set, clone, match, random, age, touch", &command,
            "t|target", "Target file or directory", &target,
            "r|reference", "Reference file for cloning", &reference,
            "d|datetime", "Datetime (YYYY-MM-DD HH:MM:SS)", &datetime,
            "s|start", "Range start datetime", &rangeStart,
            "e|end", "Range end datetime", &rangeEnd,
            "a|age", "Age amount (e.g., 30d, 6h, 90m)", &ageAmount,
            "R|recursive", "Process directories recursively", &recursive,
            "v|verbose", "Verbose output", &verbose,
            "h|help", "Show help", &showHelp
        );
        
        if (showHelp || args.length == 1 || command.length == 0) {
            writeln(BANNER);
            writeln("USAGE:");
            writeln("  timewarp -c <command> [options]");
            writeln();
            writeln("COMMANDS:");
            writeln("  show      Show file timestamps");
            writeln("  set       Set specific timestamp");
            writeln("  clone     Clone timestamps from reference file");
            writeln("  match     Match all files in dir to reference");
            writeln("  random    Randomize timestamps within range");
            writeln("  age       Age files by specified duration");
            writeln("  touch     Set timestamps to current time");
            writeln();
            writeln("OPTIONS:");
            defaultGetoptPrinter("", helpInfo.options);
            writeln();
            writeln("EXAMPLES:");
            writeln(`  timewarp -c show -t file.exe`);
            writeln(`  timewarp -c set -t file.exe -d "2020-06-15 08:30:00"`);
            writeln(`  timewarp -c clone -r /bin/ls -t malware.exe`);
            writeln(`  timewarp -c match -r /bin/ls -t ./payloads/ -R`);
            writeln(`  timewarp -c random -t file.exe -s "2019-01-01" -e "2020-12-31"`);
            writeln(`  timewarp -c age -t ./files/ -a 90d -R -v`);
            return;
        }
    } catch (Exception e) {
        writefln("[!] Error: %s", e.msg);
        return;
    }
    
    try {
        switch (command) {
            case "show":
                if (target.length == 0) {
                    writeln("[!] Target file required (-t)");
                    return;
                }
                writeln("\n[*] File Timestamps:");
                auto ts = getTimestamps(target);
                ts.print();
                break;
                
            case "set":
                if (target.length == 0 || datetime.length == 0) {
                    writeln("[!] Target (-t) and datetime (-d) required");
                    return;
                }
                auto newTime = parseDateTime(datetime);
                setTimestamps(target, newTime, newTime);
                writefln("[+] Set timestamps for: %s", target);
                if (verbose) {
                    auto ts = getTimestamps(target);
                    ts.print();
                }
                break;
                
            case "clone":
                if (target.length == 0 || reference.length == 0) {
                    writeln("[!] Target (-t) and reference (-r) required");
                    return;
                }
                cloneTimestamps(reference, target, verbose);
                break;
                
            case "match":
                if (target.length == 0 || reference.length == 0) {
                    writeln("[!] Target directory (-t) and reference (-r) required");
                    return;
                }
                matchDirectory(target, reference, verbose);
                break;
                
            case "random":
                if (target.length == 0 || rangeStart.length == 0 || rangeEnd.length == 0) {
                    writeln("[!] Target (-t), start (-s), and end (-e) required");
                    return;
                }
                auto start = parseDateTime(rangeStart);
                auto end = parseDateTime(rangeEnd);
                randomizeTimestamps(target, start, end, recursive, verbose);
                writefln("[+] Randomized timestamps for: %s", target);
                break;
                
            case "age":
                if (target.length == 0 || ageAmount.length == 0) {
                    writeln("[!] Target (-t) and age amount (-a) required");
                    return;
                }
                // Parse age amount (e.g., "30d", "6h", "90m")
                Duration ageDur;
                auto num = ageAmount[0..$-1].to!long;
                auto unit = ageAmount[$-1];
                
                switch (unit) {
                    case 'd': ageDur = days(num); break;
                    case 'h': ageDur = hours(num); break;
                    case 'm': ageDur = minutes(num); break;
                    case 's': ageDur = seconds(num); break;
                    default:
                        writeln("[!] Invalid age unit. Use d/h/m/s");
                        return;
                }
                
                ageFiles(target, ageDur, recursive, verbose);
                writefln("[+] Aged files by: %s", ageAmount);
                break;
                
            case "touch":
                if (target.length == 0) {
                    writeln("[!] Target file required (-t)");
                    return;
                }
                touchFile(target, verbose);
                break;
                
            default:
                writefln("[!] Unknown command: %s", command);
        }
    } catch (Exception e) {
        writefln("[!] Error: %s", e.msg);
    }
}
