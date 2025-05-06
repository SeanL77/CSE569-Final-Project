#!/usr/bin/env python

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType
import re


PRIVILEGE_FUNCTIONS = [
    "setuid", "seteuid", "setgid", "setegid", "setreuid", "setregid",
    "setresuid", "setresgid", "setgroups", "initgroups", 
    "sudo", "privilege", "su", "chmod", "chown", "capability"
]

PERMISSION_FUNCTIONS = [
    "chmod", "chown", "chgrp", "open", "fopen", "creat", "access",
    "setcap", "getcap", "prctl", "getrlimit", "setrlimit"
]

CAPABILITY_STRINGS = [
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID",
    "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
    "CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE", "CAP_SYS_BOOT", "CAP_SYS_MODULE"
]


# decompile function
def get_decompiled_code(func, program):
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
    
    if results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    
    return None


# look for privilege-related functions in the firmware
def check_privilege_functions(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    for func in fm.getFunctions(True):
        name = func.getName().lower()
        
        # look for privilege-related function names
        for priv_func in PRIVILEGE_FUNCTIONS:
            if priv_func.lower() in name:
                finding = {
                    "type": "privilege_function",
                    "function": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "description": "privilege-related function: {}".format(func.getName()),
                    "severity": "high",
                    "escalation_vector": priv_func
                }
                findings.append(finding)

                if script:
                    script.println("[!] privilege-related function: {} at {}".format(func.getName(), func.getEntryPoint()))
                break
    
    return findings


# look for privilege changing calls
def check_uid_calls(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    for func in fm.getFunctions(True):
        code = get_decompiled_code(func, program)
        if not code:
            continue
        
        # look for setuid(0), seteuid(0), etc. (privilege escalation)
        if re.search(r"setuid\s*\(\s*0\s*\)", code) or re.search(r"seteuid\s*\(\s*0\s*\)", code):
            finding = {
                "type": "set_root_uid",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "setting UID to root (0) in {}".format(func.getName()),
                "severity": "critical",
                "escalation_vector": "setuid_to_root"
            }
            findings.append(finding)

            if script:
                script.println("[!!] setting UID to root (0) in {}".format(func.getName()))

        # look for setgid(0), setegid(0), etc. etc.
        if re.search(r"setgid\s*\(\s*0\s*\)", code) or re.search(r"setegid\s*\(\s*0\s*\)", code):
            finding = {
                "type": "set_root_gid",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "setting GID to root (0) in {}".format(func.getName()),
                "severity": "critical",
                "escalation_vector": "setgid_to_root"
            }
            findings.append(finding)

            if script:
                script.println("[!!] setting GID to root (0) in {}".format(func.getName()))

    return findings


# look for unsafe permission operations
def check_unsafe_permissions(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    for func in fm.getFunctions(True):
        code = get_decompiled_code(func, program)
        if not code:
            continue
        
        # look for chmod 777, 666, etc.
        chmod_patterns = [
            r"chmod\s*\(\s*[\"'][^\"']*[\"']\s*,\s*0777\s*\)",
            r"chmod\s*\(\s*[\"'][^\"']*[\"']\s*,\s*0666\s*\)",
            r"chmod\s*\(\s*[\"'][^\"']*[\"']\s*,\s*511\s*\)" 
        ]
        
        for pattern in chmod_patterns:
            if re.search(pattern, code):
                finding = {
                    "type": "unsafe_chmod",
                    "function": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "description": "unsafe chmod operation in {}".format(func.getName()),
                    "severity": "high",
                    "escalation_vector": "unsafe_permissions"
                }
                findings.append(finding)

                if script:
                    script.println("[!] unsafe chmod operation in {}".format(func.getName()))
                break
        
        # look for open with insecure flags (potential arbitrary file access)
        if re.search(r"open\s*\([^,]+,\s*[^,]*O_CREAT[^,]*,\s*0666\s*\)", code) or \
           re.search(r"open\s*\([^,]+,\s*[^,]*O_CREAT[^,]*,\s*0777\s*\)", code):
            finding = {
                "type": "unsafe_file_creation",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "unsafe file creation with excessive permissions in {}".format(func.getName()),
                "severity": "high",
                "escalation_vector": "unsafe_permissions"
            }
            findings.append(finding)

            if script:
                script.println("[!] unsafe file creation with excessive permissions in {}".format(func.getName()))
    
    return findings


# look for linux capability usage and manipulation
def check_capability_usage(program, script=None):
    findings = []
    strings = program.getStringTable().getAllStrings()
    
    for s in strings:
        string_val = s.getString(True)
        string_addr = s.getAddress()
        
        for cap in CAPABILITY_STRINGS:
            if cap in string_val:
                finding = {
                    "type": "capability_usage",
                    "string": string_val,
                    "address": str(string_addr),
                    "description": "linux capability '{}' found at {}".format(cap, string_addr),
                    "severity": "medium",
                    "escalation_vector": "linux_capabilities"
                }
                findings.append(finding)

                if script:
                    script.println("[!] linux capability '{}' found at {}".format(cap, string_addr))

    # look for capability manipulation functions
    fm = program.getFunctionManager()

    for func in fm.getFunctions(True):
        code = get_decompiled_code(func, program)
        if not code:
            continue
        
        if "prctl" in code and "PR_SET_KEEPCAPS" in code:
            finding = {
                "type": "keepcaps_usage",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "PR_SET_KEEPCAPS used in {} - potential for privilege escalation".format(func.getName()),
                "severity": "critical",
                "escalation_vector": "keepcaps"
            }
            findings.append(finding)

            if script:
                script.println("[!!] PR_SET_KEEPCAPS used in {} - potential for privilege escalation".format(func.getName()))

        if "cap_set_proc" in code or "cap_set_flag" in code:
            finding = {
                "type": "capability_manipulation",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "capability manipulation in {}".format(func.getName()),
                "severity": "high",
                "escalation_vector": "capability_manipulation"
            }
            findings.append(finding)

            if script:
                script.println("[!] capability manipulation in {}".format(func.getName()))
    
    return findings


# main detection function
def detect(program=None, script=None):
    findings = []
    
    if program is None:
        program = currentProgram
    
    priv_funcs = check_privilege_functions(program, script)
    findings.extend(priv_funcs)
    
    uid_findings = check_uid_calls(program, script)
    findings.extend(uid_findings)
    
    perm_findings = check_unsafe_permissions(program, script)
    findings.extend(perm_findings)
    
    cap_findings = check_capability_usage(program, script)
    findings.extend(cap_findings)
    
    return findings


if __name__ == "__main__":
    findings = detect()
    print("found {} potential privilege escalation vectors".format(len(findings))) 