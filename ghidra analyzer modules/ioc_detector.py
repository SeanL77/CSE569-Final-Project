#!/usr/bin/env python

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType
import re


SUSPICIOUS_STRINGS = [
    "backdoor", "shell", "root", "exploit", "hack", "spawn",
    "connect-back", "reverse shell", "bind shell", "exec", "shutdown", "trojan", 
    "hidden", "password", "override", "bypass", "xor", "obscure", "encode"
]

SUSPICIOUS_NETWORKING = [
    "0.0.0.0", "255.255.255.255", "socket", "connect(", "accept(", "listen(",
    "sendto(", "recvfrom(", "bind(", "gethostbyname", "getaddrinfo"
]

SUSPICIOUS_PORTS = [
    "4444", "1337", "31337", "6666", "6667", "6000", "23", # backdoor ports
    "5900", "5901", "5902", # VNC ports
    "22", "23", "3389" # SSH, Telnet, RDP
]

OBFUSCATION_PATTERNS = [
    r"base64_decode", r"base64_encode", r"decode\s*\(", r"encode\s*\(",
    r"xor\s*\(", r"strrev\s*\(", r"rot13", r"\\x[0-9a-fA-F]{2}"
]


# decompile function
def get_decompiled_code(func, program):
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
    
    if results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    
    return None


# look for suspicious strings in the firmware
def check_suspicious_strings(program, script=None):
    findings = []
    
    # get all strings from program
    strings = program.getStringTable().getAllStrings()
    
    for s in strings:
        string_val = s.getString(True)
        string_addr = s.getAddress()
        
        # check for suspicious strings
        for suspicious in SUSPICIOUS_STRINGS:
            if suspicious.lower() in string_val.lower():
                finding = {
                    "type": "suspicious_string",
                    "string": string_val,
                    "address": str(string_addr),
                    "description": "suspicious string: '{}' at {}".format(string_val, string_addr),
                    "severity": "medium",
                    "ioc_type": "string",
                    "indicator": suspicious
                }
                findings.append(finding)

                if script:
                    script.println("[!] suspicious string: '{}' at {}".format(string_val, string_addr))
                break
        
        # check for IP addresses
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        ip_matches = re.findall(ip_pattern, string_val)
        
        for ip in ip_matches:
            finding = {
                "type": "ip_address",
                "string": string_val,
                "address": str(string_addr),
                "description": "IP address found: '{}' at {}".format(ip, string_addr),
                "severity": "medium",
                "ioc_type": "network",
                "indicator": ip
            }
            findings.append(finding)

            if script:
                script.println("[!] IP address found: '{}' at {}".format(ip, string_addr))

        # check for suspicious ports
        for port in SUSPICIOUS_PORTS:
            if port in string_val:
                finding = {
                    "type": "suspicious_port",
                    "string": string_val,
                    "address": str(string_addr),
                    "description": "suspicious port number: '{}' at {}".format(port, string_addr),
                    "severity": "high",
                    "ioc_type": "network",
                    "indicator": port
                }
                findings.append(finding)

                if script:
                    script.println("[!] suspicious port number... '{}' at {}".format(port, string_addr))

    return findings


# look for suspicious function behavior 
def check_suspicious_functions(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    for func in fm.getFunctions(True):
        code = get_decompiled_code(func, program)
        if not code:
            continue
        
        # check for suspicious networking
        for suspicious_net in SUSPICIOUS_NETWORKING:
            if suspicious_net in code:
                finding = {
                    "type": "suspicious_networking",
                    "function": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "description": "suspicious networking: '{}' in {}".format(suspicious_net, func.getName()),
                    "severity": "high" if suspicious_net in ["0.0.0.0", "255.255.255.255"] else "medium",
                    "ioc_type": "function",
                    "indicator": suspicious_net
                }
                findings.append(finding)

                if script:
                    script.println("[!] suspicious networking: '{}' in {}".format(suspicious_net, func.getName()))

        # check for obfuscation techniques
        for pattern in OBFUSCATION_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                finding = {
                    "type": "obfuscation",
                    "function": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "description": "potential obfuscation in {}".format(func.getName()),
                    "severity": "high",
                    "ioc_type": "function",
                    "indicator": pattern
                }
                findings.append(finding)

                if script:
                    script.println("[!!] potential obfuscation in {}".format(func.getName()))

        # check for suspicious control flow (e.g., JMP self, anti-debugging)
        if "ptrace" in code or "isdebuggerpresent" in code.lower() or "debugger" in code.lower():
            finding = {
                "type": "anti_debugging",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "anti-debugging detected in {}".format(func.getName()),
                "severity": "critical",
                "ioc_type": "function",
                "indicator": "anti_debugging"
            }
            findings.append(finding)

            if script:
                script.println("[!!] anti-debugging detected in {}".format(func.getName()))

    return findings


# look for suspicious symbols
def check_suspicious_symbols(program, script=None):
    findings = []
    symbolTable = program.getSymbolTable()
    
    symbols = symbolTable.getAllSymbols(True)
    for symbol in symbols:
        name = symbol.getName()
        
        # check for suspicious symbol names
        for suspicious in SUSPICIOUS_STRINGS:
            if suspicious.lower() in name.lower():
                finding = {
                    "type": "suspicious_symbol",
                    "symbol": name,
                    "address": str(symbol.getAddress()),
                    "description": "suspicious symbol: '{}' at {}".format(name, symbol.getAddress()),
                    "severity": "medium",
                    "ioc_type": "symbol",
                    "indicator": suspicious
                }
                findings.append(finding)

                if script:
                    script.println("[!] suspicious symbol: '{}' at {}".format(name, symbol.getAddress()))
                break
    
    return findings


# main function to detect potential IoCs
def detect(program=None, script=None):
    findings = []
    
    if program is None:
        program = currentProgram
    
    # check for suspicious strings
    string_findings = check_suspicious_strings(program, script)
    findings.extend(string_findings)
    
    # check for suspicious functions
    function_findings = check_suspicious_functions(program, script)
    findings.extend(function_findings)
    
    # check for suspicious symbols
    symbol_findings = check_suspicious_symbols(program, script)
    findings.extend(symbol_findings)
    
    return findings


if __name__ == "__main__":
    findings = detect()
    print("found {} potential indicators of compromise".format(len(findings)))