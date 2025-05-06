#!/usr/bin/env python

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType
import re


# PLC/Modbus 
MODBUS_FUNCTIONS = ["modbus_read", "modbus_write", "mb_read", "mb_write", "read_holding_register", "write_register"]
MODBUS_FUNCTION_CODES = {1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 
                        4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register", 
                        15: "Write Multiple Coils", 16: "Write Multiple Registers"}

# SCADA/DNP3 
DNP3_FUNCTIONS = ["dnp3_read", "dnp3_write", "dnp3_send", "dnp3_receive"]
DNP3_FUNCTION_CODES = {1: "Read", 2: "Write", 3: "Direct Operate", 4: "Direct Operate No Ack", 
                      13: "Cold Restart", 14: "Warm Restart", 20: "Enable Unsolicited",
                      21: "Disable Unsolicited"}

# IoT/Wireless 
IOT_FUNCTIONS = ["mqtt_publish", "mqtt_subscribe", "http_post", "http_get", "coap_post", "coap_get",
                "websocket_send", "websocket_receive", "bluetooth_send", "bluetooth_receive"]

# network protocols
NETWORK_PROTOCOLS = ["ethernet", "tcp", "udp", "ip", "http", "https", "ftp", "ssh", "telnet"]


# decompile function
def get_decompiled_code(func, program):
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
    
    if results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    return None


# analyze PLC firmware
def analyze_plc_firmware(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    # find modbus functions
    for func in fm.getFunctions(True):
        name = func.getName().lower()
        
        for mb_func in MODBUS_FUNCTIONS:
            if mb_func.lower() in name:
                finding = {
                    "type": "modbus_function",
                    "function": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "description": "modbus function detected: {}".format(func.getName()),
                    "severity": "medium"
                }
                findings.append(finding)

                if script:
                    script.println("modbus function: {} at {}".format(func.getName(), func.getEntryPoint()))

                # check for direct function code usage
                code = get_decompiled_code(func, program)
                if code:
                    for code_num, desc in MODBUS_FUNCTION_CODES.items():
                        if "0x{:02X}".format(code_num) in code or "= {};".format(code_num) in code or "== {}".format(code_num) in code:
                            finding = {
                                "type": "modbus_function_code",
                                "function": func.getName(),
                                "address": str(func.getEntryPoint()),
                                "description": "modbus function code {} ({}) used in {}".format(code_num, desc, func.getName()),
                                "severity": "low"
                            }
                            findings.append(finding)

                            if script:
                                script.println("modbus function code {} ({}) used in {}".format(code_num, desc, func.getName()))

                break
    
    # look for unsafe timing controls
    for func in fm.getFunctions(True):
        code = get_decompiled_code(func, program)
        if not code:
            continue
            
        # check for timing-related code in PLC firmware
        if "delay" in code.lower() and ("loop" in code.lower() or "while" in code.lower()):
            finding = {
                "type": "unsafe_timing",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "potential unsafe timing control in {}".format(func.getName()),
                "severity": "high"
            }
            findings.append(finding)

            if script:
                script.println("[!] potential unsafe timing control in {}".format(func.getName()))

    return findings


# analyze SCADA firmware
def analyze_scada_firmware(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    # find DNP3 functions
    for func in fm.getFunctions(True):
        name = func.getName().lower()
        
        # look for DNP3 functions
        for dnp3_func in DNP3_FUNCTIONS:
            if dnp3_func.lower() in name:
                finding = {
                    "type": "dnp3_function",
                    "function": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "description": "DNP3 function detected: {}".format(func.getName()),
                    "severity": "medium"
                }
                findings.append(finding)

                if script:
                    script.println("DNP3 function: {} at {}".format(func.getName(), func.getEntryPoint()))

                # check for direct function code usage
                code = get_decompiled_code(func, program)
                if code:
                    for code_num, desc in DNP3_FUNCTION_CODES.items():
                        if "0x{:02X}".format(code_num) in code or "= {};".format(code_num) in code or "== {}".format(code_num) in code:
                            finding = {
                                "type": "dnp3_function_code",
                                "function": func.getName(),
                                "address": str(func.getEntryPoint()),
                                "description": "DNP3 function code {} ({}) in {}".format(code_num, desc, func.getName()),
                                "severity": "low"
                            }
                            findings.append(finding)

                            if script:
                                script.println("[+] DNP3 function code {} ({}) in {}".format(code_num, desc, func.getName()))
                break
    
    # look for authentication checks 
    for func in fm.getFunctions(True):
        name = func.getName().lower()
        if "auth" in name or "login" in name or "authenticate" in name:
            code = get_decompiled_code(func, program)
            if not code:
                continue
                
            # check for weak authentication
            if "==" in code and ("password" in code.lower() or "user" in code.lower()):
                finding = {
                    "type": "weak_authentication",
                    "function": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "description": "potential weak authentication in {}".format(func.getName()),
                    "severity": "critical"
                }
                findings.append(finding)

                if script:
                    script.println("[!!] potential weak authentication in {}".format(func.getName()))

    return findings


# analyze IoT firmware
def analyze_iot_firmware(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    # find IoT protocol functions
    for func in fm.getFunctions(True):
        name = func.getName().lower()
        
        # look for IoT-specific functions
        for iot_func in IOT_FUNCTIONS:
            if iot_func.lower() in name:
                finding = {
                    "type": "iot_protocol",
                    "function": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "description": "IoT protocol function detected: {}".format(func.getName()),
                    "severity": "medium"
                }
                findings.append(finding)

                if script:
                    script.println("IoT protocol function: {} at {}".format(func.getName(), func.getEntryPoint()))
                break
        
        # check for encryption
        if "encrypt" in name or "decrypt" in name or "aes" in name or "sha" in name:
            finding = {
                "type": "encryption_function",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "encryption function detected: {}".format(func.getName()),
                "severity": "low"
            }
            findings.append(finding)

            if script:
                script.println("encryption function: {} at {}".format(func.getName(), func.getEntryPoint()))

    # look for network protocol usage
    for func in fm.getFunctions(True):
        code = get_decompiled_code(func, program)
        if not code:
            continue
        
        # check plaintext protocols
        for protocol in NETWORK_PROTOCOLS:
            if protocol.lower() in code.lower():
                # high severity alert for plaintext protocols
                severity = "high" if protocol in ["http", "ftp", "telnet"] else "low"
                
                finding = {
                    "type": "network_protocol",
                    "function": func.getName(),
                    "protocol": protocol,
                    "address": str(func.getEntryPoint()),
                    "description": "{} protocol usage detected in {}".format(protocol.upper(), func.getName()),
                    "severity": severity
                }
                findings.append(finding)

                if script:
                    prefix = "[!]" if severity == "high" else "[+]"
                    script.println("{} {} protocol usage in {}".format(prefix, protocol.upper(), func.getName()))

    return findings


# analyze generic CPS firmware
def analyze_generic_firmware(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    # look for system / command execution
    for func in fm.getFunctions(True):
        code = get_decompiled_code(func, program)
        if not code:
            continue
            
        # check command execution
        if "system(" in code or "exec(" in code or "popen(" in code:
            finding = {
                "type": "command_execution",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "command execution found in {}".format(func.getName()),
                "severity": "critical"
            }
            findings.append(finding)

            if script:
                script.println("[!!] command execution found in {}".format(func.getName()))
        
        # check file operations
        if "fopen(" in code or "open(" in code:
            finding = {
                "type": "file_operation",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "file operation found in {}".format(func.getName()),
                "severity": "medium"
            }
            findings.append(finding)

            if script:
                script.println("file operation found in {}".format(func.getName()))

    return findings



# analyze firmware based on its type
def analyze(program=None, script=None, firmware_type="generic"):
    findings = []
    
    if program is None:
        program = currentProgram
    
    if firmware_type == "plc" or firmware_type == "generic":
        plc_findings = analyze_plc_firmware(program, script)
        findings.extend(plc_findings)
        
    if firmware_type == "scada" or firmware_type == "generic":
        scada_findings = analyze_scada_firmware(program, script)
        findings.extend(scada_findings)
        
    if firmware_type == "iot" or firmware_type == "generic":
        iot_findings = analyze_iot_firmware(program, script)
        findings.extend(iot_findings)
        
    if firmware_type == "generic":
        generic_findings = analyze_generic_firmware(program, script)
        findings.extend(generic_findings)
    
    return findings


if __name__ == "__main__":
    findings = analyze()
    print("found {} firmware-specific features and vulnerabilities".format(len(findings)))
