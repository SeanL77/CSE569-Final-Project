#!/usr/bin/env python

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import SymbolType
import re


CONTROL_FUNCTIONS = [
    "set_parameter", "set_speed", "set_temperature", "set_pressure", "set_valve", 
    "motor_control", "relay_control", "pump_control", "actuator_control",
    "pwm_set", "digital_write", "analog_write", "pin_control",
    "modbus_write", "dnp3_write", "canbus_write", "write_register"
]

SAFETY_CHECKS = [
    "limit_check", "range_check", "safety_check", "verify_bounds", 
    "validate_input", "check_temperature", "check_pressure", "watchdog"
]

# regular expressions for control logic patterns
CONTROL_LOOP_PATTERN = r"while|for\s*\(.*(temperature|pressure|level|speed|position|state)\s*"
STATE_MACHINE_PATTERN = r"switch\s*\(\s*(state|mode|status)\s*\)"
THRESHOLD_CHECK_PATTERN = r"if\s*\(\s*(temperature|pressure|level|speed|position)\s*[><=!]=?\s*\w+\s*\)"
TIMER_PATTERN = r"(delay|wait|sleep|timeout|timer)\s*\(\s*\d+"


# decompile function
def get_decompiled_code(func, program):
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())
    
    if results.decompileCompleted():
        return results.getDecompiledFunction().getC()
    
    return None


# look for critical control functions in the program / firmware
def find_critical_functions(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    for func in fm.getFunctions(True):
        name = func.getName().lower()
        
        # check for control-related function names
        for control_func in CONTROL_FUNCTIONS:
            if control_func.lower() in name:
                finding = {
                "type": "critical_control_function",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "critical control function detected: {}".format(func.getName()), 
                "severity": "high"
            }
            findings.append(finding)

            if script:
                script.println("[!] critical control function: {} at {}".format(func.getName(), func.getEntryPoint())) 
            break

    return findings

# check for missing safety checks in critical control functions
def check_missing_safety_checks(program, script=None):
    findings = []
    
    # get all the critical functions
    critical_funcs = []
    fm = program.getFunctionManager()
    
    for func in fm.getFunctions(True):
        name = func.getName().lower()
        for control_func in CONTROL_FUNCTIONS:
            if control_func.lower() in name:
                critical_funcs.append(func)
                break
    
    # check each critical function for safety checks
    for func in critical_funcs:
        has_safety_check = False
        code = get_decompiled_code(func, program)
        
        if not code:
            continue
            
        # check for safety check functions
        for check in SAFETY_CHECKS:
            if check.lower() in code.lower():
                has_safety_check = True
                break
                
        # check for bounds checking patterns
        if re.search(r"if\s*\(.+[<>]=?.+\)", code):
            has_safety_check = True
            
        if not has_safety_check:
            finding = {
                "type": "missing_safety_check",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "critical function {} may be missing safety checks".format(func.getName()),  
                "severity": "critical"
            }
            findings.append(finding)

            if script:
                script.println("[!!] missing safety check in critical function: {} at {}".format(func.getName(), func.getEntryPoint())) 

    return findings


# check for control loops and state machines in firmware
def find_control_loops(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    for func in fm.getFunctions(True):
        code = get_decompiled_code(func, program)
        if not code:
            continue
            
        # check for control loops
        if re.search(CONTROL_LOOP_PATTERN, code, re.IGNORECASE):
            finding = {
                "type": "control_loop",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "control loop detected in {}".format(func.getName()), 
                "severity": "medium"
            }
            findings.append(finding)

            if script:
                script.println("control loop found in: {} at {}".format(func.getName(), func.getEntryPoint())) 
                
        # check for state machines
        if re.search(STATE_MACHINE_PATTERN, code, re.IGNORECASE):
            finding = {
                "type": "state_machine",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "state machine in {}".format(func.getName()), 
                "severity": "medium"
            }
            findings.append(finding)

            if script:
                script.println("state machine found in: {} at {}".format(func.getName(), func.getEntryPoint()))  
    
        # check for threshold checking
        if re.search(THRESHOLD_CHECK_PATTERN, code, re.IGNORECASE):
            finding = {
                "type": "threshold_check",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "threshold check detected in {}".format(func.getName()), 
                "severity": "low"
            }
            findings.append(finding)

            if script:
                script.println("threshold check found in: {} at {}".format(func.getName(), func.getEntryPoint()))  
    
    return findings


# check for timer functions in the firmware
def find_timer_functions(program, script=None):
    findings = []
    fm = program.getFunctionManager()
    
    for func in fm.getFunctions(True):
        code = get_decompiled_code(func, program)
        if not code:
            continue
            
        # check for timer patterns
        if re.search(TIMER_PATTERN, code, re.IGNORECASE):
            finding = {
                "type": "timer_function",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "timer function found in {}".format(func.getName()), 
                "severity": "low"
            }
            findings.append(finding)

            if script:
                script.println("timer function found in: {} at {}".format(func.getName(), func.getEntryPoint()))  

    return findings


# analyze control logic in the CPS firmware
def analyze(program=None, script=None):
    findings = []
    
    if program is None:
        program = currentProgram
    
    # find all potential critical control functions
    critical_funcs = find_critical_functions(program, script)
    findings.extend(critical_funcs)
    
    # check for missing safety checks
    missing_checks = check_missing_safety_checks(program, script)
    findings.extend(missing_checks)
    
    # find control loops and state machines
    control_structures = find_control_loops(program, script)
    findings.extend(control_structures)
    
    # find timer functions
    timer_funcs = find_timer_functions(program, script)
    findings.extend(timer_funcs)
    
    return findings


if __name__ == "__main__":
    findings = analyze()
    print("found {} control logic elements".format(len(findings)))