from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import Function
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.lang import OperandType
import json

UNSAFE_FUNCS = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 'memcpy', 'strncpy', 'strncat']


# check if function name is in the list of unsafe functions
def is_unsafe(name, unsafe_list=None):
    if unsafe_list is None:
        unsafe_list = UNSAFE_FUNCS
    return name in unsafe_list


# look at a function and see if there's potential for a buffer overflow
def analyze_function_for_overflow(func, program, script=None, unsafe_list=None):
    findings = []
    instructions = func.getBody()
    
    for addr in instructions.getAddresses(True):
        inst = program.getListing().getInstructionAt(addr)
        
        if inst and inst.getFlowType().isCall():
            flows = inst.getFlows()
            
            if not flows:
                continue
            called_func = program.getFunctionManager().getFunctionAt(flows[0])
            
            if called_func and is_unsafe(called_func.getName(), unsafe_list):
                # see if local buffer is involved
                called_name = called_func.getName()
                operands = [inst.getOpObjects(i) for i in range(inst.getNumOperands())]
                all_ops = [item for sublist in operands for item in sublist]
                
                for op in all_ops:
                    if hasattr(op, 'isStackVariable') and op.isStackVariable():
                        finding = {
                            "type": "buffer_overflow",
                            "function": func.getName(),
                            "address": str(addr),
                            "called_function": called_name,
                            "description": "possible buffer overflow in '{}' using local buffer with '{}'".format(func.getName(), called_name),
                            "severity": "critical" if called_name in ['strcpy', 'gets'] else "high"
                        }

                        findings.append(finding)
                        
                        if script:
                            script.println("[!!!!] POSSIBLE BUFFER OVERFLOW: '{}' at {} in {} using local buffer".format(called_name, addr, func.getName()))
                        break
                else:
                    finding = {
                        "type": "insecure_function",
                        "function": func.getName(),
                        "address": str(addr),
                        "called_function": called_name,
                        "description": "insecure function call to '{}' in '{}'".format(called_name, func.getName()),
                        "severity": "medium"
                    }
                    findings.append(finding)

                    if script:
                        script.println("[!] insecure function call to '{}' at {} in {}".format(called_name, addr, func.getName()))

    return findings


# check array access for bounds checking
def check_array_bounds(program, script=None):
    findings = []
    decompiler_service = None
    if script:
        decompiler_service = script.getDecompiler()
    
    if not decompiler_service:
        if script:
            script.println("[!] WARNING: decompiler not available... skipping array bounds check then..")
        return findings
    
    fm = program.getFunctionManager()
    
    for func in fm.getFunctions(True):
        # decompile function
        high_func = decompiler_service.decompileFunction(func, 60, ConsoleTaskMonitor())
        if not high_func:
            continue
        
        # check for array access patterns w/o bounds checking
        decompiled_code = high_func.getDecompiledFunction().getC()
        if "[" in decompiled_code and "if" not in decompiled_code:
            finding = {
                "type": "unbounded_array_access",
                "function": func.getName(),
                "address": str(func.getEntryPoint()),
                "description": "potential unbounded array access in {}".format(func.getName()),
                "severity": "medium"
            }
            findings.append(finding)

            if script:
                script.println("[!] potential unbounded array access in {}".format(func.getName()))
    
    return findings


# look for the buffer overflows in the program
def find_buffer_overflows(program=None, script=None):
    findings = []
    
    if program is None:
        program = currentProgram
        
    # load unsafe functions from config if available
    unsafe_list = UNSAFE_FUNCS
    if script and hasattr(script, 'config') and 'taint_settings' in script.config:
        unsafe_list = script.config['taint_settings']['sinks']
    
    fm = program.getFunctionManager()
    
    # check each function for unsafe function calls
    for func in fm.getFunctions(True):
        func_findings = analyze_function_for_overflow(func, program, script, unsafe_list)
        findings.extend(func_findings)
    
    # check for array access w/o bounds checking
    array_findings = check_array_bounds(program, script)
    findings.extend(array_findings)
    
    return findings


if __name__ == "__main__":
    findings = find_buffer_overflows()
    print("found {} potential buffer overflow vulnerabilities".format(len(findings)))
