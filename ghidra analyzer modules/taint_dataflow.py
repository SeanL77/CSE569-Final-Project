from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.listing import Function


TAINT_SOURCES = ["recv", "read", "fgets"]
UNSAFE_SINKS = ["strcpy", "sprintf", "strcat", "gets"]


# decompile function
def get_high_function(func):
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    
    if not decomp.decompileFunction(func, 60, ConsoleTaskMonitor()):
        print(f"failed to decompile {func.getName()}")
        return None
    
    return decomp.getHighFunction()


# check if the operation is a source call
def is_source_call(op):
    if op.getOpcode() == PcodeOp.CALL:
        fname = op.getInput(0).getAddress().getFunction().getName()
        return fname in TAINT_SOURCES
    
    return False


# check if the operation is a sink call
def is_sink_call(op):
    if op.getOpcode() == PcodeOp.CALL:
        fname = op.getInput(0).getAddress().getFunction().getName()
        return fname in UNSAFE_SINKS
    
    return False


# get tainted variables from source calls 
def get_tainted_vars(high_func):
    tainted = set()
    
    for op in high_func.getPcodeOps():
        if is_source_call(op):
            for i in range(1, op.getNumInputs()):
                input_var = op.getInput(i)
                tainted.add(input_var)
    
    return tainted


# propagate taint through copy / move operations
def propagate_taint(high_func, tainted):
    new_taint = set(tainted)
    changed = True
    
    while changed:
        changed = False
        for op in high_func.getPcodeOps():
            # copy / move operations
            if op.getOpcode() in (PcodeOp.COPY, PcodeOp.INT_ADD, PcodeOp.PTRADD):
                input0 = op.getInput(0)
                output = op.getOutput()
                if input0 in new_taint and output not in new_taint:
                    new_taint.add(output)
                    changed = True
    
    return new_taint


# detect if tainted variables reach unsafe sink calls
def detect_tainted_sinks(high_func, tainted_vars):
    for op in high_func.getPcodeOps():
        if is_sink_call(op):
            for i in range(1, op.getNumInputs()):
                if op.getInput(i) in tainted_vars:
                    print(f"[!!] tainted input reaches unsafe sink at {op.getSeqnum().getTarget()}")
                    break


# main function to analyze each function in program
def analyze_function(func):
    high_func = get_high_function(func)
    
    if not high_func:
        return
    
    tainted = get_tainted_vars(high_func)
    tainted = propagate_taint(high_func, tainted)
    detect_tainted_sinks(high_func, tainted)


# run the analysis on all functions in the program
def run():
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        analyze_function(func)

run()
