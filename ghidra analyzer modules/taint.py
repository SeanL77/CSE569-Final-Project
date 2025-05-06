from ghidra.program.model.symbol import RefType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp


TAINT_SOURCES = ['recv', 'read', 'fgets', 'getchar']
UNSAFE_SINKS = ['strcpy', 'strcat', 'sprintf', 'gets', 'memcpy']


tainted_vars = set()


def get_called_function(instruction):
    if instruction.getFlowType().isCall():
        flows = instruction.getFlows()
        if flows:
            return getFunctionAt(flows[0])
    return None


def is_taint_source(func_name):
    return func_name in TAINT_SOURCES


def is_unsafe_sink(func_name):
    return func_name in UNSAFE_SINKS


def track_taint():
    fm = currentProgram.getFunctionManager() 
    # monitor = ConsoleTaskMonitor()
    
    for func in fm.getFunctions(True):
        listing = currentProgram.getListing() 
        instructions = listing.getInstructions(func.getBody(), True)
        
        for inst in instructions:
            called_func = get_called_function(inst)
            
            if called_func:
                name = called_func.getName()
                
                if is_taint_source(name):
                    print("[TAINT] Data source '{}' at {} in {}".format(name, inst.getAddress(), func.getName()))
                    output = inst.getResult()
                    
                    if output:
                        tainted_vars.add(str(output))

            # propagate taint through copy / move operations
            pcodeOps = inst.getPcode()
            for op in pcodeOps:
                
                if op.getOpcode() in (PcodeOp.COPY, PcodeOp.MOV):
                    input0 = op.getInput(0)
                    output = op.getOutput()
                    
                    if input0 and output and str(input0) in tainted_vars:
                        tainted_vars.add(str(output))

            # check if the tainted value reaches unsafe sink
            if called_func and is_unsafe_sink(called_func.getName()):
                inputs = [str(op) for i in range(inst.getNumOperands()) for op in inst.getOpObjects(i)]
                for operand in inputs:
                    if operand in tainted_vars:
                        print("[!!] tainted data reaches unsafe sink '{}' at {} in {}".format(called_func.getName(), inst.getAddress(), func.getName()))
                        break

track_taint()
