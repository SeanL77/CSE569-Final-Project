from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SymbolType


INSECURE_FUNCTIONS = {
    "strcpy", "memcpy", "strcat", "strncat",
    "sprintf", "scanf", "sscanf", "gets", "system",
    "exec", "execl", "execlp", "execv", "execvp",
    "execvpe", "popen", "printf", "fprintf"
}


class InsecureFunctionsAnalyzer(GhidraScript):
    def run(self):
        program = self.currentProgram
        if program is None:
            self.println("no program loaded! load a program into ghidra to run this script!")
            return

        listing = program.getListing()
        function_manager = program.getFunctionManager()
        results = []

        self.println("\nlooking for insecure function calls...\n")

        # iterate through functions
        for function in function_manager.getFunctions(True):
            body = function.getBody()
            instructions = listing.getInstructions(body, True)

            for instr in instructions:
                if not instr.getFlowType().isCall():
                    continue

                # get called address
                flows = instr.getFlows()
                if not flows:
                    continue

                # try to resolve called function
                called_func = function_manager.getFunctionAt(flows[0])
                if called_func is None:
                    continue

                name = called_func.getName()
                if name in INSECURE_FUNCTIONS:
                    msg = "[!] insecure call to '{}' at {} in function '{}'".format(name, instr.getAddress(), function.getName())
                    self.println(msg)
                    results.append((name, instr.getAddress(), function.getName()))

        if not results:
            self.println("no insecure function calls found.")
        else:
            self.println("\nfound {} insecure function call(s).".format(len(results)))
