# -*- coding: utf-8 -*-
#@author Sean Lucas, Sophia Dykstra
#@category Analysis
#@keybinding
#@menupath Tools.RiskyFunctionAnalyzer
#@toolbar

import os
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import CodeUnit
from java.io import FileWriter

listing = currentProgram.getListing()
RISKY_SUBSTRINGS = ["strcpy", "strcat", "sprintf", "memcpy", "gets", "scanf", "alloc", "malloc", "free", "realloc"]

FORMAT_FUNCS = ["printf", "fprintf", "sprintf", "snprintf", "vprintf", "vsprintf"]
BUFFER_KEYWORDS = ["char ", "char[", "buffer", "buf"]
UNSAFE_PATTERNS = ["[", "]", "=", "+", "-"]

def is_risky_function(name):
    name_lower = name.lower()
    return any(substr in name_lower for substr in RISKY_SUBSTRINGS)

def is_format_string_vuln(decompiled_code):
    for line in decompiled_code.splitlines():
        for fmt in FORMAT_FUNCS:
            if fmt in line and '(' in line:
                args = line.split(fmt)[1]
                if not ("\"" in args.split(",")[0]):
                    return True
    return False

def buffer_overflow_heuristic(decompiled_code):
    stack_allocs = [line.strip() for line in decompiled_code.splitlines() if any(kw in line for kw in BUFFER_KEYWORDS)]
    possible_overflows = []

    for decl in stack_allocs:
        var_name = decl.split()[-1].replace(";", "").replace("]", "").split("[")[0]
        if any(op in decl for op in UNSAFE_PATTERNS):
            possible_overflows.append(decl)

    return possible_overflows

def analyze_program():
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()

    risky_funcs = {}
    call_edges = []

    for func in functions:
        fname = func.getName()
        reasons = []

        if is_risky_function(fname):
            reasons.append("Name matches risky pattern")
            listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, "risky function: " + fname)
            func.setName("RISKY_" + fname, SourceType.USER_DEFINED)

        results = decompiler.decompileFunction(func, 30, monitor)
        if results and results.decompileCompleted():
            decompiled_code = results.getDecompiledFunction().getC()

            for keyword in RISKY_SUBSTRINGS:
                if keyword in decompiled_code:
                    reasons.append("decompiled code uses: " + keyword)
                    listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, "uses risky operation: " + keyword)
                    break

            if is_format_string_vuln(decompiled_code):
                reasons.append("potential format string vulnerability")

            buf_overflows = buffer_overflow_heuristic(decompiled_code)
            if buf_overflows:
                reasons.append("potential buffer overflow risk (stack): " + ", ".join(buf_overflows[:2]))

        if reasons:
            risky_funcs[func] = reasons

        for ref in getReferencesTo(func.getEntryPoint()):
            from_func = getFunctionContaining(ref.getFromAddress())
            if from_func and from_func != func:
                call_edges.append((from_func.getName(), func.getName()))

    decompiler.dispose()
    return risky_funcs, call_edges

def export_call_graph(risky_funcs, call_edges):
    user_home = os.getenv("USERPROFILE") or os.getenv("HOME")
    dot_path = os.path.join(user_home, "ghidra_risk_graph.dot")
    fw = FileWriter(dot_path)
    fw.write("digraph RiskyCallGraph {\n")
    for func in risky_funcs:
        fw.write('  "{}" [color=red, style=filled];\n'.format(func.getName()))
    for caller, callee in call_edges:
        if callee in [f.getName() for f in risky_funcs]:
            fw.write('  "{}" -> "{}";\n'.format(caller, callee))
    fw.write("}\n")
    fw.close()
    print("[+] Exported call graph to: {}".format(dot_path))

def generate_risk_report(risky_funcs, call_edges):
    user_home = os.getenv("USERPROFILE") or os.getenv("HOME")
    report_path = os.path.join(user_home, "ghidra_risk_report.txt")
    with open(report_path, "w") as f:
        f.write("=== Risk Analysis Report ===\n\n")
        for func, reasons in risky_funcs.items():
            f.write("[*] Function: {}\n".format(func.getName()))
            for reason in reasons:
                f.write("    - {}\n".format(reason))

            callers = [caller for caller, callee in call_edges if callee == func.getName()]
            if callers:
                f.write("    Called by: {}\n".format(", ".join(callers)))
            f.write("\n")
    print("[+] Exported risk report to: {}".format(report_path))

def compute_risk_score(risky_funcs, call_edges, total_funcs):
    if total_funcs == 0:
        return 0, "No functions in binary."

    risky_count = len(risky_funcs)
    risky_ops = 0
    malloc_related = 0
    risky_names = 0

    for func, reasons in risky_funcs.items():
        for reason in reasons:
            if "Uses risky operation" in reason:
                risky_ops += 1
            if "alloc" in reason:
                malloc_related += 1
            if "Name matches risky pattern" in reason:
                risky_names += 1

    callers = [caller for caller, callee in call_edges if callee in [f.getName() for f in risky_funcs]]
    unique_callers = set(callers)

    f_weight = min((risky_count / float(total_funcs)) * 40, 40)
    op_weight = min((risky_ops / float(max(risky_count, 1))) * 30, 30)
    call_weight = min((len(unique_callers) / float(total_funcs)) * 20, 20)
    alloc_weight = min((malloc_related / float(max(risky_count, 1))) * 10, 10)

    total_score = round(f_weight + op_weight + call_weight + alloc_weight, 2)
    explanation = (
        "Score Breakdown:\n"
        " - Risky Functions: {:.2f}/40\n"
        " - Risky Ops in Code: {:.2f}/30\n"
        " - External Calls to Risky Funcs: {:.2f}/20\n"
        " - Unchecked alloc/free: {:.2f}/10\n"
    ).format(f_weight, op_weight, call_weight, alloc_weight)

    return total_score, explanation

# Run all
risky_funcs, call_edges = analyze_program()
export_call_graph(risky_funcs, call_edges)
generate_risk_report(risky_funcs, call_edges)

total_funcs = currentProgram.getFunctionManager().getFunctionCount()
score, explanation = compute_risk_score(risky_funcs, call_edges, total_funcs)
print("=== Vulnerability Score: {}/100 ===".format(score))
print(explanation)
