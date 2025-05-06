#!/usr/bin/env python

import os
import json
from ghidra.app.script import GhidraScript

import buffer_overflow
import insecure_functions
import hardcoded_credentials
# import taint
import control_logic_analyzer
import firmware_specific_analyzer
import ioc_detector
import privilege_escalation_detector


class CPSAnalyzer(GhidraScript):
    def __init__(self):
        super(CPSAnalyzer, self).__init__()
        self.results = {
            "buffer_overflows": [],
            "insecure_functions": [],
            "hardcoded_credentials": [],
            "taint_flows": [],
            "control_logic_issues": [],
            "firmware_specific_issues": [],
            "iocs": [],
            "privilege_escalation": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
        self.config = None


    def load_config(self):
        config_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "config.json")
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.println("ERROR loading config file: {}".format(e))
            return {
                "firmware_type": "generic",
                "analysis_modules": [
                    "buffer_overflow",
                    "insecure_functions",
                    "hardcoded_credentials",
                    "taint",
                    "control_logic_analyzer",
                    "firmware_specific_analyzer",
                    "ioc_detector",
                    "privilege_escalation_detector"
                ]
            }


    def run(self):
        # make sure a program is loaded
        if currentProgram is None:
            self.println("no program loaded. you need to load a program in ghidra before running the script.")
            return

        self.config = self.load_config()
        self.println("starting CPS firmware analysis...")
        self.println("analyzing program: {}".format(currentProgram.getName()))
        
        if "buffer_overflow" in self.config["analysis_modules"]:
            self.println("detecting buffer overflows...")
            self.results["buffer_overflows"] = buffer_overflow.find_buffer_overflows(currentProgram, self)

        if "insecure_functions" in self.config["analysis_modules"]:
            self.println("detecting insecure function calls...")
            self.results["insecure_functions"] = insecure_functions.find_insecure_calls(currentProgram, self)

        if "hardcoded_credentials" in self.config["analysis_modules"]:
            self.println("detecting hardcoded credentials...")
            self.results["hardcoded_credentials"] = hardcoded_credentials.scan_for_hardcoded_strings(currentProgram, self)

        if "taint" in self.config["analysis_modules"]:
            self.println("doing taint analysis...")
            self.results["taint_flows"] = taint.track_taint(currentProgram, self)

        if "control_logic_analyzer" in self.config["analysis_modules"]:
            self.println("analyzing control logic...")
            self.results["control_logic_issues"] = control_logic_analyzer.analyze(currentProgram, self)

        if "firmware_specific_analyzer" in self.config["analysis_modules"]:
            self.println("doing firmware-specific analysis...")
            self.results["firmware_specific_issues"] = firmware_specific_analyzer.analyze(
                currentProgram, self, self.config["firmware_type"]
            )

        if "ioc_detector" in self.config["analysis_modules"]:
            self.println("looking for indicators of compromise...")
            self.results["iocs"] = ioc_detector.detect(currentProgram, self)

        if "privilege_escalation_detector" in self.config["analysis_modules"]:
            self.println("checking for privilege escalation...")
            self.results["privilege_escalation"] = privilege_escalation_detector.detect(currentProgram, self)

        self.calculate_summary()
        self.print_results_to_console()
        self.println("analysis done!!")
        self.println("found {} critical, {} high, {} medium, and {} low severity issues.".format(
            self.results['summary']['critical'],
            self.results['summary']['high'],
            self.results['summary']['medium'],
            self.results['summary']['low']
        ))


    def calculate_summary(self):
        for module, findings in self.results.items():
            if module != "summary" and isinstance(findings, list):
                for finding in findings:
                    if "severity" in finding:
                        self.results["summary"][finding["severity"]] += 1


    def print_results_to_console(self):
        self.println("\nfinal analysis report:\n")
        try:
            self.println(json.dumps(self.results, indent=2))
        except Exception as e:
            self.println("error printing results: {}".format(e))


if __name__ == "__main__":
    print("script must be run within ghidra")
