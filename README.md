# Automated Vulnerability Discovery in CPS Firmware Using Ghidra

## Overview

This project presents a set of tools and scripts built on [Ghidra](https://ghidra-sre.org/), to automate the static analysis of CPS firmware binaries. Our goal is to assist developers and analysts in identifying potential security risks early in the firmware lifecycle and to encourage the integration of cybersecurity considerations from the ground up in CPS design.


## Features

- **Modular Ghidra Scripts**: Automate static binary analysis to identify potential vulnerabilities using scripted control flow and data flow analysis.
- **Risk Visualization**: Generates call graphs and risk reports that highlight vulnerable regions in the firmware and their relation to core functionality.


## Usage
Download specific python script you need to in the scripting development environment of Ghidra and run it on a decompiled item within a project in Ghidra
