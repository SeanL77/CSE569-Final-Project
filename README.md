# Automated Vulnerability Discovery in CPS Firmware Using Ghidra

## Overview

This project presents a set of tools and scripts built on [Ghidra](https://ghidra-sre.org/), to automate the static analysis of CPS firmware binaries. Our goal is to assist developers and analysts in identifying potential security risks early in the firmware lifecycle and to encourage the integration of cybersecurity considerations from the ground up in CPS design.


## Features

- **Modular Ghidra Scripts**: Automate static binary analysis to identify potential vulnerabilities using scripted control flow and data flow analysis.
- **Risk Visualization**: Generates call graphs and risk reports that highlight vulnerable regions in the firmware and their relation to core functionality.


## Usage
Run the specific python script you need to in the scripting development environment of Ghidra


## References

[1] Lopez-Morales, Efren, et al. “SoK: Security of Programmable Logic Controllers.” *33rd USENIX Security Symposium (USENIX Security 24)*, 2024.

[2] Rhabdomancer Ghidra Script. [https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java](https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java)

[3] Haruspex Ghidra Script. [https://github.com/0xdea/ghidra-scripts/blob/main/Haruspex.java](https://github.com/0xdea/ghidra-scripts/blob/main/Haruspex.java)

[4] Binary Ninja. [https://binary.ninja](https://binary.ninja/)

[5] Harkat, H., Camarinha-Matos, L. M., Goes, J., & Ahmed, H. F. T. “Cyber-Physical Systems Security: A Systematic Review.” *Computers & Industrial Engineering*, 2024. 
[https://doi.org/10.1016/j.cie.2024.109891](https://doi.org/10.1016/j.cie.2024.109891)

[6] National Security Agency. “Four Years Later: The Impacts of Ghidra’s Public Release.” [https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3319971/four-years-later-the-impacts-of-ghidras-public-release](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3319971/four-years-later-the-impacts-of-ghidras-public-release/)

[7] Zerof, Nik. “Ghidra vs. IDA Pro: Strengths and Weaknesses of NSA’s Free Reverse Engineering Toolkit.” *HackMag*. [https://hackmag.com/security/nsa-ghidra](https://hackmag.com/security/nsa-ghidra/)

[8] Tyagi, A. K., & Sreenath, N. “Cyber Physical Systems: Analyses, Challenges and Possible Solutions.” *Internet of Things and Cyber-Physical Systems*, vol. 1, 2021, pp. 22–33. [https://doi.org/10.1016/j.iotcps.2021.12.002](https://doi.org/10.1016/j.iotcps.2021.12.002)

[9] Home Assistant Official Website. [https://www.home-assistant.io](https://www.home-assistant.io)

[10] Home Assistant GitHub Repository. [https://github.com/home-assistant/core](https://github.com/home-assistant/core)

[11] Home Assistant `data_entry_flow.py` Source Code. [https://github.com/home-assistant/core/blob/dev/homeassistant/data_entry_flow.py](https://github.com/home-assistant/core/blob/dev/homeassistant/data_entry_flow.py)

[12] Home Assistant `core_config.py` Source Code. [https://github.com/home-assistant/core/blob/dev/homeassistant/core_config.py](https://github.com/home-assistant/core/blob/dev/homeassistant/core_config.py)

[13] GptHidra – Ghidra Plugin with GPT Integration. [https://github.com/evyatar9/GptHidra](https://github.com/evyatar9/GptHidra)

[14] reai-ghidra – Reverse Engineering AI Plugin for Ghidra. [https://github.com/RevEngAI/reai-ghidra](https://github.com/RevEngAI/reai-ghidra)

