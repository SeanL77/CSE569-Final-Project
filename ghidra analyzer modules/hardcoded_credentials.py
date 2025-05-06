#!/usr/bin/env python

from ghidra.program.model.data import StringDataInstance
import re


DEFAULT_PATTERNS = [
    "admin", "password", "passwd", "pwd", "secret", "key", 
    "credential", "token", "auth", "apikey", "api_key",
    "root", "login", "user"
]


# look for hardcoded credentials in strings
def scan_for_hardcoded_strings(program=None, script=None):
    findings = []
    
    if program is None:
        program = currentProgram
    
    # get patterns from config file
    patterns = DEFAULT_PATTERNS
    if script and hasattr(script, 'config') and 'credential_settings' in script.config:
        patterns = script.config['credential_settings']['patterns']
    
    # get strings from program
    strings = program.getStringTable().getAllStrings()
    
    for s in strings:
        string_val = s.getString(True)
        string_addr = s.getAddress()
        
        # look for credential-like patterns
        for pattern in patterns:
            if pattern.lower() in string_val.lower():
                contains_credential_pattern = (
                    re.search(r"[\"']?\w+[\"']?\s*[:=]\s*[\"'].+[\"']", string_val) or
                    re.search(r"password\s*[:=]", string_val.lower()) or
                    re.search(r"user\w*\s*[:=]", string_val.lower())
                )
                
                severity = "high" if contains_credential_pattern else "medium"
                
                finding = {
                    "type": "hardcoded_credential",
                    "string": string_val,
                    "address": str(string_addr),
                    "pattern": pattern,
                    "description": "potential hardcoded credential: '{}' at {}".format(string_val, string_addr),
                    "severity": severity
                }
                findings.append(finding)

                if script:
                    script.println("[!] potential hardcoded credential: '{}' at {}".format(string_val, string_addr))
                break
    
    # look for certificate / key file content patterns
    cert_patterns = [
        "-----BEGIN", "PRIVATE KEY", "CERTIFICATE", "RSA PRIVATE",
        "ssh-rsa", "ssh-dss", "OPENSSH"
    ]
    
    for s in strings:
        string_val = s.getString(True)
        string_addr = s.getAddress()
        
        for cert_pattern in cert_patterns:
            if cert_pattern in string_val:
                finding = {
                    "type": "hardcoded_key",
                    "string": string_val[:50] + "..." if len(string_val) > 50 else string_val,
                    "address": str(string_addr),
                    "pattern": cert_pattern,
                    "description": "potential hardcoded key / certificate at {}".format(string_addr),
                    "severity": "critical"
                }
                findings.append(finding)

                if script:
                    script.println("[!!!] potential hardcoded key / certificate at {}".format(string_addr))
                break

    # look for JWT token patterns
    jwt_pattern = r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
    
    for s in strings:
        string_val = s.getString(True)
        string_addr = s.getAddress()
        
        if re.search(jwt_pattern, string_val):
            finding = {
                "type": "hardcoded_jwt",
                "string": string_val[:50] + "..." if len(string_val) > 50 else string_val,
                "address": str(string_addr),
                "pattern": "JWT",
                "description": "potential hardcoded JWT token at {}".format(string_addr),
                "severity": "high"
            }
            findings.append(finding)

            if script:
                script.println("[!] potential hardcoded JWT token at {}".format(string_addr))
    
    return findings


if __name__ == "__main__":
    findings = scan_for_hardcoded_strings()
    print("found {} potential hardcoded credentials".format(len(findings)))
