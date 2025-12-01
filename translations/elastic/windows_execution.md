# Windows Execution — Elastic EQL / KQL notes

PowerShell Encoded Command Execution:
```
process where process.name in ("powershell.exe", "pwsh.exe") and
process.command_line : ("* -e *", "* -enc *", "* -encodedcommand *")
```
caveats: Use process.command_line; ensure endpoint security integration populates it. Filter known deployment parents.

Mshta JavaScript or VBScript Execution:
```
process where process.name == "mshta.exe" and
process.command_line : ("*javascript:*", "*vbscript:*", "*.hta*")
```
caveats: Parent process context improves fidelity.
