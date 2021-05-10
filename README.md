# memexec

### Build Instructions
- Open '.sln' project with Visual Studio and Build.
*Release builds can be downloaded directly also*

### Examples
**Help**
`memexec.exe -h`
**Execute EXE in memory**
`memexec.exe -v -f c:\\windows\\system32\\calc.exe`
**Execute EXE in memory and save shellcode in output file**
`memexec.exe -o out.bin -f c:\\windows\\system32\\calc.exe`
**Execute shellcode**
`memexec.exe -v -s out.bin`
**Execute shellcode hosted via HTTP**
`memexec.exe -v -u http://localhost:8081/out.bin`

### TO-DO

- Add more IOC metrics for CDM.
- Ability to accept encoded shellcode (b64/zip)
