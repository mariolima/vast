# vast

Shellcode loader using Freeze for NTDLL unhooking and EarlyBird APC Queue for shellcode execution. The new process gets then unhooked by remotely overwritting its old NTDLL .text section (_Frozen regression_).

```mermaid
sequenceDiagram
autonumber
participant V as Vast
participant T as Windows Signed PE
V->>T: Create suspended process with <br>BLOCK_NON_MICROSOFT_BINARIES
opt Freeze unhooking flow
V-->>+V: PEB walk and get NTDLL .text address
T->>V: Get remote NTDLL .text section
V-->>-V: Overwrite local NTDLL .text section<br>Patch ETW (NtTraceControl)
end
V-->>T: Allocate & Protect remote memory
V->>T: QueueApc Thread + NtResumeThread
note over T: Shellcode gets executed
V->>T: Overwrite remote  NTDLL .text section<br>with unhooked one
note right of T: New process hooks<br>get unhooked now
```
