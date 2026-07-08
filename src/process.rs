use crate::util::{to_wide, wait_exit};
use std::collections::HashSet;
use std::io::Write;
use windows::Win32::Foundation::{CloseHandle, ERROR_BAD_LENGTH, HANDLE, HMODULE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx};
use windows::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, Sleep, CreateRemoteThread, WaitForSingleObject, GetExitCodeThread, OpenProcessToken, GetCurrentProcess};
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{SW_SHOWNORMAL};

fn wstr_to_string(slice: &[u16]) -> String {
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    String::from_utf16_lossy(&slice[..end])
}

pub fn elevate_if_needed(mipath: &str) {
    let mut token: HANDLE = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() { return; }

    let mut elevation = TOKEN_ELEVATION::default();
    let mut ret_len: u32 = 0;
    let ok = unsafe { GetTokenInformation(token, TokenElevation, Some(std::ptr::addr_of_mut!(elevation).cast()), size_of::<TOKEN_ELEVATION>() as u32, &mut ret_len) };
    unsafe { let _ = windows::Win32::Foundation::CloseHandle(token); };
    if ok.is_err() { return; }
    if elevation.TokenIsElevated != 0 { return; }

    let mut path = vec![0u16; 260];
    let len = unsafe { GetModuleFileNameW(HMODULE::default(), &mut path) };
    if len == 0 { return; }

    unsafe { let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE); }
    let runas = to_wide("runas");
    let mipath_wide = to_wide(mipath);
    let params_pcwstr = if mipath.is_empty() { PCWSTR::null() } else { PCWSTR(mipath_wide.as_ptr()) };
    let rc = unsafe { ShellExecuteW(None, PCWSTR(runas.as_ptr()), PCWSTR(path.as_ptr()), params_pcwstr, PCWSTR::null(), SW_SHOWNORMAL) };

    if rc.0 as isize > 32 { std::process::exit(0); }
    if rc.0 as isize == 5 { wait_exit("Unable to run as admin: Access Denied"); }
    wait_exit(&format!("Unable to run as admin: {:p}", rc.0));
}

fn verify_injection(pe: &PROCESSENTRY32W, module: &str, log_name: bool, injected_pids: &mut HashSet<u32>) -> bool {
    let module_norm = module.to_ascii_lowercase();
    let basename_start = module.rfind('\\').map(|i| i + 1).unwrap_or(0);
    let target_basename = module[basename_start..].to_ascii_lowercase();

    let snapshot = loop {
        let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID) };
        match h {
            Ok(h) if h != INVALID_HANDLE_VALUE => break h,
            _ => {
                let err = unsafe { windows::Win32::Foundation::GetLastError() };
                if err != ERROR_BAD_LENGTH {
                    let exe = wstr_to_string(&pe.szExeFile);
                    println!("{} ({}): Unable to verify if 3DMigoto was successfully loaded: {:?}", exe, pe.th32ProcessID, err);
                    return false;
                }
            }
        }
    };

    let mut me: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    me.dwSize = size_of::<MODULEENTRY32W>() as u32;

    if unsafe { Module32FirstW(snapshot, &mut me) }.is_err() {
        let exe = wstr_to_string(&pe.szExeFile);
        println!("{} ({}): Unable to verify if 3DMigoto was successfully loaded", exe, pe.th32ProcessID);
        unsafe { let _ = CloseHandle(snapshot); };
        return false;
    }

    if log_name {
        let exe_path = wstr_to_string(&me.szExePath);
        println!("Target process found ({}): {}", pe.th32ProcessID, exe_path);
    }

    let exe_dir = {
        let p = wstr_to_string(&me.szExePath).to_ascii_lowercase();
        match p.rfind('\\') { Some(i) => p[..=i].to_string(), None => p, }
    };

    let mut rc = false;
    while unsafe { Module32NextW(snapshot, &mut me) }.is_ok() {
        let mod_name = wstr_to_string(&me.szModule).to_ascii_lowercase();
        if mod_name != target_basename { continue; }

        let mod_path = wstr_to_string(&me.szExePath).to_ascii_lowercase();
        if mod_path == module_norm {
            if !injected_pids.contains(&pe.th32ProcessID) {
                println!("{}: 3DMigoto loaded :)", pe.th32ProcessID);
                injected_pids.insert(pe.th32ProcessID);
            }
            rc = true;
        } else {
            let mod_dir = match mod_path.rfind('\\') {
                Some(i) => mod_path[..=i].to_string(),
                None => mod_path.clone(),
            };
            if mod_dir == exe_dir { wait_exit(&format!("\n\n\nWARNING: Found a second copy of 3DMigoto loaded from the game directory:\n{}\nThis may crash - please remove the copy in the game directory and try again\n\n\n", wstr_to_string(&me.szExePath))); }
        }
    }
    unsafe { let _ = CloseHandle(snapshot); };
    rc
}

fn check_for_running_target(target: &str, module: &str, seen_pids: &mut HashSet<u32>, injected_pids: &mut HashSet<u32>) -> bool {
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) => h,
        Err(_) => {
            println!("Unable to take process snapshot");
            return false;
        }
    };

    let basename_start = target.rfind('\\').map(|i| i + 1).unwrap_or(0);
    let target_basename = target[basename_start..].to_ascii_lowercase();
    let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    if unsafe { Process32FirstW(snapshot, &mut pe) }.is_err() { unsafe { let _ = CloseHandle(snapshot); }; return false; }

    let mut rc = false;
    loop {
        let exe_name = wstr_to_string(&pe.szExeFile).to_ascii_lowercase();
        if exe_name == target_basename {
            let log_name = !seen_pids.contains(&pe.th32ProcessID);
            rc = verify_injection(&pe, module, log_name, injected_pids) || rc;
            seen_pids.insert(pe.th32ProcessID);
        }
        if unsafe { Process32NextW(snapshot, &mut pe) }.is_err() { break; }
    }
    unsafe { let _ = CloseHandle(snapshot); };
    rc
}

fn inject_dll(pid: u32, dll_path: &str) -> bool {
    let dll_wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_size = dll_wide.len() * 2;
    let access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    let proc = match unsafe { OpenProcess(access, false, pid) } {
        Ok(h) => h,
        Err(e) => { println!("{pid}: OpenProcess failed: {e}"); return false; }
    };
    let dll_path_wide = to_wide(dll_path);
    if unsafe { GetFileAttributesW(PCWSTR(dll_path_wide.as_ptr())) } == INVALID_FILE_ATTRIBUTES {
        unsafe { let _ = CloseHandle(proc); }
        println!("{pid}: DLL path not accessible: \"{}\"", dll_path);
        return false;
    }
    let load_lib = {
        let kernel32 = match unsafe { GetModuleHandleW(PCWSTR(to_wide("kernel32.dll").as_ptr())) } {
            Ok(h) => h,
            Err(e) => { unsafe { let _ = CloseHandle(proc); } println!("{pid}: GetModuleHandleW(kernel32) failed: {e}"); return false; }
        };
        match unsafe { GetProcAddress(kernel32, PCSTR(b"LoadLibraryW\0".as_ptr())) } {
            Some(f) => f,
            None => { unsafe { let _ = CloseHandle(proc); } println!("{pid}: GetProcAddress(LoadLibraryW) failed"); return false; }
        }
    };
    let remote_mem = unsafe { VirtualAllocEx(proc, None, byte_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    if remote_mem.is_null() {
        let e = unsafe { windows::Win32::Foundation::GetLastError() };
        unsafe { let _ = CloseHandle(proc); }
        println!("{pid}: VirtualAllocEx failed: {e:?}");
        return false;
    }
    if unsafe { WriteProcessMemory(proc, remote_mem, dll_wide.as_ptr().cast(), byte_size, None) }.is_err() {
        unsafe { VirtualFreeEx(proc, remote_mem, 0, MEM_RELEASE).ok(); }
        unsafe { let _ = CloseHandle(proc); }
        println!("{pid}: WriteProcessMemory failed");
        return false;
    }
    let thread = match unsafe { CreateRemoteThread(proc, None, 0, Some(std::mem::transmute(load_lib)), Some(remote_mem as *const _), 0, None) } {
        Ok(t) => t,
        Err(e) => {
            unsafe { VirtualFreeEx(proc, remote_mem, 0, MEM_RELEASE).ok(); }
            unsafe { let _ = CloseHandle(proc); }
            println!("{pid}: CreateRemoteThread failed: {e}");
            return false;
        }
    };
    let wait = unsafe { WaitForSingleObject(thread, 15000) };
    let mut loaded = false;
    if wait == WAIT_OBJECT_0 {
        let mut exit_code = 0u32;
        if unsafe { GetExitCodeThread(thread, &mut exit_code) }.is_ok() && exit_code != 0 { loaded = true; } else { println!("{pid}: LoadLibraryW returned NULL (injection failed)"); }
    } else if wait == WAIT_TIMEOUT { println!("{pid}: Injection thread timed out (15s)"); } else { println!("{pid}: WaitForSingleObject failed (WAIT_FAILED)"); }
    unsafe { let _ = CloseHandle(thread); };
    unsafe { VirtualFreeEx(proc, remote_mem, 0, MEM_RELEASE).ok(); }
    unsafe { let _ = CloseHandle(proc); }
    loaded
}

fn scan_and_inject(target: &str, module_path: &str, injected_pids: &mut HashSet<u32>, printed_pids: &mut HashSet<u32>) -> bool {
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } { Ok(h) => h, Err(_) => return false};
    let basename_start = target.rfind('\\').map(|i| i + 1).unwrap_or(0);
    let target_basename = target[basename_start..].to_ascii_lowercase();
    let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snapshot, &mut pe) }.is_err() { unsafe { let _ = CloseHandle(snapshot); } return false; }
    let mut rc = false;
    loop {
        let exe_name = wstr_to_string(&pe.szExeFile).to_ascii_lowercase();
        if exe_name == target_basename {
            let pid = pe.th32ProcessID;
            if injected_pids.contains(&pid) {
                rc = true;
            } else {
                if printed_pids.insert(pid) { println!("Target process found ({pid})"); }
                if inject_dll(pid, module_path) {
                    println!("{pid}: 3DMigoto injected :)");
                    injected_pids.insert(pid);
                    rc = true;
                }
            }
        }
        if unsafe { Process32NextW(snapshot, &mut pe) }.is_err() { break; }
    }
    unsafe { let _ = CloseHandle(snapshot); }
    rc
}

pub fn wait_for_target_inject(target: &str, module_path: &str, wait: bool, delay: i32) {
    let mut injected_pids: HashSet<u32> = HashSet::new();
    let mut printed_pids: HashSet<u32> = HashSet::new();

    while wait || delay == -1 {
        if scan_and_inject(target, module_path, &mut injected_pids, &mut printed_pids) && delay != -1 { break; }
        unsafe { Sleep(100) };
    }

    for i in (1..=delay).rev() {
        print!("Shutting down loader in {}...\r", i);
        std::io::stdout().flush().ok();
        unsafe { Sleep(1000) };
        scan_and_inject(target, module_path, &mut injected_pids, &mut printed_pids);
    }
}

pub fn wait_for_target(target: &str, module_path: &str, wait: bool, delay: i32) {
    let mut seen_pids: HashSet<u32> = HashSet::new();
    let mut injected_pids: HashSet<u32> = HashSet::new();

    while wait || delay == -1 {
        if check_for_running_target(target, module_path, &mut seen_pids, &mut injected_pids) && delay != -1 { break; }
        unsafe { Sleep(1000) };
    }

    for i in (1..=delay).rev() {
        print!("Shutting down loader in {}...\r", i);
        std::io::stdout().flush().ok();
        unsafe { Sleep(1000) };
        check_for_running_target(target, module_path, &mut seen_pids, &mut injected_pids);
    }
}
