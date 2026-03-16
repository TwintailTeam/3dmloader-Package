#![windows_subsystem = "windows"]

mod ini;
mod process;
mod util;
mod version;

use util::{to_wide, wait_exit};
use windows::Win32::Foundation::{HANDLE, HINSTANCE, HMODULE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Threading::{CreateMutexA, GetCurrentProcess, GetCurrentThread, OpenProcessToken, SetThreadDescription};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{SetWindowsHookExW, UnhookWindowsHookEx, HOOKPROC, SW_SHOWNORMAL, WINDOWS_HOOK_ID, WH_CBT};
use windows::core::{PCSTR, PCWSTR};

use std::ffi::CString;

fn elevate_if_needed(mipath: &str) {
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

fn main() {
    let thread_name: Vec<u16> = "3dmloader.exe\0".encode_utf16().collect();
    unsafe { let _ = SetThreadDescription(GetCurrentThread(), PCWSTR(thread_name.as_ptr())); }
    let mutex_name = CString::new("Local\\3DMigotoLoader").unwrap();
    let _ = unsafe { CreateMutexA(None, false, PCSTR(mutex_name.as_ptr().cast())) };
    if unsafe { windows::Win32::Foundation::GetLastError() } == windows::Win32::Foundation::ERROR_ALREADY_EXISTS { wait_exit("ERROR: Another instance of the 3DMigoto Loader is already running. Please close it and try again"); }

    println!("\n------------------------------- 3DMigoto Loader ------------------------------\n");

    let mipath: String = std::env::args().nth(1).unwrap_or_default();
    let ini_path = if mipath.is_empty() { "d3dx.ini".to_string() } else { format!("{}\\d3dx.ini", mipath) };

    let ini_content = std::fs::read_to_string(&ini_path).unwrap_or_else(|_| wait_exit("Unable to open d3dx.ini"));
    let section = ini::find_section(&ini_content, "Loader").unwrap_or_else(|| wait_exit("d3dx.ini missing [Loader] section"));
    let target = ini::find_setting(section, "target").unwrap_or_else(|| wait_exit("d3dx.ini [Loader] missing required \"target\" setting")).to_string();
    let module_name = ini::find_setting(section, "module").unwrap_or_else(|| wait_exit("d3dx.ini [Loader] missing required \"module\" setting")).to_string();
    let module_path = if mipath.is_empty() { module_name } else { format!("{}\\{}", mipath, module_name) };

    let check_ver = ini::find_bool(section, "check_version", true);
    let require_admin = ini::find_bool(section, "require_admin", false);
    let entry_point = ini::find_setting(section, "entry_point").unwrap_or("CBTProc").to_string();
    let hook_proc_id = ini::find_int(section, "hook_proc", WH_CBT.0);
    let do_wait = ini::find_bool(section, "wait_for_target", true);
    let delay = ini::find_int(section, "delay", 0);

    let loader_mode = std::env::var("LOADER_MODE").unwrap_or_default();
    let use_inject = loader_mode.eq_ignore_ascii_case("inject");

    if check_ver { version::check_3dmigoto_version(&module_path); }
    if require_admin { elevate_if_needed(&mipath); }

    let module_cstr = CString::new(module_path.as_str()).unwrap();
    let module: HMODULE = unsafe { LoadLibraryA(PCSTR(module_cstr.as_ptr().cast())) }.unwrap_or_else(|_| wait_exit(&format!("Unable to load \"{}\"", module_path)));

    let mut full_path_buf = vec![0u16; 260];
    let full_len = unsafe { GetModuleFileNameW(module, &mut full_path_buf) };
    let module_full_path = String::from_utf16_lossy(&full_path_buf[..full_len as usize]).to_string();
    println!("Loaded {}\n", module_full_path);

    if use_inject {
        println!("3DMigoto ready!");
        process::wait_for_target_inject(&target, &module_full_path, do_wait, delay);
    } else {
        let ep_cstr = CString::new(entry_point.as_str()).unwrap();
        let fn_raw = unsafe { GetProcAddress(module, PCSTR(ep_cstr.as_ptr().cast())) }.unwrap_or_else(|| wait_exit("Module does not support injection method\nMake sure this is a recent 3DMigoto d3d11.dll"));
        let hookproc: HOOKPROC = Some(unsafe { std::mem::transmute(fn_raw) });
        let hook = unsafe { SetWindowsHookExW(WINDOWS_HOOK_ID(hook_proc_id), hookproc, HINSTANCE(module.0), 0) }.unwrap_or_else(|_| wait_exit("Error installing hook"));

        println!("3DMigoto ready!");
        process::wait_for_target(&target, &module_full_path, do_wait, delay);
        unsafe { let _ = UnhookWindowsHookEx(hook); };
    }
}
