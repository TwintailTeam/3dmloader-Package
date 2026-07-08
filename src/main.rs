#![windows_subsystem = "windows"]

mod ini;
mod process;
mod util;

use windows::Win32::Foundation::{HINSTANCE, HMODULE};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Threading::{CreateMutexA, GetCurrentThread, SetThreadDescription};
use windows::Win32::UI::WindowsAndMessaging::{SetWindowsHookExW, UnhookWindowsHookEx, HOOKPROC, WINDOWS_HOOK_ID, WH_CBT};
use windows::core::{PCSTR, PCWSTR};

fn main() {
    let thread_name: Vec<u16> = "3dmloader.exe\0".encode_utf16().collect();
    unsafe { let _ = SetThreadDescription(GetCurrentThread(), PCWSTR(thread_name.as_ptr())); }
    let mutex_name = std::ffi::CString::new("Local\\3DMigotoLoader").unwrap();
    let _ = unsafe { CreateMutexA(None, false, PCSTR(mutex_name.as_ptr().cast())) };
    if unsafe { windows::Win32::Foundation::GetLastError() } == windows::Win32::Foundation::ERROR_ALREADY_EXISTS { util::wait_exit("ERROR: Another instance of the 3DMigoto Loader is already running. Please close it and try again"); }

    println!("\n------------------------------- 3DMigoto Loader ------------------------------\n");

    let mipath: String = std::env::args().nth(1).unwrap_or_default();
    let ini_path = if mipath.is_empty() { "d3dx.ini".to_string() } else { format!("{}\\d3dx.ini", mipath) };

    let ini_content = std::fs::read_to_string(&ini_path).unwrap_or_else(|_| util::wait_exit("Unable to open d3dx.ini"));
    let section = ini::find_section(&ini_content, "Loader").unwrap_or_else(|| util::wait_exit("d3dx.ini missing [Loader] section"));
    let target = ini::find_setting(section, "target").unwrap_or_else(|| util::wait_exit("d3dx.ini [Loader] missing required \"target\" setting")).to_string();
    let module_name = ini::find_setting(section, "module").unwrap_or_else(|| util::wait_exit("d3dx.ini [Loader] missing required \"module\" setting")).to_string();
    let module_path = if mipath.is_empty() { module_name } else { format!("{}\\{}", mipath, module_name) };

    let check_ver = ini::find_bool(section, "check_version", true);
    let require_admin = ini::find_bool(section, "require_admin", false);
    let entry_point = ini::find_setting(section, "entry_point").unwrap_or("CBTProc").to_string();
    let hook_proc_id = ini::find_int(section, "hook_proc", WH_CBT.0);
    let do_wait = ini::find_bool(section, "wait_for_target", true);
    let delay = ini::find_int(section, "delay", 0);

    let loader_mode = std::env::var("LOADER_MODE").unwrap_or_default();
    let use_inject = loader_mode.eq_ignore_ascii_case("inject");

    if check_ver { util::check_3dmigoto_version(&module_path); }
    if require_admin { process::elevate_if_needed(&mipath); }

    let module_cstr = std::ffi::CString::new(module_path.as_str()).unwrap();
    let module: HMODULE = unsafe { LoadLibraryA(PCSTR(module_cstr.as_ptr().cast())) }.unwrap_or_else(|_| util::wait_exit(&format!("Unable to load \"{}\"", module_path)));

    let mut full_path_buf = vec![0u16; 260];
    let full_len = unsafe { GetModuleFileNameW(module, &mut full_path_buf) };
    let module_full_path = String::from_utf16_lossy(&full_path_buf[..full_len as usize]).to_string();
    println!("Loaded {}\n", module_full_path);

    if use_inject {
        println!("3DMigoto ready!");
        process::wait_for_target_inject(&target, &module_full_path, do_wait, delay);
    } else {
        let ep_cstr = std::ffi::CString::new(entry_point.as_str()).unwrap();
        let fn_raw = unsafe { GetProcAddress(module, PCSTR(ep_cstr.as_ptr().cast())) }.unwrap_or_else(|| util::wait_exit("Module does not support injection method\nMake sure this is a recent 3DMigoto d3d11.dll"));
        let hookproc: HOOKPROC = Some(unsafe { std::mem::transmute(fn_raw) });
        let hook = unsafe { SetWindowsHookExW(WINDOWS_HOOK_ID(hook_proc_id), hookproc, HINSTANCE(module.0), 0) }.unwrap_or_else(|_| util::wait_exit("Error installing hook"));

        println!("3DMigoto ready!");
        process::wait_for_target(&target, &module_full_path, do_wait, delay);
        unsafe { let _ = UnhookWindowsHookEx(hook); };
    }
}
