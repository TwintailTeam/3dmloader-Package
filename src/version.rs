use crate::util::wait_exit;
use std::ffi::CString;
use windows::Win32::Storage::FileSystem::{GetFileVersionInfoA, GetFileVersionInfoSizeA, VerQueryValueA, VS_FIXEDFILEINFO};
use windows::core::PCSTR;

#[repr(C)]
struct LangCodePage {
    language: u16,
    code_page: u16,
}

fn has_3dmigoto_description(data: &[u8], module_path: &str) -> bool {
    let query = CString::new("\\VarFileInfo\\Translation").unwrap();
    let mut ptr: *mut LangCodePage = std::ptr::null_mut();
    let mut size: u32 = 0;

    let ok = unsafe { VerQueryValueA(data.as_ptr().cast(), PCSTR(query.as_ptr().cast()), std::ptr::addr_of_mut!(ptr).cast(), &mut size) };
    if !ok.as_bool() { wait_exit("3DMigoto file information query failed"); }

    let count = size as usize / std::mem::size_of::<LangCodePage>();
    for i in 0..count {
        let lc = unsafe { &*ptr.add(i) };
        let sub = CString::new(format!("\\StringFileInfo\\{:04x}{:04x}\\FileDescription", lc.language, lc.code_page)).unwrap();
        let mut desc_ptr: *mut u8 = std::ptr::null_mut();
        let mut desc_size: u32 = 0;

        let ok = unsafe { VerQueryValueA(data.as_ptr().cast(), PCSTR(sub.as_ptr().cast()), std::ptr::addr_of_mut!(desc_ptr).cast(), &mut desc_size) };
        if !ok.as_bool() { continue; }

        let bytes = unsafe { std::slice::from_raw_parts(desc_ptr, desc_size as usize) };
        let desc = std::str::from_utf8(bytes).unwrap_or("").trim_end_matches('\0');
        println!("{} description: \"{}\"", module_path, desc);
        if desc.starts_with("3Dmigoto") { return true; }
    }
    false
}

pub fn check_3dmigoto_version(module_path: &str) {
    let path_c = CString::new(module_path).expect("module path contains null byte");
    let pcstr = PCSTR(path_c.as_ptr().cast());

    let size = unsafe { GetFileVersionInfoSizeA(pcstr, Some(std::ptr::null_mut())) };
    if size == 0 { wait_exit("3DMigoto version size check failed"); }

    let mut data = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoA(pcstr, 0, size, data.as_mut_ptr().cast()) }.is_err() { wait_exit("3DMigoto version info check failed"); }
    if !has_3dmigoto_description(&data, module_path) { wait_exit(&format!("ERROR: \"{}\" is not 3DMigoto. Ensure LOADER_MODULE is set correctly.", module_path)); }

    let mut info: *mut VS_FIXEDFILEINFO = std::ptr::null_mut();
    let mut info_size: u32 = 0;
    let root = CString::new("\\").unwrap();
    if !unsafe { VerQueryValueA(data.as_ptr().cast(), PCSTR(root.as_ptr().cast()), std::ptr::addr_of_mut!(info).cast(), &mut info_size) }.as_bool() { wait_exit("3DMigoto version query check failed"); }

    let fi = unsafe { &*info };
    println!("3DMigoto Version {}.{}.{}", fi.dwProductVersionMS >> 16, fi.dwProductVersionMS & 0xffff, fi.dwProductVersionLS >> 16);

    let too_old = fi.dwProductVersionMS < 0x0001_0003 || (fi.dwProductVersionMS == 0x0001_0003 && fi.dwProductVersionLS < 0x000f_0000);
    if too_old { wait_exit("This version of 3DMigoto is too old to be safely loaded - please use 1.3.15 or later", ); }
}
