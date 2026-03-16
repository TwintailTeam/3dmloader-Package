use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONERROR};
use windows::core::PCWSTR;

pub fn wait_exit(msg: &str) -> ! {
    if !msg.is_empty() {
        let title: Vec<u16> = "3DMigoto Loader\0".encode_utf16().collect();
        let text: Vec<u16> = format!("{}\0", msg).encode_utf16().collect();
        unsafe { MessageBoxW(None, PCWSTR(text.as_ptr()), PCWSTR(title.as_ptr()), MB_OK | MB_ICONERROR); }
    }
    std::process::exit(1)
}

pub fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
