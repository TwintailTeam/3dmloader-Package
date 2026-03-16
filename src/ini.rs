pub fn find_section<'a>(content: &'a str, section: &str) -> Option<&'a str> {
    let needle = format!("[{}]", section);
    let lower = content.to_ascii_lowercase();
    let pos = lower.find(needle.to_ascii_lowercase().as_str())?;
    let rest = &content[pos + needle.len()..];
    let newline = rest.find('\n').map(|i| i + 1).unwrap_or(rest.len());
    Some(&rest[newline..])
}

pub fn find_setting<'a>(section: &'a str, key: &str) -> Option<&'a str> {
    for line in section.lines() {
        let line = line.trim();
        if line.starts_with('[') { return None; }
        if line.starts_with(';') || line.starts_with('#') || line.is_empty() { continue; }
        if let Some(eq) = line.find('=') {
            if line[..eq].trim().eq_ignore_ascii_case(key) {
                let val = line[eq + 1..].trim();
                return Some(val.split(';').next().unwrap_or("").trim());
            }
        }
    }
    None
}

pub fn find_bool(section: &str, key: &str, default: bool) -> bool {
    match find_setting(section, key) {
        None => default,
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
    }
}

pub fn find_int(section: &str, key: &str, default: i32) -> i32 {
    find_setting(section, key).and_then(|v| v.parse().ok()).unwrap_or(default)
}
