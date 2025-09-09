#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::{cmp::Ordering, fs::OpenOptions, io::{self, Write}, path::{Component, PathBuf}, ptr};
use data::{FileData, FileRecordSegmentHeader, SetFilePointerEx, KERNEL32_ADDR, OUTPUT_FILE, STARTING_OFFSET, UPCASE};
use regex_lite::{escape, Regex};
use windows::Win32::Foundation::HANDLE;

pub fn parse_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in input.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

pub fn print_help() {
    let help_text = lc!(r#"
Available commands:

    · read_file c:\windows\system32\config SAM c:\windows\temp\SAM
    · read_by_index 12871 c:\windows\temp\SAM
    · ls c:\windows\system32\config
    · show c:\windows\system32 ntdll.dll
    · show_by_regex /someregex/ [hidden] [verbose]
    · show_by_index 1251
    · show_hidden
    · set_target \\.\C:
    · rebuild
    · output C:\Path\To\Output.txt ('none' to disable it)
    · help
    "#);

    println!("{}", help_text);
}

pub fn build_regex_matcher(user_input: &str) -> Result<Regex, regex_lite::Error> {
    let pattern = if user_input.starts_with('/') && user_input.ends_with('/') && user_input.len() > 2 {
        &user_input[1..user_input.len() - 1]
    } else {
        let escaped = escape(user_input);
        return Regex::new(&format!("^{}$", escaped));
    };

    Regex::new(pattern)
}

pub fn assign_name(fd: &mut FileData, namespace: u8, name: String) {
    if !fd.all_names.contains(&name) {
        fd.all_names.push(name.clone());
    }
    
    match namespace {
        0 => fd.posix_names.push(name),
        1 => fd.win32_names.push(name),
        2 => fd.short_names.push(name),
        3 => {
            fd.win32_names.push(name.clone());
            fd.short_names.push(name);
        }
        _ => {}
    }
}

pub fn utf16_ptr_to_string(ptr: &[u16], length: usize) -> Option<String> 
{
    if length <= 0 {
        return None;
    }

    let trimmed = &ptr[..length];

    String::from_utf16(trimmed).ok()
}

pub fn resolve_relative_path(current_path: &str, relative_target: &str) -> String {
    let base_path = PathBuf::from(current_path)
        .parent() 
        .unwrap()
        .to_path_buf();

    let mut result_path = base_path;

    for component in PathBuf::from(relative_target).components() {
        match component {
            Component::ParentDir => {
                result_path.pop();
            }
            Component::Normal(c) => {
                result_path.push(c);
            }
            _ => {}
        }
    }

    result_path.display().to_string()
}

pub fn handle_strings(strs: &Vec<String>) -> io::Result<()> {

    let path = {
        let guard = OUTPUT_FILE.read().expect("none");
        guard.clone()
    };

    if path == "none" {
        print_strings(strs);
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    for s in strs {
        file.write_all(s.as_bytes())?;
    }

    file.flush()?;
    Ok(())
}

pub fn print_strings(strs: &Vec<String>) {
    for s in strs {
        print!("{}", s);
    }
}

pub unsafe fn set_file_pointer_ex_file_begin(offset: i64, handle: HANDLE) -> bool
{
    let function_ptr: SetFilePointerEx;
    let ret_value: Option<bool>;
    let total_offset = STARTING_OFFSET + offset;
    dinvoke_rs::dinvoke::dynamic_invoke!(
        KERNEL32_ADDR,
        &lc!("SetFilePointerEx"),
        function_ptr,
        ret_value,
        handle,
        total_offset,
        ptr::null_mut(),
        0 // FILE_BEGIN
    );

    if ret_value.is_some() {
        ret_value.unwrap()
    } else {
        false
    }
}

/// Converts a utf16 char using the UPCASE table.
/// If no conversion is possible, it returns the same char
fn to_upper(ch: u16) -> u16 {
    let table = UPCASE.read().unwrap();
    if (ch as usize) < table.len() {
        table[ch as usize]
    } else {
        ch
    }
}

/// Compare two NTFS names in a case-insensitive manner using $UpCase.
///
/// Returns:
/// - `Ordering::Less` if `a` < `b`
/// - `Ordering::Equal` if `a` == `b`
/// - `Ordering::Greater` if `a` > `b`
pub fn compare_ntfs_names(a: &[u16], b: &[u16]) -> Ordering {
    let iter_a = a.iter().map(|&ch| to_upper(ch));
    let iter_b = b.iter().map(|&ch| to_upper(ch));

    iter_a.cmp(iter_b)
}

pub unsafe fn is_hidden(mft_entry: &Vec<u8>) -> bool {

    let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;
    let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
    if signature_str == lc!("FILE") &&  (*file_record_segment_header).flags & 0x1 == 0 {
        return true;
    }

    false
}

pub unsafe fn is_directory(mft_entry: &Vec<u8>) -> bool 
{
    let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;

    let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return false;
    }

    if (*file_record_segment_header).flags & 0x02 == 0 {
        println!("{}", &lc!("[x] Selected entry is not a directory."));
        return false;
    }

    true
}
