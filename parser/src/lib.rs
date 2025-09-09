#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::{i64, slice, vec};
use std::ptr::{self, addr_of_mut};
use data::{get_mft_entry_copy, get_mft_len, get_ntfs_data, iter_mft_entries, push_mft_entry, set_ntfs_data, AttributeHeader, AttributeListEntry, ContentWrapper, DirectoryFilesList, FileData, FileNameAttributeHeader, FileNameAttributeHeaderFixed, FileRecordSegmentHeader, IndexAllocationBlock, IndexEntryHeader, IndexNodeHeader, IndexRootAttributeHeader, NTFSVolumeDataBuffer, NonResidentAttributeHeader, ReparsePointSymlinkAttributeHeader, ResidentAttributeHeader, RtlDecompressBuffer, RunEntry, StandardInformationAttributeHeader, ATTRIBUTE_LIST_ATTRIBUTE, COMPRESSION_FORMAT_LZNT1, DATA_ATTRIBUTE, FILE_NAME_ATTRIBUTE, H_VOLUME, INDEX_ALLOCATION_ATTRIBUTE, INDEX_ROOT_ATTRIBUTE, IO_REPARSE_TAG_WOF, KERNEL32_ADDR, MFT_DATA, REPARSE_POINT_ATTRIBUTE, REPARSE_POINT_MOUNT_POINT, REPARSE_POINT_SYMLINK, STANDARD_INFORMATION_ATTRIBUTE, TERMINATOR_ATTRIBUTE, UPCASE, VCN, VOLUME};
use dinvoke_rs::data::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, PVOID};
use regex_lite::Regex;
use utils::{assign_name, compare_ntfs_names, is_hidden, handle_strings, resolve_relative_path, set_file_pointer_ex_file_begin, utf16_ptr_to_string, is_directory};
use windows::Win32::Foundation::{CloseHandle, HANDLE};

/// Opens a handle to the specified NTFS volume and rebuilds the in-memory MFT cache.
/// Accepts any path format supported by `CreateFile`. If empty, refreshes the current volume cache.
///
/// # Parameters
/// - `new_volume`: Path or identifier of the target volume.
///
/// # Returns
/// `true` if the operation succeeds, `false` otherwise.
pub unsafe fn set_target(new_volume: &str) -> bool

{
    if !new_volume.is_empty() {
        let mut volume_lock = VOLUME.write().unwrap();
        *volume_lock = new_volume.to_string();
    } 

    let volume_lock = VOLUME.read().unwrap();
    let mut volume_path_utf16: Vec<u16> = (*volume_lock).encode_utf16().collect();
    volume_path_utf16.push(0);

    let function_ptr: dinvoke_rs::data::CreateFileW;
    let ret_value: Option<HANDLE>;
    dinvoke_rs::dinvoke::dynamic_invoke!(
        KERNEL32_ADDR,
        &lc!("CreateFileW"),
        function_ptr,
        ret_value,
        volume_path_utf16.as_ptr(),
        GENERIC_READ, // FILE_READ_DATA seems to be enough in most cases 
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        ptr::null_mut(),
        3, // OPEN_EXISTING
        128, // FILE_ATTRIBUTE_NORMAL
        HANDLE::default()
    );

    let read_volume_handle = ret_value.unwrap();
    if read_volume_handle.0 == -1 { // INVALID_HANDLE_VALUE
        println!("{}{}.", &lc!("[x] Failed to open a handle to "), new_volume);
        return false;
    }

    let _ = CloseHandle(H_VOLUME);
    H_VOLUME = read_volume_handle;
    rebuild_mft();

    true

}

unsafe fn rebuild_mft() 
{
    let mut ntfs_data_tmp = NTFSVolumeDataBuffer::default();
   
    if !set_file_pointer_ex_file_begin(0, H_VOLUME) {
        println!("{}", &lc!("[x] Call to SetFilePointerEx in rebuild_mft() failed."));
        return;
    } 

    let function_ptr: dinvoke_rs::data::ReadFile;
    let ret_value: Option<i32>;
    let mut bytes_to_read: u32 = 0;
    let buffer = vec![0u8; 512];
    let buffer_ptr: PVOID = std::mem::transmute(buffer.as_ptr());
    dinvoke_rs::dinvoke::dynamic_invoke!(
        KERNEL32_ADDR,
        &lc!("ReadFile"),
        function_ptr,
        ret_value,
        H_VOLUME,
        buffer_ptr,
        512 as u32, // Boot sector's size; it always seems to be 512 bytes
        &mut bytes_to_read,
        ptr::null_mut()
    );

    if ret_value.unwrap() == 0 {
        println!("{}", &lc!("[x] Call to ReadFile in rebuild_mft() failed."));
        return;
    }

    let boot_sector_ptr: *const u8 = buffer.as_ptr();
    let bytes_per_sector: u16 = *(boot_sector_ptr.add(0xB) as *const u16);
    let sectors_per_cluster: u8 = *(boot_sector_ptr.add(0xD) as *const u8);
    let mft_start_lcn: i64 = *(boot_sector_ptr.add(0x30) as *const i64);
    let clusters_per_file_record: i8 = *(boot_sector_ptr.add(0x40) as *const i8);
    let bytes_per_cluster = bytes_per_sector as u32 * sectors_per_cluster as u32;

    let bytes_per_file_record_segment = if clusters_per_file_record >= 0 {
        bytes_per_cluster * clusters_per_file_record as u32
    } else {
        1 << ((-clusters_per_file_record) as u32) // 2 raised to the absolute power of clusters_per_file_record
    };

    ntfs_data_tmp.mft_start_lcn = mft_start_lcn;
    ntfs_data_tmp.bytes_per_cluster = bytes_per_cluster; // Usually 4KB
    ntfs_data_tmp.bytes_per_file_record_segment = bytes_per_file_record_segment; // Usually 1KB -> 2 sectors per file record
    ntfs_data_tmp.bytes_per_sector = bytes_per_sector as _; // Usually 512 B

    set_ntfs_data(ntfs_data_tmp);
    let ntfs_data = get_ntfs_data();
    let mft_offset_in_bytes = ntfs_data.mft_start_lcn * ntfs_data.bytes_per_cluster as i64;

    if !set_file_pointer_ex_file_begin(mft_offset_in_bytes, H_VOLUME) {
        println!("{}", &lc!("[x] Second call to SetFilePointerEx in rebuild_mft() failed."));
        return;
    }

    let mut bytes_to_read: u32 = 0;
    let record_size = ntfs_data.bytes_per_file_record_segment as usize; // Size of each entry, usually 1KB (1024 bytes)
    let first_entry_buffer = vec![0u8; record_size];
    let first_entry_buffer_ptr: PVOID = std::mem::transmute(first_entry_buffer.as_ptr());
    let function_ptr: dinvoke_rs::data::ReadFile;
    let ret_value: Option<i32>;
    dinvoke_rs::dinvoke::dynamic_invoke!(
        KERNEL32_ADDR,
        &lc!("ReadFile"),
        function_ptr,
        ret_value,
        H_VOLUME,
        first_entry_buffer_ptr,
        record_size as u32,
        &mut bytes_to_read,
        ptr::null_mut()
    );

    if ret_value.unwrap() == 0 {
        println!("{}", &lc!("[x] Second call to ReadFile in rebuild_mft() failed."));
        return;
    }
    
    let mut mft_data = MFT_DATA.write().unwrap();
    *mft_data = Vec::new();    
    drop(mft_data); // JIC, to prevent deadlock
    
    //add_mft_entry(first_entry); mft entry 0 is self-contained, so if I add it here I would be adding it a second time and all the indexes would be incorrectly +1.
    let data_runs: Option<Vec<RunEntry>> = get_data_run_list_from_entry(&first_entry_buffer, &mut 0, &mut 0, &mut 0, &mut false, &mut 0);
    if data_runs.is_none() {
        println!("{}", &lc!("[x] Data run list not found for MFT itself."));
        return;
    }
    
    let mut runs = data_runs.unwrap();
    runs.sort_by_key(|run| run.first_vcn); // We sort based on the first vcn
    read_all_mft_entries(runs);

}

/// Builds the in-memory cache by reading the MFT using the data runs
/// from MFT entry 0.
///
/// # Parameters
/// - `data_runs`: Data run list for MFT entry 0.
unsafe fn read_all_mft_entries(data_runs: Vec<RunEntry>)
{
    println!("{}", &lc!("[-] Reading MFT entries..."));
    let ntfs_data = get_ntfs_data();
    for data_run in data_runs.iter().enumerate() {
        let data_run_content = read_data_run_clusters(data_run.1);
        if data_run_content.is_none() {
            continue;
        }

        let data_run_content = data_run_content.unwrap();
        let chunks = data_run_content.chunks(ntfs_data.bytes_per_file_record_segment as _);
        let mut offset = data_run.1.offset * ntfs_data.bytes_per_cluster as i64;
        for  chunk in chunks {
            let file_record_segment_header = chunk.as_ptr() as *const FileRecordSegmentHeader;
            let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
            let mut c = chunk.to_vec();
            if signature_str == lc!("FILE")  {
                fix_sequence_number(c.as_mut_ptr(), chunk.len());
            }

            let mut entry = ContentWrapper {offset: offset, content: c};
            push_mft_entry(&mut entry);
            offset += ntfs_data.bytes_per_file_record_segment as i64;
        }
    }

    let upcase_entry = get_mft_entry_copy(10);
    if upcase_entry.is_none() {
        panic!("{}", &lc!("[x] Critical error: $UpCase file not found.")); 
    }
    let upcase_entry = upcase_entry.unwrap();
    println!("{}", &lc!("[-] Parsing $UpCase file."));
    parse_upcase(&upcase_entry.content);
    println!("{}", &lc!("[+] $Upcase file parsed."));
}

/// Parses the content of the $UpCase MFT entry and stores it in memory.
///
/// # Parameters
/// - `upcase_entry`: Raw content of the $UpCase MFT entry.
unsafe fn parse_upcase(upcase_entry: &Vec<u8>)
{
    let contents = get_file_content(upcase_entry);
    if contents.is_none() {
        panic!("{}", &lc!("[x] Critical error: $UpCase parsing failed.")); // There is no point in continuing the execution from here
    }

    let mut upcase_lock = UPCASE.write().unwrap();
    let mut upcase_content = contents.unwrap();
    let upcase_content_len = upcase_content.len() / 2; // utf16
    let ptr = upcase_content.as_mut_ptr() as *mut u16;
    for i in 0..upcase_content_len {
        let item  = *(ptr.add(i as usize));
        upcase_lock.push(item);
    }
}

/// Extracts the data run list of the non-resident unnamed $DATA attribute from an MFT entry.
/// The returned list is **not** sorted by first VCN.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry.
/// - `last_cluster_index`: Mutable reference to store the last VCN.
/// - `attribute_size`: Mutable reference to store the size of the data.
/// - `compression_unit`: Mutable reference to store compression information.
///
/// # Returns
/// `Some(Vec<RunEntry>)` if a non-resident $DATA attribute is found, `None` otherwise
/// or if the $DATA attribute is resident.
unsafe fn get_data_run_list_from_entry(mft_entry: &Vec<u8>, last_cluster_index: &mut i64, attribute_size: &mut u64, compression_unit: &mut u16, compressed: &mut bool, depth: &mut u16) -> Option<Vec<RunEntry>>
{
    if *depth == 10 { // Preventing infinite recursion, JIC, I think its not needed
        return None;
    } else {
        *depth += 1;
    }

    let first_file_record_segment_header = *(mft_entry.as_ptr() as *const FileRecordSegmentHeader);

    let signature_str = String::from_utf8_lossy(&first_file_record_segment_header.signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry's signature does not match."));
        return None;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + first_file_record_segment_header.first_attribute_offset as usize) as *mut AttributeHeader;
    let mut attribute_list: *mut ResidentAttributeHeader = ptr::null_mut();
    let mut data_attributes: Vec<*mut NonResidentAttributeHeader> = vec![];

    loop 
    {
        if (*attribute_ptr).attribute_type == DATA_ATTRIBUTE && (*attribute_ptr).name_length == 0  { // The main content is in the unnamed $DATA attribute
            if (*attribute_ptr).non_resident == 0 { // The contents of the atribute reside in the mft entry itself
                return None;
            }
            data_attributes.push(attribute_ptr as *mut _);
        } else if (*attribute_ptr).attribute_type == ATTRIBUTE_LIST_ATTRIBUTE {
            attribute_list = attribute_ptr as *mut _;
        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }
        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    if data_attributes.len() == 0 && attribute_list == ptr::null_mut() {
            return None;
    }

    let mut runs = Vec::new();

    for data_attribute in data_attributes {
        let mut temp_attribute_size = 0u64;
        get_data_run_list_from_non_resident_attribute(data_attribute, last_cluster_index, &mut temp_attribute_size, compression_unit, compressed, mft_entry, &mut runs);
        *attribute_size += temp_attribute_size;
    }

    if attribute_list != ptr::null_mut() {
        let ret;

        if (*attribute_list).base_header.non_resident == 1 { // I'm not sure how often you would find a non resident attribute_list
            let non_resident_attribute_list = attribute_list as *mut NonResidentAttributeHeader;
            ret = get_data_run_list_from_non_resident_attribute_list(non_resident_attribute_list, attribute_size, compression_unit, compressed, depth, mft_entry);
        } else {
            ret = get_data_run_list_from_resident_attribute_list(attribute_list, attribute_size, compression_unit, compressed, depth);   
        }

        if ret.is_some() {
            runs.extend_from_slice(&ret.unwrap());
        }
    }

    //runs.sort_by_key(|run| run.first_vcn); // We sort based on the first vcn
    Some(runs)
}

/// Parses the data run list from a non-resident attribute and appends the
/// runs to `data_run_list`. 
///
/// # Parameters
/// - `non_resident_attribute`: Pointer to the non-resident attribute header.
/// - `last_cluster_index`: Output for the last VCN.
/// - `attribute_size`: Output for the data size.
/// - `compression_unit`: Output for compression info.
/// - `mft_entry`: Raw content of the MFT entry containing the non-resident attribute.
/// - `data_run_list`: List to append parsed runs into.
unsafe fn get_data_run_list_from_non_resident_attribute(non_resident_attribute: *mut NonResidentAttributeHeader, last_cluster_index: &mut i64, attribute_size: &mut u64, compression_unit: &mut u16, compressed: &mut bool, mft_entry: &Vec<u8>, data_run_list: &mut Vec<RunEntry>)
{
    let first_cluster = (*non_resident_attribute).first_cluster;
    let last_cluster = (*non_resident_attribute).last_cluster;
    
    let remaining_clusters = match last_cluster.checked_sub(first_cluster)
        .and_then(|diff| diff.checked_add(1)) {
            Some(val) => val,
            None => return,
        };

    let mut remaining_clusters = remaining_clusters; 

    if (*non_resident_attribute).compression_unit != 0 && ((*non_resident_attribute).base_header.flags & 0x0001 != 0){
        *compression_unit = (*non_resident_attribute).compression_unit;
        *compressed = true;
    }

    if (*non_resident_attribute).attribute_size != 0 {
        *attribute_size = (*non_resident_attribute).attribute_size; // Attribute disk size
    }
    
    let runs_offset_in_entry = (non_resident_attribute as usize + (*non_resident_attribute).data_runs_offset as usize) - mft_entry.as_ptr() as usize;
    let mut pointer = runs_offset_in_entry;
    let end_of_data_attribute = non_resident_attribute as usize + (*non_resident_attribute).base_header.length as usize - mft_entry.as_ptr() as usize;
    loop 
    {

        if pointer >= end_of_data_attribute {
            break; 
        }

        let run_header = mft_entry[pointer];
        pointer += 1;

        // If 0, we have reached the end of the data run list
        if run_header == 0 { 
            break;
        }

        let length_field_bytes = run_header & 0x0F;
        let offset_field_bytes = (run_header >> 4) & 0x0F;

        // value > 8 is invalid in NTFS
        if length_field_bytes > 8 || offset_field_bytes > 8 {
            pointer += length_field_bytes as usize + offset_field_bytes as usize;
            continue;
        }

        // We read the length in clusters
        let mut length = 0u64;
        if length_field_bytes > 0 {
            if pointer + length_field_bytes as usize > mft_entry.len() {
                break;
            }

            let mut length_buf = [0u8; 8];
            length_buf[..length_field_bytes as usize]
                .copy_from_slice(&mft_entry[pointer .. pointer + length_field_bytes as usize]);
            pointer += length_field_bytes as usize;

            length = u64::from_le_bytes(length_buf);
        }

        // We read the offset (signed, incremental)
        let mut offset = 0i64;
        if offset_field_bytes > 0 {
            if pointer + offset_field_bytes as usize > mft_entry.len() {
                break;
            }
            let mut offset_buf = [0u8; 8];
            offset_buf[..offset_field_bytes as usize]
                .copy_from_slice(&mft_entry[pointer .. pointer + offset_field_bytes as usize]);
            pointer += offset_field_bytes as usize;

            // If the high bit of the last byte is set to 1, you must sign-extend
            if offset_buf[offset_field_bytes as usize - 1] & 0x80 != 0 {
                for b in &mut offset_buf[offset_field_bytes as usize..] {
                    *b = 0xFF;
                }
            }
            offset = i64::from_le_bytes(offset_buf);
        }

        if length > remaining_clusters {
            continue;
        }

        remaining_clusters -= length;

        // The actual LCN is relative to the previous one (incremental offset).
        let lcn = match last_cluster_index.checked_add(offset) {
            Some(val) => val,
            None => continue, // I guess we continue in case this data run is "broken"?
        };

        *last_cluster_index = lcn;

        // If offset_field_bytes = 0 and length > 0 it is usually a sparse data run.
        let final_offset = if offset_field_bytes == 0 && length > 0 
        {
            -1 // This is how I internally mark sparse data run
        } else {
            lcn
        };

        data_run_list.push(RunEntry {
            length,
            offset: final_offset,
            first_vcn: (*non_resident_attribute).first_cluster, // firstVCN
            last_vcn: (*non_resident_attribute).last_cluster // lastVCN
        });
    }

    if remaining_clusters > 0 {
        data_run_list.push(RunEntry {
            length: remaining_clusters as _,
            offset: -1,
            first_vcn: (*non_resident_attribute).first_cluster,
            last_vcn: (*non_resident_attribute).last_cluster
        });
    }
}

/// Extracts and combines the data run lists of all unnamed $DATA
/// attributes from a non-resident attribute list. The resulting data run list is **not**
/// sorted by first VCN.
///
/// # Parameters
/// - `attribute_list`: Pointer to the non-resident attribute list.
/// - `attribute_size`: Mutable reference to store the total data size.
/// - `compression_unit`: Mutable reference to store compression information.
/// - `mft_entry`: Raw content of the MFT entry containing the attribute list.
///
/// # Returns
/// `Some(Vec<RunEntry>)` with the combined data run list if found, `None` otherwise.
unsafe fn get_data_run_list_from_non_resident_attribute_list(attribute_list: *mut NonResidentAttributeHeader, attribute_size: &mut u64, compression_unit: &mut u16, compressed: &mut bool, depth: &mut u16, mft_entry: &Vec<u8>) -> Option<Vec<RunEntry>>
{
    let mut runs: Vec<RunEntry> = vec![];
    let mut first_lcn = 0;
    let mut attr_size = 0;
    get_data_run_list_from_non_resident_attribute(attribute_list, &mut first_lcn, &mut attr_size, &mut 0, &mut false, mft_entry, &mut runs);
    let mut total_content = vec![];
    for data_run in runs.iter().enumerate() {
        let data_run_content = read_data_run_clusters(data_run.1);
        if data_run_content.is_none() {
            continue;
        }
        let mut data_run_content = data_run_content.unwrap();
        total_content.append(&mut data_run_content);
    }

    let mut attribute_list_entry = total_content.as_mut_ptr() as *mut AttributeListEntry;
    let mut analyzed_bytes = 0;
    let mut run_entries = vec![];
    let mut analyzed_entries: Vec<u64> = vec![];
    let mut lcn = 0i64;
    while analyzed_bytes < total_content.len()
    {
        if (*attribute_list_entry).attribute_type == DATA_ATTRIBUTE && (*attribute_list_entry).name_length == 0
        {
            let index = (*attribute_list_entry).next_mft_entry_index();
            
            if !analyzed_entries.contains(&index)
            {
                analyzed_entries.push(index); // We only parse the unnamed $DATA for each entry once, all at once.

                let mft_entry = get_mft_entry_copy(index as _);
                if mft_entry.is_none() {
                    return None;
                }

                let mft_entry = mft_entry.unwrap();
                let mut a_size = 0;
                let mut c_unit = 0;
                let mut comp = false;
                let r =  get_data_run_list_from_entry(&mft_entry.content, &mut lcn, &mut a_size, &mut c_unit, &mut comp, depth);
                if r.is_some() {
                    let entries = r.unwrap();
                    run_entries.extend_from_slice(&entries);

                    if *attribute_size == 0 {
                        if let Some(result) = attribute_size.checked_add(a_size) {// It seems we only have to take into account the first $DATA attribute's size.
                            *attribute_size = result;
                        } else {
                            return None; // Overflow, invalid data runs
                        } 
                    }
                    
                    if (*compression_unit == 0 && c_unit != 0) && (*compressed == false && comp) {
                        *compression_unit = c_unit;
                        *compressed = true;
                    }
                }
            } 
        } else if (*attribute_list_entry).attribute_type == TERMINATOR_ATTRIBUTE || (*attribute_list_entry).entry_length == 0{
            break;
        } 

        attribute_list_entry = (attribute_list_entry as usize + (*attribute_list_entry).entry_length as usize) as _;
        analyzed_bytes += (*attribute_list_entry).entry_length as usize;

    }
    
    return Some(run_entries);
}

/// Extracts and combines the data run lists of all unnamed $DATA
/// attributes from a resident attribute list. The resulting list is **not**
/// sorted by first VCN.
///
/// # Parameters
/// - `attribute_list`: Pointer to the resident attribute list.
/// - `attribute_size`: Mutable reference to store the total data size.
/// - `compression_unit`: Mutable reference to store compression information.
///
/// # Returns
/// `Some(Vec<RunEntry>)` with the combined data run list if found, `None` otherwise.
fn get_data_run_list_from_resident_attribute_list(attribute_list: *mut ResidentAttributeHeader, attribute_size: &mut u64, compression_unit: &mut u16, compressed: &mut bool, depth: &mut u16) -> Option<Vec<RunEntry>>
{
    unsafe 
    {
        let mut attribute_list_entry = (attribute_list as usize + (*attribute_list).attribute_offset as usize) as *mut AttributeListEntry;
        let mut analyzed_bytes = (*attribute_list).attribute_offset as u32;
        let mut run_entries = vec![];
        let mut analyzed_entries: Vec<u64> = vec![];
        let mut lcn = 0i64;

        while analyzed_bytes < (*attribute_list).attribute_length 
        {
            if (*attribute_list_entry).attribute_type == DATA_ATTRIBUTE && (*attribute_list_entry).name_length == 0
            {
                let index = (*attribute_list_entry).next_mft_entry_index();
                
                if !analyzed_entries.contains(&index)
                {
                    analyzed_entries.push(index); // We only parse the unnamed $DATA for each entry once, all at once.

                    let mft_entry = get_mft_entry_copy(index as _);
                    if mft_entry.is_none() {
                        return None;
                    }

                    let mft_entry = mft_entry.unwrap();
                    let mut a_size = 0;
                    let mut c_unit = 0;
                    let mut comp = false;
                    let r =  get_data_run_list_from_entry(&mft_entry.content, &mut lcn, &mut a_size, &mut c_unit, &mut comp, depth);
                    if r.is_some() {
                        let entries = r.unwrap();
                        run_entries.extend_from_slice(&entries);

                        if *attribute_size == 0 {
                            if let Some(result) = attribute_size.checked_add(a_size) {// It seems we only have to take into account the first $DATA attribute's size.
                                *attribute_size = result;
                            } else {
                                return None; // Overflow, invalid data runs
                            } 
                        }

                        if (*compression_unit == 0 && c_unit != 0) && (*compressed == false && comp) {
                            *compression_unit = c_unit;
                            *compressed = true;
                        }
                    }
                }
            } else if (*attribute_list_entry).attribute_type == TERMINATOR_ATTRIBUTE {
                break;
            }

            attribute_list_entry = (attribute_list_entry as usize + (*attribute_list_entry).entry_length as usize) as _;
            analyzed_bytes += (*attribute_list_entry).entry_length as u32;

        }

        Some(run_entries)
    }
}

/// Extracts data runs from `INDEX_ALLOCATION` attributes named `$I30` listed in
/// a resident attribute list and appends them to `run_entries`.
/// The runs are **not** sorted by first VCN.
///
/// # Parameters
/// - `attribute_list`: Pointer to the resident attribute list.
/// - `run_entries`: List to append parsed runs into.
fn get_data_run_list_from_resident_attribute_list_index_allocation_i30(attribute_list: *mut ResidentAttributeHeader, run_entries: &mut Vec<RunEntry>)
{
    unsafe 
    {
        let mut attribute_list_entry = (attribute_list as usize + (*attribute_list).attribute_offset as usize) as *mut AttributeListEntry;
        let mut analyzed_bytes = (*attribute_list).attribute_offset as u32;
        let mut analyzed_entries: Vec<u64> = vec![];
        let mut lcn = 0i64;

        while analyzed_bytes < (*attribute_list).attribute_length 
        {            
            if (*attribute_list_entry).attribute_type == INDEX_ALLOCATION_ATTRIBUTE && (*attribute_list_entry).name_length != 0 {

                let name_bytes_ptr = (attribute_list_entry as *const u8).add((*attribute_list_entry).name_offset as usize);
                let len_bytes = (*attribute_list_entry).name_length as usize * 2;
                let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
        
                let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_list_entry).name_length as usize);
                for chunk in name_bytes.chunks_exact(2) {
                    utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                }
        
                if let Ok(name) = String::from_utf16(&utf16) {
                    if name.to_ascii_lowercase() == lc!("$i30") {
                        let index = (*attribute_list_entry).next_mft_entry_index();
                
                        if !analyzed_entries.contains(&index)
                        {
                            analyzed_entries.push(index); // We only parse the unnamed $DATA for each entry once, all at once.

                            let mft_entry = get_mft_entry_copy(index as _);
                            if mft_entry.is_none() {
                                return;
                            }

                            let mft_entry = mft_entry.unwrap();
                            let r =  get_data_run_list_from_entry_index_allocation(&mft_entry.content, &mut lcn);
                            if r.is_some() {
                                let entries = r.unwrap();
                                run_entries.extend_from_slice(&entries);
                            }
                        }
                    }
                }
            } else if (*attribute_list_entry).attribute_type == TERMINATOR_ATTRIBUTE {
                break;
            }

            attribute_list_entry = (attribute_list_entry as usize + (*attribute_list_entry).entry_length as usize) as _;
            analyzed_bytes += (*attribute_list_entry).entry_length as u32;
        }
    }
}

/// Extracts the data run list from the `INDEX_ALLOCATION` attribute named `$I30`
/// of an MFT entry. The returned list is **not** sorted by first VCN.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry.
/// - `last_cluster_index`: Mutable reference to store the last VCN.
///
/// # Returns
/// `Some(Vec<RunEntry>)` if the `INDEX_ALLOCATION` attribute is found, `None` otherwise.
unsafe fn get_data_run_list_from_entry_index_allocation(mft_entry: &Vec<u8>, last_cluster_index: &mut i64) -> Option<Vec<RunEntry>>
{

    let first_file_record_segment_header = *(mft_entry.as_ptr() as *const FileRecordSegmentHeader);

    let signature_str = String::from_utf8_lossy(&first_file_record_segment_header.signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry's signature does not match."));
        return None;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + first_file_record_segment_header.first_attribute_offset as usize) as *mut AttributeHeader;
    let mut index_allocation_attribute: *mut NonResidentAttributeHeader = ptr::null_mut();

    loop 
    {
        if (*attribute_ptr).attribute_type == INDEX_ALLOCATION_ATTRIBUTE && (*attribute_ptr).name_length != 0 {

            let name_bytes_ptr = (attribute_ptr as *const u8).add((*attribute_ptr).name_offset as usize);
            let len_bytes = (*attribute_ptr).name_length as usize * 2;
            let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
    
            let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_ptr).name_length as usize);
            for chunk in name_bytes.chunks_exact(2) {
                utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
            }
    
            if let Ok(name) = String::from_utf16(&utf16) {
                if name.to_ascii_lowercase() == lc!("$i30") {
                    index_allocation_attribute = attribute_ptr as *mut _;
                    break;
                }
            }

        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }
        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    if index_allocation_attribute == ptr::null_mut() {
        return None;
    }

    let mut runs = vec![];
    get_data_run_list_from_non_resident_attribute(index_allocation_attribute, last_cluster_index, &mut 0, &mut 0, &mut false, mft_entry, &mut runs);

    Some(runs)
}

/// Retrieves the `STANDARD_INFORMATION` attribute from an MFT entry.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry.
///
/// # Returns
/// `Some(StandardInformationAttributeHeader)` if the attribute is found, `None` otherwise.
unsafe fn get_mft_entry_standard_attribute(mft_entry: &Vec<u8>) -> Option<StandardInformationAttributeHeader> 
{
    let first_file_record_segment_header = *(mft_entry.as_ptr() as *const FileRecordSegmentHeader);

    let signature_str = String::from_utf8_lossy(&first_file_record_segment_header.signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return None;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + first_file_record_segment_header.first_attribute_offset as usize) as *mut AttributeHeader;
    let standard_attribute: *mut StandardInformationAttributeHeader;
    loop 
    {
        if (*attribute_ptr).attribute_type == STANDARD_INFORMATION_ATTRIBUTE  {
            standard_attribute = attribute_ptr as _;
            return Some(*standard_attribute);
        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }

        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    None
}

/// Returns the absolute path of the directory containing the specified file,
/// without including the file name.
/// 
/// # Returns
/// Absolute path of the directory as a `String`.
fn get_file_full_path(file_data: &FileData) -> String
{
    let mut parts: Vec<String> = vec![];
    let mut previous_parents: Vec<u64> = vec![];
    get_parent_directory_recursive(file_data.parent, &mut parts, &mut previous_parents);
    parts.reverse();
    parts.join("\\")
}

/// Recursively retrieves the name of a parent directory by its MFT index,
/// preferring the Win32 name over the DOS name, and appends it to `parts`.
///
/// # Parameters
/// - `parent_index`: MFT index of the parent directory.
/// - `parts`: List to store the directory name parts.
/// - `previous_parents`: List of already visited parent indices to prevent loops.
fn get_parent_directory_recursive(parent_index: u64, parts: &mut Vec<String>, previous_parents: &mut Vec<u64>)
{
    unsafe 
    {
        if parent_index == 5 { // 5 is index of the root directory
            return;
        }

        let mft_entry = get_mft_entry_copy(parent_index as _).unwrap();
        let file_record_segment_header = mft_entry.content.as_ptr()  as *const FileRecordSegmentHeader;
        let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
        
        if signature_str != lc!("FILE") {
            return;
        }

        let mut found_short = false;
        let mut new_parent_index = 0;
        let mut attribute = (file_record_segment_header as usize + (*file_record_segment_header).first_attribute_offset as usize) as *mut AttributeHeader;
        while (attribute as isize - file_record_segment_header as isize) < mft_entry.content.len() as isize
        {
            if (*attribute).attribute_type == FILE_NAME_ATTRIBUTE 
            {
                let file_name_attribute = attribute as *mut FileNameAttributeHeader;
                let file_ptr = (file_name_attribute as *mut u8).add(size_of::<FileNameAttributeHeader>()) as *const u16;
                let file_content: &[u16] = slice::from_raw_parts(file_ptr, (*file_name_attribute).filename_length as usize);
                let file_name = utf16_ptr_to_string(&file_content, (*file_name_attribute).filename_length as usize);
                if (*file_name_attribute).namespace != 2 // different from DOS name
                { 
                    if file_name.is_some() 
                    {
                        let name = file_name.unwrap();
                        if found_short {
                            parts.pop();
                            found_short = false;
                        }

                        parts.push(name);
                        new_parent_index = (*file_name_attribute).parent_record_number();
                        if new_parent_index != parent_index && !previous_parents.contains(&new_parent_index) { // Preventing infinite loops
                            previous_parents.push(parent_index);
                            get_parent_directory_recursive(new_parent_index, parts, previous_parents);
                        }

                        break;
                    }
                }
                else // We do not want the FILE_NAME containing the short name, there should be another one with the win32 name ; If we have no other choice, we keep it.
                {
                    if file_name.is_some() 
                    {
                        let name = file_name.unwrap();
                        parts.push(name);

                        new_parent_index = (*file_name_attribute).parent_record_number();
                        found_short = true;
                    }
                }
                
            } else if (*attribute).attribute_type == TERMINATOR_ATTRIBUTE {
                break;
            }

            attribute = (attribute as usize + (*attribute).length as usize) as _;
        }

        // I think this code is unlikely to run in a normal environment, I leave it here just in case
        if found_short && new_parent_index != 0 {
            if new_parent_index != parent_index && !previous_parents.contains(&new_parent_index) { // Preventing infinite loops
                previous_parents.push(parent_index);
                get_parent_directory_recursive(new_parent_index, parts, previous_parents);
            }
        }

        
    }
}

/// Retrieves the content of the unnamed `$DATA` attribute from an MFT entry,
/// returning it decompressed if necessary.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry.
///
/// # Returns
/// `Some(Vec<u8>)` with the decompressed content if found, `None` otherwise.
unsafe fn get_file_content(mft_entry: &Vec<u8>) -> Option<Vec<u8>>
{
    let ntfs_data = get_ntfs_data();
    let mut attribute_size = 0;
    let mut compression_unit = 0;
    let mut is_compressed = false;
    let runs = get_data_run_list_from_entry(mft_entry, &mut 0, &mut attribute_size, &mut compression_unit, &mut is_compressed, &mut 0);
    if runs.is_none() {
        return get_file_content_resident_data(mft_entry);
    }

    let mut vcn_list: Vec<VCN> = vec![];
    let mut data_runs = runs.unwrap();
    data_runs.sort_by_key(|run| run.first_vcn); // We sort based on the first vcn
    
    for data_run in data_runs
    {
        if data_run.offset == -1  { // Sparse data run
            let vcn = VCN { is_sparse: true, content: vec![]};
            vcn_list.extend(std::iter::repeat(vcn.clone()).take(data_run.length as _));
            continue;
        }

        let size_to_read = 64 * 1024 * 1024; // We read 64MBs at a time
        let mut data_run_data_left = (data_run.length as usize * ntfs_data.bytes_per_cluster as usize) as i64;
        let mut temporal_pointer = data_run.offset * ntfs_data.bytes_per_cluster as i64; // Where to move the pointer to

        while data_run_data_left > 0
        {
            if !set_file_pointer_ex_file_begin(temporal_pointer, H_VOLUME) {
                println!("{}", &lc!("[x] Call to SetFilePointerEx in get_file_content() failed."));
                return None;
            }

            let mut bytes_to_read = size_to_read;
            if data_run_data_left < bytes_to_read {
                bytes_to_read = data_run_data_left;
            }
            
            let mut bytes_read: u32 = 0;
            let buffer = vec![0u8; bytes_to_read as _];
            let buffer_ptr: PVOID = std::mem::transmute(buffer.as_ptr());
            let function_ptr: dinvoke_rs::data::ReadFile;
            let ret_value: Option<i32>;
            dinvoke_rs::dinvoke::dynamic_invoke!(
                KERNEL32_ADDR,
                &lc!("ReadFile"),
                function_ptr,
                ret_value,
                H_VOLUME,
                buffer_ptr,
                bytes_to_read as u32,
                &mut bytes_read,
                ptr::null_mut()
            );

            if ret_value.unwrap() == 0  {
                println!("{}", &lc!("[x] Call to ReadFile in get_file_content() failed."));
                return None;
            }

            temporal_pointer += bytes_to_read as i64;
            data_run_data_left -= bytes_to_read;
            for chunk in buffer.chunks(ntfs_data.bytes_per_cluster as _) {
                let vcn = VCN { is_sparse: false, content: chunk.to_vec()};
                vcn_list.push(vcn);
            }
        }
    }

    let clusters_per_unit = 1usize << compression_unit as usize;
    process_units(&vcn_list, ntfs_data.bytes_per_cluster as _, clusters_per_unit,attribute_size, is_compressed)
    
}

/// Retrieves the content of a file stored in a resident `$DATA` attribute
/// within the MFT entry.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry.
///
/// # Returns
/// `Some(Vec<u8>)` with the content if found, `None` otherwise.
unsafe fn get_file_content_resident_data(mft_entry: &Vec<u8>) -> Option<Vec<u8>>
{
    let first_file_record_segment_header = *(mft_entry.as_ptr() as *const FileRecordSegmentHeader);

    let signature_str = String::from_utf8_lossy(&first_file_record_segment_header.signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return None;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + first_file_record_segment_header.first_attribute_offset as usize) as *mut AttributeHeader;

    loop 
    {
        if (*attribute_ptr).attribute_type == DATA_ATTRIBUTE && (*attribute_ptr).name_length == 0  { 
            if (*attribute_ptr).non_resident == 0 { 
                let stream_length = *((attribute_ptr as *mut u8).add(16) as *const u32); // Offset 0x10
                let sream_starting_offset = *((attribute_ptr as *mut u8).add(20) as *const u16); // Offset 0x14

                let data_start = (attribute_ptr as *mut u8).add(sream_starting_offset as usize);
                let content = std::slice::from_raw_parts(data_start, stream_length as usize);
                return Some(content.to_vec());
            }

            break;
        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }
        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    None
}

/// Retrieves the content of all index allocation blocks referenced by the
/// data run list of an `INDEX_ALLOCATION` attribute.
///
/// # Parameters
/// - `data_run_list`: Data run list of the `INDEX_ALLOCATION` attribute.
///
/// # Returns
/// `Some(Vec<ContentWrapper>)` with the content of the blocks if found, `None` otherwise.
unsafe fn get_index_allocation_content(data_run_list: Vec<RunEntry>) -> Option<Vec<ContentWrapper>>
{
    let ntfs_data = get_ntfs_data();
    let mut final_content: Vec<ContentWrapper> = vec![]; 
    
    for data_run in data_run_list
    {
        if data_run.offset == -1  { // Sparse data run
            let buff_len = data_run.length as usize * ntfs_data.bytes_per_cluster as usize;
            let buffer = vec![0u8; buff_len];
            let content_wrapper = ContentWrapper {offset: -1, content: buffer};
            final_content.push(content_wrapper);
            continue;
        }

        let size_to_read = 64 * 1024 * 1024;
        let mut data_run_data_left = (data_run.length as usize * ntfs_data.bytes_per_cluster as usize) as i64;
        let mut temporal_pointer = data_run.offset * ntfs_data.bytes_per_cluster as i64;

        while data_run_data_left > 0
        {
            if !set_file_pointer_ex_file_begin(temporal_pointer, H_VOLUME) {
                println!("{}", &lc!("[x] Call to SetFilePointerEx in get_index_allocation_content() failed."));
                return None;
            }

            let mut bytes_to_read = size_to_read;
            if data_run_data_left < bytes_to_read {
                bytes_to_read = data_run_data_left;
            }
            
            let function_ptr: dinvoke_rs::data::ReadFile;
            let ret_value: Option<i32>;
            let mut bytes_read: u32 = 0;
            let buffer = vec![0u8; bytes_to_read as _];
            let buffer_ptr: PVOID = std::mem::transmute(buffer.as_ptr());
            dinvoke_rs::dinvoke::dynamic_invoke!(
                KERNEL32_ADDR,
                &lc!("ReadFile"),
                function_ptr,
                ret_value,
                H_VOLUME,
                buffer_ptr,
                bytes_to_read as u32,
                &mut bytes_read,
                ptr::null_mut()
            );

            if ret_value.unwrap() == 0 || bytes_read != bytes_to_read as _ {
                println!("{}", &lc!("[x] Call to ReadFile in get_index_allocation_content() failed."));
                return None;
            }

            let content_wrapper = ContentWrapper {offset: temporal_pointer, content: buffer};
            temporal_pointer += bytes_to_read as i64;
            data_run_data_left -= bytes_to_read;
            final_content.push(content_wrapper);
        }
    }

    Some(final_content)
    
}

/// Retrieves the content of all index allocation blocks referenced by the
/// data run list of an `INDEX_ALLOCATION` attribute, returning the data
/// combined in a single vector.
///
/// # Parameters
/// - `data_run_list`: Data run list of the `INDEX_ALLOCATION` attribute.
///
/// # Returns
/// `Some(Vec<u8>)` with the combined content if found, `None` otherwise.
unsafe fn get_index_allocation_content_single_vector(data_run_list: Vec<RunEntry>) -> Option<Vec<u8>>
{
    let ntfs_data = get_ntfs_data();
    let mut final_content: Vec<u8> = vec![]; 
    
    for data_run in data_run_list
    {
        if data_run.offset == -1  { // Sparse data run
            let buff_len = data_run.length as usize * ntfs_data.bytes_per_cluster as usize;
            let buffer = vec![0u8; buff_len];
            final_content.extend_from_slice(&buffer);
            continue;
        }

        let size_to_read = 64 * 1024 * 1024;
        let mut data_run_data_left = (data_run.length as usize * ntfs_data.bytes_per_cluster as usize) as i64;
        let mut temporal_pointer = data_run.offset * ntfs_data.bytes_per_cluster as i64;

        while data_run_data_left > 0
        {
            if !set_file_pointer_ex_file_begin(temporal_pointer, H_VOLUME) {
                println!("{}", &lc!("[x] Call to SetFilePointerEx in get_index_allocation_content() failed."));
                return None;
            }

            let mut bytes_to_read = size_to_read;
            if data_run_data_left < bytes_to_read {
                bytes_to_read = data_run_data_left;
            }
            
            let function_ptr: dinvoke_rs::data::ReadFile;
            let ret_value: Option<i32>;
            let mut bytes_read: u32 = 0;
            let buffer = vec![0u8; bytes_to_read as _];
            let buffer_ptr: PVOID = std::mem::transmute(buffer.as_ptr());
            dinvoke_rs::dinvoke::dynamic_invoke!(
                KERNEL32_ADDR,
                &lc!("ReadFile"),
                function_ptr,
                ret_value,
                H_VOLUME,
                buffer_ptr,
                bytes_to_read as u32,
                &mut bytes_read,
                ptr::null_mut()
            );

            if ret_value.unwrap() == 0 || bytes_read != bytes_to_read as _ {
                println!("{}", &lc!("[x] Call to ReadFile in get_index_allocation_content() failed."));
                return None;
            }

            temporal_pointer += bytes_to_read as i64;
            data_run_data_left -= bytes_to_read;
            final_content.extend_from_slice(&buffer);
        }
    }

    Some(final_content)
}

/// Reads the content of the clusters referenced by a single data run.
///
/// # Parameters
/// - `data_run`: Data run to read from.
///
/// # Returns
/// `Some(Vec<u8>)` with the clusters' content if successful, `None` otherwise.
unsafe fn read_data_run_clusters(data_run: &RunEntry) -> Option<Vec<u8>>
{
    let ntfs_data = get_ntfs_data();
    let data_run_total_size = data_run.length as usize * ntfs_data.bytes_per_cluster as usize;

    if data_run.offset == -1  {
        // sparse 
        let buff = vec![0u8; data_run_total_size];
        return Some(buff);
    }

    let size_to_read = 64 * 1024 * 1024; // We read 64MBs at a time 
    let mut temporal_pointer = data_run.offset * ntfs_data.bytes_per_cluster as i64; // Where to move the pointer to
    let mut complete_output: Vec<u8> = vec![];
    let mut data_left_to_read = data_run_total_size as i64;

    while data_left_to_read > 0
    {
        if !set_file_pointer_ex_file_begin(temporal_pointer, H_VOLUME) {
            println!("{}", &lc!("[x] Call to SetFilePointerEx in read_data_run_clusters() failed."));
            return None;
        }

        let mut bytes_to_read = size_to_read;
        if data_left_to_read < bytes_to_read {
            bytes_to_read = data_left_to_read;
        }

        let mut bytes_read: u32 = 0;
        let buffer2 = vec![0u8; bytes_to_read as _];
        let buffer2_ptr: PVOID = std::mem::transmute(buffer2.as_ptr());
        let function_ptr: dinvoke_rs::data::ReadFile;
        let ret_value: Option<i32>;
        dinvoke_rs::dinvoke::dynamic_invoke!(
            KERNEL32_ADDR,
            &lc!("ReadFile"),
            function_ptr,
            ret_value,
            H_VOLUME,
            buffer2_ptr,
            bytes_to_read as u32,
            &mut bytes_read,
            ptr::null_mut()
        );

        if ret_value.unwrap() == 0 || bytes_read != bytes_to_read as _ {
            return None;
        }

        temporal_pointer += bytes_to_read as i64;
        data_left_to_read -= bytes_to_read;
        complete_output.extend_from_slice(&buffer2);
    }

    Some(complete_output)
    
}

/// Retrieves a copy of an MFT entry by its index.
///
/// # Parameters
/// - `index`: Index of the MFT entry.
///
/// # Returns
/// `Some(Vec<u8>)` with the entry content if found, `None` otherwise.
pub unsafe fn read_mft_entry_by_index(index: usize) -> Option<Vec<u8>>
{
    if get_mft_len() < index {
        return None;
    }

    let mft_entry = get_mft_entry_copy(index);
    if mft_entry.is_none() {
        return None;
    }

    let mft_entry = mft_entry.unwrap();
    let file_contents ;
    if entry_has_reparse_point(&mft_entry.content) {
        println!("{}", &lc!("[-] The entry has a Reparse Point attribute."));
        file_contents =  untangle_reparse_point(&mft_entry.content, &mut String::default(), false, &mut false)
    } else {
        file_contents = get_file_content(&mft_entry.content)
    }

    return file_contents;
}

/// Reads and decompresses the content of a file located in the specified
/// parent directory.
///
/// # Parameters
/// - `input_directory`: Path of the parent directory.
/// - `name_to_search`: Name of the file to read.
///
/// # Returns
/// `Some(Vec<u8>)` with the decompressed file content if found, `None` otherwise.
pub unsafe fn read_file_from_mft(input_directory: &str, name_to_search: &str) -> Option<Vec<u8>>
{
    let mut split: Vec<&str> = input_directory.split_terminator('\\').collect();

    if split.is_empty() {
        return None;
    } 
    
    let volume_letter = *split.first().unwrap();
    let mut index = 5; // root entry
    let mut next_entry: Option<ContentWrapper>; 
    loop 
    {
        split.remove(0);
        next_entry = get_mft_entry_copy(index as _);
        if next_entry.is_none() {
            break;
        }

        if split.is_empty() {
            let last_dir_entry = next_entry.unwrap();
            let ind = search_file_name_in_index_i30(&last_dir_entry.content, name_to_search);
            if ind.is_none() {
                break;
            }

            index = ind.unwrap();
            next_entry = get_mft_entry_copy(index as _); 
            if next_entry.is_none() {
                break;
            }

            let mft_final_entry = next_entry.unwrap();
            let file_contents ;
            if entry_has_reparse_point(&&mft_final_entry.content) {
                println!("{}", &lc!("[-] The entry has a Reparse Point attribute."));
                let mut joined = format!(r"{}\{}", input_directory, name_to_search);
                file_contents = untangle_reparse_point(&&mft_final_entry.content, &mut joined, false, &mut false);
            } else {
                file_contents = get_file_content(&&mft_final_entry.content);
            }

            return file_contents;
        }

        let mft_entry = next_entry.unwrap();
        let ind = search_file_name_in_index_i30(&mft_entry.content, split[0]);
        if ind.is_none() {
            break;
        }

        index = ind.unwrap();
    }

    println!("{}", &lc!("[-] $I30 index search failed, fallback to sequential search..."));
    for (index, entry) in iter_mft_entries().enumerate()
    {          
        let file_names= search_filename_in_mft_entry_by_str(&entry.content, name_to_search, 0, false);
        if file_names.is_some()
        {
            let mut files_names = file_names.unwrap();
            for (_, data) in files_names.iter_mut() 
            {
                data.mft_entry_index = index;
                let retrieved_full_path = get_file_full_path(&data);
                for any_file_name in &data.all_names 
                { 
                    let mut joined;
                    if retrieved_full_path.is_empty() {
                        joined = format!(r"{}", volume_letter);
                    } else {
                        joined = format!(r"{}\{}",volume_letter, retrieved_full_path);
                    } 

                    let joined_u16: Vec<u16> = joined.encode_utf16().collect();
                    let dir_u16: Vec<u16> = input_directory.encode_utf16().collect();
                    let order = compare_ntfs_names(&joined_u16, &dir_u16);
                    if order == Ordering::Equal 
                    {
                        let mut mft_entry = entry;
                        let mut base_index = get_base_record_index(&mft_entry.content) as usize;
                        if base_index != 0 {
                            mft_entry = get_mft_entry_copy(base_index).unwrap();
                        } else {
                            base_index = data.mft_entry_index;
                        }

                        if get_mft_len() < base_index {
                            return None;
                        }

                        joined = format!(r"{}\{}", joined, any_file_name);
                        println!("[+] Entry {} matched. Record index: {}", joined, base_index);
                    
                        let file_contents ;
                        if entry_has_reparse_point(&mft_entry.content) {
                            println!("{}", &lc!("[-] The entry has a Reparse Point attribute."));
                            file_contents =  untangle_reparse_point(&mft_entry.content, &mut joined, false, &mut false);
                        } else {
                            file_contents = get_file_content(&mft_entry.content);
                        }

                        return file_contents;
                    }
                }
            }
        }
    }

    println!("{}", &lc!("[-] Match not found."));
    None
}

/// Retrieves all file names from an MFT entry that match the given regular expression.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry.
/// - `regex`: Regular expression to match file names.
///
/// # Returns
/// `Some(HashMap<u64, FileData>)` with matching file names, or `None` if none are found.
fn search_filename_in_mft_entry_by_regex(mft_entry: &Vec<u8>, regex: &Regex) -> Option<HashMap<u64, FileData>>
{
    unsafe 
    {
        let bytes_per_mft_file_records = get_ntfs_data().bytes_per_file_record_segment;

        let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;
        let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
        if signature_str != lc!("FILE") {
            return None;
        }

        let mut attribute = (file_record_segment_header as usize + (*file_record_segment_header).first_attribute_offset as usize) as *mut AttributeHeader;
        let mut file_names: HashMap<u64, FileData> = HashMap::default();
        while (attribute as isize - file_record_segment_header as isize) < bytes_per_mft_file_records as isize
        {
            if (*attribute).attribute_type == FILE_NAME_ATTRIBUTE 
            {
                let file_name_attribute = attribute as *mut FileNameAttributeHeader; 
                if (*file_name_attribute).resident_attribute.base_header.non_resident == 0 
                {
                    let file_name;
                    if (*file_name_attribute).filename_length == 0 {
                        file_name = Some(String::from(""));
                    } else {
                        let file_ptr = (file_name_attribute as *mut u8).add(size_of::<FileNameAttributeHeader>()) as *const u16;
                        let file_content: &[u16] = slice::from_raw_parts(file_ptr, (*file_name_attribute).filename_length as usize);
                        file_name = String::from_utf16(file_content).ok();
                    }

                    if file_name.is_some() 
                    {
                        let name = file_name.unwrap();
                        let parent = (*file_name_attribute).parent_record_number();
                        // All entries that have a filename that matches the regular expression
                        if regex.is_match(&name) { 
                            let fd = file_names.entry(parent).or_insert_with(|| {
                                let mut new_fd = FileData::default();
                                new_fd.parent = parent;
                                new_fd
                            });
    
                            assign_name(fd, (*file_name_attribute).namespace, name);
                        } 
                    }
                }   
            } else if (*attribute).attribute_type == TERMINATOR_ATTRIBUTE {
                break;
            }

            attribute = (attribute as usize + (*attribute).length as usize) as _;
        }


        if file_names == HashMap::default() { 
            None
        } else {
            for (_, data) in file_names.iter_mut() 
            {
                let mut present: HashSet<String> = data.win32_names
                    .iter()
                    .map(|s| s.to_lowercase())
                    .collect();
                
                for s in &data.posix_names {
                    let s_lower = s.to_lowercase();
                    if !present.contains(&s_lower) {
                        present.insert(s_lower);
                        data.win32_names.push(s.clone());
                    }
                }
            }

            Some(file_names)
        }
    }
}

fn search_filename_in_attribute_list_by_str(attribute_list: *mut ResidentAttributeHeader, file_to_search: &str, parent_record: u64, get_all_names: bool, file_names: &mut HashMap<u64, FileData>) 
{
    unsafe 
    {
        let mut attribute_list_entry = (attribute_list as usize + (*attribute_list).attribute_offset as usize) as *mut AttributeListEntry;
        let mut analyzed_bytes = (*attribute_list).attribute_offset as u32;
        let mut analyzed_entries: Vec<u64> = vec![];

        while analyzed_bytes < (*attribute_list).attribute_length 
        {
            if (*attribute_list_entry).attribute_type == FILE_NAME_ATTRIBUTE
            {
                let index = (*attribute_list_entry).next_mft_entry_index();
                
                if !analyzed_entries.contains(&index)
                {
                    analyzed_entries.push(index);
                    let mft_entry = get_mft_entry_copy(index as _);
                    if mft_entry.is_none() {
                        continue;
                    }

                    let mft_entry = mft_entry.unwrap();
                    search_filename_in_mft_entry_by_str_aux(&mft_entry.content, file_to_search, parent_record, get_all_names, file_names);
                }
            } else if (*attribute_list_entry).attribute_type == TERMINATOR_ATTRIBUTE {
                break;
            }

            attribute_list_entry = (attribute_list_entry as usize + (*attribute_list_entry).entry_length as usize) as _;
            analyzed_bytes += (*attribute_list_entry).entry_length as u32;

        }

    }
}

fn search_filename_in_mft_entry_by_str_aux(mft_entry: &Vec<u8>, file_to_search: &str, parent_record: u64, get_all_names: bool, file_names: &mut HashMap<u64, FileData>) 
{
    unsafe 
    {
        let bytes_per_mft_file_records = get_ntfs_data().bytes_per_file_record_segment;

        let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;
        let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
        if signature_str != lc!("FILE") {
            return;
        }

        let mut attribute = (file_record_segment_header as usize + (*file_record_segment_header).first_attribute_offset as usize) as *mut AttributeHeader;
        while (attribute as isize - file_record_segment_header as isize) < bytes_per_mft_file_records as isize
        {
            if (*attribute).attribute_type == FILE_NAME_ATTRIBUTE 
            {
                let file_name_attribute = attribute as *mut FileNameAttributeHeader;
                if (*file_name_attribute).resident_attribute.base_header.non_resident == 0 // Necesario? -> no, se puede quitar
                {
                    let file_name;
                    let file_ptr = (file_name_attribute as *mut u8).add(size_of::<FileNameAttributeHeader>()) as *const u16;
                    let file_name_content: &[u16] = slice::from_raw_parts(file_ptr, (*file_name_attribute).filename_length as usize);
                    file_name = String::from_utf16(file_name_content).ok();
                    
                    if file_name.is_some() 
                    {
                        let name = file_name.unwrap();
                        let parent = (*file_name_attribute).parent_record_number(); // Useful to locate all hardlinks of a file
                        let filename_u16: Vec<u16> = file_to_search.encode_utf16().collect();
                        let order = compare_ntfs_names(&filename_u16, file_name_content);

                        // All names of the entry in a particular parent directory
                        // Or a particular name in all parent directories
                        // Or all names, regardless of location
                        if file_to_search.is_empty() && parent_record == parent ||
                            order == Ordering::Equal || 
                            get_all_names { 

                                let fd = file_names.entry(parent).or_insert_with(|| {
                                    let mut new_fd = FileData::default();
                                    new_fd.parent = parent;
                                    new_fd
                                });
        
                                assign_name(fd, (*file_name_attribute).namespace, name);
                        } 
                    }
                }   
            } else if (*attribute).attribute_type == TERMINATOR_ATTRIBUTE {
                break;
            }

            attribute = (attribute as usize + (*attribute).length as usize) as _;
        }
    }
}


/// Searches for a file name in an MFT entry using case-insensitive comparison.
/// If `get_all_names` is `true`, retrieves all names from the entry.
/// If `file_to_search` is empty and `parent_record` is provided, retrieves all
/// names whose parent matches the given record index.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry.
/// - `file_to_search`: Name to search for (empty string for parent-based search).
/// - `parent_record`: Parent record index for filtering.
/// - `get_all_names`: Whether to retrieve all names in the entry.
///
/// # Returns
/// `Some(HashMap<u64, FileData>)` with the matching names, or `None` if none are found.
fn search_filename_in_mft_entry_by_str(mft_entry: &Vec<u8>, file_to_search: &str, parent_record: u64, get_all_names: bool) -> Option<HashMap<u64, FileData>>
{
    unsafe 
    {
        let bytes_per_mft_file_records = get_ntfs_data().bytes_per_file_record_segment;

        let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;
        let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
        if signature_str != lc!("FILE") {
            return None;
        }

        let mut attribute = (file_record_segment_header as usize + (*file_record_segment_header).first_attribute_offset as usize) as *mut AttributeHeader;
        let mut attribute_list: *mut ResidentAttributeHeader = ptr::null_mut();
        let mut file_names: HashMap<u64, FileData> = HashMap::default();
        while (attribute as isize - file_record_segment_header as isize) < bytes_per_mft_file_records as isize
        {
            if (*attribute).attribute_type == FILE_NAME_ATTRIBUTE 
            {
                let file_name_attribute = attribute as *mut FileNameAttributeHeader;
                if (*file_name_attribute).resident_attribute.base_header.non_resident == 0 // Necesario? -> no, se puede quitar
                {
                    let file_name;
                    let file_ptr = (file_name_attribute as *mut u8).add(size_of::<FileNameAttributeHeader>()) as *const u16;
                    let file_name_content: &[u16] = slice::from_raw_parts(file_ptr, (*file_name_attribute).filename_length as usize);
                    file_name = String::from_utf16(file_name_content).ok();
                    
                    if file_name.is_some() 
                    {
                        let name = file_name.unwrap();
                        let parent = (*file_name_attribute).parent_record_number(); // Useful to locate all hardlinks of a file
                        let filename_u16: Vec<u16> = file_to_search.encode_utf16().collect();
                        let order = compare_ntfs_names(&filename_u16, file_name_content);

                        // All names of the entry in a particular parent directory
                        // Or a particular name in all parent directories
                        // Or all names, regardless of location
                        if file_to_search.is_empty() && parent_record == parent ||
                            order == Ordering::Equal || 
                            get_all_names { 

                                let fd = file_names.entry(parent).or_insert_with(|| {
                                    let mut new_fd = FileData::default();
                                    new_fd.parent = parent;
                                    new_fd
                                });
        
                                assign_name(fd, (*file_name_attribute).namespace, name);
                        } 
                    }
                }   
            } else if (*attribute).attribute_type == ATTRIBUTE_LIST_ATTRIBUTE {
                attribute_list = attribute as *mut _;
            } else if (*attribute).attribute_type == TERMINATOR_ATTRIBUTE {
                break;
            }

            attribute = (attribute as usize + (*attribute).length as usize) as _;
        }

        if attribute_list != ptr::null_mut() {
            search_filename_in_attribute_list_by_str(attribute_list, file_to_search, parent_record, get_all_names, &mut file_names);
        }

        if file_names == HashMap::default() { 
            None
        } else {
            for (_, data) in file_names.iter_mut() 
            {
                let mut present: HashSet<String> = data.win32_names
                .iter()
                .map(|s| s.to_lowercase())
                .collect();
        
                for s in &data.posix_names {
                    let s_lower = s.to_lowercase();
                    if !present.contains(&s_lower) {
                        present.insert(s_lower);
                        data.win32_names.push(s.clone());
                    }
                }
            }

            Some(file_names)
        }
    }
}

/// Traverses the `$I30` index B+ tree of an MFT entry to find a file name.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry.
/// - `name_to_search`: File name to locate.
///
/// # Returns
/// `Some(u64)` with the matching record index, or `None` if not found.
unsafe fn search_file_name_in_index_i30(mft_entry: &Vec<u8>, name_to_search: &str) -> Option<u64>
{
    let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;

    let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return None;
    }

    if (*file_record_segment_header).flags & 0x02 == 0 {
        println!("{}", &lc!("[x] Selected entry is not a directory."));
        return None;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + (*file_record_segment_header).first_attribute_offset as usize) as *mut AttributeHeader;
    let mut attribute_list: *mut ResidentAttributeHeader = ptr::null_mut();
    let mut index_root: *mut IndexRootAttributeHeader = ptr::null_mut();
    let mut extended_entry_index_root = IndexRootAttributeHeader::default();
    let mut index_allocation_attributes: Vec<*mut NonResidentAttributeHeader> = vec![];
    let bytes_per_mft_file_records = get_ntfs_data().bytes_per_file_record_segment;
    let mut found_extendend_entry = false;
    let mut vcn_or_record_id = 0;

    while (attribute_ptr as isize - file_record_segment_header as isize) < bytes_per_mft_file_records as isize
    {
        if (*attribute_ptr).attribute_type == INDEX_ROOT_ATTRIBUTE  {
            if (*attribute_ptr).name_length != 0 {

                let name_bytes_ptr = (attribute_ptr as *const u8)
                    .add((*attribute_ptr).name_offset as usize);
                let len_bytes = (*attribute_ptr).name_length as usize * 2;
                let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
        
                let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_ptr).name_length as usize);
                for chunk in name_bytes.chunks_exact(2) {
                    utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                }
        
                if let Ok(name) = String::from_utf16(&utf16) {
                    if name.to_ascii_lowercase() == lc!("$i30") {
                        index_root = attribute_ptr as *mut _;
                    }
                }
            }

        } else if (*attribute_ptr).attribute_type == INDEX_ALLOCATION_ATTRIBUTE  { 
            if (*attribute_ptr).name_length != 0 {

                let name_bytes_ptr = (attribute_ptr as *const u8)
                    .add((*attribute_ptr).name_offset as usize);
                let len_bytes = (*attribute_ptr).name_length as usize * 2;
                let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
        
                let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_ptr).name_length as usize);
                for chunk in name_bytes.chunks_exact(2) {
                    utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                }
        
                if let Ok(name) = String::from_utf16(&utf16) {
                    if name.to_ascii_lowercase() == lc!("$i30") {
                        index_allocation_attributes.push(attribute_ptr as *mut _);
                    }
                }
            }
         
        } else if (*attribute_ptr).attribute_type == ATTRIBUTE_LIST_ATTRIBUTE {
            attribute_list = attribute_ptr as *mut _;
        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }
        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    if index_root == ptr::null_mut() {
        if attribute_list != ptr::null_mut() {

            let mut attribute_list_entry = (attribute_list as usize + (*attribute_list).attribute_offset as usize) as *mut AttributeListEntry;
            let mut analyzed_bytes = (*attribute_list).attribute_offset as u32;

            while analyzed_bytes < (*attribute_list).attribute_length 
            {
                if (*attribute_list_entry).attribute_type == INDEX_ROOT_ATTRIBUTE 
                {
                    let name_bytes_ptr = (attribute_list_entry as *const u8).add((*attribute_list_entry).name_offset as usize);
                    let len_bytes = (*attribute_list_entry).name_length as usize * 2;
                    let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
            
                    let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_list_entry).name_length as usize);
                    for chunk in name_bytes.chunks_exact(2) {
                        utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                    }
            
                    if let Ok(name) = String::from_utf16(&utf16) {
                        if name.to_ascii_lowercase() == lc!("$i30") {
                            let index = (*attribute_list_entry).next_mft_entry_index();
                            let extended_entry = get_mft_entry_copy(index as _);
                            if extended_entry.is_none() {
                                return None;
                            }

                            let extended_entry = extended_entry.unwrap();
                            if search_file_name_index_root_extended_mft_entry(&extended_entry.content, name_to_search, &mut vcn_or_record_id, &mut extended_entry_index_root){
                                return Some(vcn_or_record_id);
                            }

                            found_extendend_entry = true;
                            break;
                        }

                    }
                    
                } else if (*attribute_list_entry).attribute_type == TERMINATOR_ATTRIBUTE {
                    break;
                }

                attribute_list_entry = (attribute_list_entry as usize + (*attribute_list_entry).entry_length as usize) as _;
                analyzed_bytes += (*attribute_list_entry).entry_length as u32;

            }
        } else {
            return None;   
        }
    }

    let mut runs: Vec<RunEntry> = vec![];
    let mut last_cluster_index = 0i64;
    
    if index_root != ptr::null_mut() {
        if found_extendend_entry { // Something weird happened, we have two INDEX_ROOT for the same entry
            return None;
        }

        if search_file_index_root_i30(index_root, name_to_search, &mut vcn_or_record_id) {
            return Some(vcn_or_record_id);
        }
    } else if !found_extendend_entry { // No INDEX_ROOT
        return None;
    }
    
    if vcn_or_record_id == u64::MAX {
        return None;
    }

    if found_extendend_entry {
        index_root = std::mem::transmute(&extended_entry_index_root);
    }

    if !index_allocation_attributes.is_empty(){
        for index_allocation_attr in index_allocation_attributes {
            get_data_run_list_from_non_resident_attribute(index_allocation_attr, &mut last_cluster_index, &mut 0, &mut 0, &mut false, mft_entry, &mut runs);
        }
    } 

    if attribute_list != ptr::null_mut() {
        get_data_run_list_from_resident_attribute_list_index_allocation_i30(attribute_list, &mut runs)
    }

    if runs.is_empty() { // We didn't find the name in INDEX ROOT and there is not INDEX ALLOCATION
        return None;
    }

    runs.sort_by_key(|run| run.first_vcn); // We sort based on the first vcn

    let wrapper = get_index_allocation_content_single_vector(runs);
    if wrapper.is_none() {
        return None;
    }

    let content = wrapper.unwrap();
    let content_ptr = content.as_ptr();
    let content_len = content.len();
    let bytes_per_cluster = get_ntfs_data().bytes_per_cluster;
    let name_to_search_u16: Vec<u16> = name_to_search.encode_utf16().collect();

    loop 
    {
        let offset = if vcn_or_record_id == 0 {
            0
        } else {
            vcn_or_record_id as usize * bytes_per_cluster as usize
        };

        if (content_ptr as usize + offset) > (content_ptr as usize + content_len - (*index_root).index_block_size as usize) {
            return None;
        }

        let block_ptr = (content_ptr as usize + offset) as *mut IndexAllocationBlock;
        let signature_str = String::from_utf8_lossy(&(*block_ptr).signature);
        if signature_str != lc!("INDX") {
            return None;
        }

        let max_len = content_len - (block_ptr as usize - content_ptr as usize);
        fix_sequence_number(block_ptr as _, max_len); //Index allocation blocks also use sequence numbers to check the integrity of the data
        let index_node_header: *mut IndexNodeHeader = addr_of_mut!((*block_ptr).index_node_header);
        let mut index_entry: *mut IndexEntryHeader = (index_node_header as usize + (*index_node_header).entries_offset as usize) as *mut _;
        let mut total_entries_size = (*index_node_header).total_entry_size as i32;

        while (index_entry as usize - content_ptr as usize) < content_len && total_entries_size > 0
        {

            if (*index_entry).flags & 0x02 != 0 {
                if (*index_entry).flags & 0x01 == 0 { // No child
                   return None
                } else {
                    let vcn_ptr = (index_entry as usize + (*index_entry).entry_size as usize - 8) as *mut u64;
                    vcn_or_record_id = *vcn_ptr; // We follow the VCN pointer
                    break;
                }
            }

            let fixed_file_name: *mut FileNameAttributeHeaderFixed = (index_entry as usize + size_of::<IndexEntryHeader>()) as *mut _;
           
            let file_ptr = (fixed_file_name as *mut u8).add(size_of::<FileNameAttributeHeaderFixed>()) as *const u16;
            let file_name_content: &[u16] = slice::from_raw_parts(file_ptr, (*fixed_file_name).filename_length as usize);
            let order = compare_ntfs_names(&name_to_search_u16, file_name_content);

            // https://harelsegev.github.io/posts/i30-parsers-output-false-entries.-heres-why/ indicates that this is not a b+tree but a b-tree
            if order == Ordering::Equal { 
                let entry_index = (*index_entry).file_reference();
                return Some(entry_index);
            } else if order == Ordering::Less {
                if (*index_entry).flags & 0x01 == 0 { // No child
                    return None;
                } else {
                    let vcn_ptr = (index_entry as usize + (*index_entry).entry_size as usize - 8) as *mut u64; // VCN field
                    vcn_or_record_id = *vcn_ptr; // We follow the VCN pointer 
                    break;
                } 
            } 

            // if Greater -> continue with next entry
            total_entries_size -= (*index_entry).entry_size as i32;
            index_entry = (index_entry as usize + (*index_entry).entry_size as usize) as *mut _;
        }
    }

}

/// Auxiliar function that searches a file name in the `$I30` index root attribute of an extended file record
/// or retrieves the VCN of the next index entry to analyze.
///
/// # Parameters
/// - `mft_entry`: Raw content of the extended file record.
/// - `name_to_search`: File name to locate.
/// - `vcn_or_entry_id`: Mutable reference to store the VCN or file record ID.
///
/// # Returns
/// `true` if the name or VCN is found, `false` otherwise.
unsafe fn search_file_name_index_root_extended_mft_entry(mft_entry: &Vec<u8>, name_to_search: &str, vcn_or_record_id: &mut u64, out_index_root: &mut IndexRootAttributeHeader) -> bool
{
    let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;
    let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return false;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + (*file_record_segment_header).first_attribute_offset as usize) as *mut AttributeHeader;
    let mut index_root: *mut IndexRootAttributeHeader = ptr::null_mut();
    let bytes_per_mft_file_records = get_ntfs_data().bytes_per_file_record_segment;

    while (attribute_ptr as isize - file_record_segment_header as isize) < bytes_per_mft_file_records as isize
    {
        if (*attribute_ptr).attribute_type == INDEX_ROOT_ATTRIBUTE  {
            if (*attribute_ptr).name_length != 0 {
                let name_bytes_ptr = (attribute_ptr as *const u8)
                    .add((*attribute_ptr).name_offset as usize);
                let len_bytes = (*attribute_ptr).name_length as usize * 2;
                let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
        
                let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_ptr).name_length as usize);
                for chunk in name_bytes.chunks_exact(2) {
                    utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                }
        
                if let Ok(name) = String::from_utf16(&utf16) {
                    if name.to_ascii_lowercase() == lc!("$i30") {
                        index_root = attribute_ptr as *mut _;
                        break;
                    }
                }
            }

        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }
        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    if index_root == ptr::null_mut() {
        false
    } else{
        *out_index_root = *index_root;
        search_file_index_root_i30(index_root, name_to_search, vcn_or_record_id)
    }

}

/// Searches the `$I30` index root attribute entries for a matching file name
/// or retrieves the VCN of the next index entry to analyze.
///
/// # Parameters
/// - `index_root`: Pointer to the index root attribute header.
/// - `name_to_search`: File name to locate.
/// - `vcn_or_entry_id`: Mutable reference to store the VCN or file record ID.
///
/// # Returns
/// `true` if the name or VCN is found, `false` otherwise.
unsafe fn search_file_index_root_i30(index_root: *mut IndexRootAttributeHeader, name_to_search: &str, vcn_or_entry_id: &mut u64) -> bool
{
    let index_node_header: *mut IndexNodeHeader = addr_of_mut!((*index_root).index_node_header);
    let mut index_entry: *mut IndexEntryHeader = (index_node_header as usize + (*index_node_header).entries_offset as usize) as *mut _;
    let mut total_entries_size = (*index_node_header).total_entry_size as i32;
    let name_to_search_u16: Vec<u16> = name_to_search.encode_utf16().collect();
    while total_entries_size > 0
    {
        if (*index_entry).flags & 0x02 != 0 {
            if (*index_entry).flags & 0x01 == 0 { // No child
                *vcn_or_entry_id = u64::MAX;
                return false;
            } else {
                let vcn_ptr = (index_entry as usize + (*index_entry).entry_size as usize - 8) as *mut u64;
                *vcn_or_entry_id = *vcn_ptr; // We continue the search in IndexAllocation (right branch)
                return false;
            }
        }

        let fixed_file_name: *mut FileNameAttributeHeaderFixed = (index_entry as usize + size_of::<IndexEntryHeader>()) as *mut _;
        let file_ptr = (fixed_file_name as *mut u8).add(size_of::<FileNameAttributeHeaderFixed>()) as *const u16;
        let file_name_content: &[u16] = slice::from_raw_parts(file_ptr, (*fixed_file_name).filename_length as usize);
        let order = compare_ntfs_names(&name_to_search_u16, file_name_content);
        
        if order == Ordering::Equal {
            *vcn_or_entry_id = (*index_entry).file_reference();
            return true;
        } else if order == Ordering::Less {
            if (*index_entry).flags & 0x01 == 0 { // No child
                *vcn_or_entry_id = u64::MAX;
                return false;
            } else {
                let vcn_ptr = (index_entry as usize + (*index_entry).entry_size as usize - 8) as *mut u64;
                *vcn_or_entry_id = *vcn_ptr; // We continue the search in IndexAllocation 
                return false;
            }

            // else we continue with the next entry
        } 

        // if greater -> continue with next entry
            
        total_entries_size -= (*index_entry).entry_size as i32;
        index_entry = (index_entry as usize + (*index_entry).entry_size as usize) as *mut _;
    }

    *vcn_or_entry_id = u64::MAX;
    false
}

/// Lists all files in a directory by traversing its `$I30` index.
///
/// # Parameters
/// - `full_path`: Absolute path of the target directory.
///
/// # Returns
/// `Some(HashMap<u64, DirectoryFilesList>)` with the files if found, `None` otherwise.
pub unsafe fn list_files_from_directory(full_path: &str) -> Option<HashMap<u64, DirectoryFilesList>>
{
    if full_path == "." {
        let mft_entry = get_mft_entry_copy(5).unwrap();
        list_files_from_mft_entry(&mft_entry.content);
        return None;
    }

    let mut split: Vec<&str> = full_path.split_terminator('\\').collect();
    if split.is_empty() {
        return None;
    } 

    if split.len() == 1 {
        let mft_entry = get_mft_entry_copy(5).unwrap();
        list_files_from_mft_entry(&mft_entry.content);
        return None;
    }
    
    let volume_letter = *split.first().unwrap();
    let directory_name = *split.last().unwrap();
    let mut index = 5; // root entry
    let mut next_entry: Option<ContentWrapper>; 
    
    loop 
    {
        next_entry = get_mft_entry_copy(index as _);
        if next_entry.is_none() {
            break;
        }

        split.remove(0);
        if split.is_empty() {
            next_entry = get_mft_entry_copy(index as _); 
            if next_entry.is_none() {
                break;
            }

            let mft_final_entry = next_entry.unwrap();
            if !is_directory(&mft_final_entry.content) {
                return None;
            }

            let result = list_files_from_mft_entry(&mft_final_entry.content);
            if result.is_none() {
                break;
            }

            return result;
        }

        let mft_entry = next_entry.unwrap();
        let ind = search_file_name_in_index_i30(&mft_entry.content, split[0]);
        if ind.is_none() {
            break;
        }

        index = ind.unwrap();
        
    }

    println!("{}", &lc!("[-] $I30 index search failed, fallback to sequential search..."));
    for (index, entry) in iter_mft_entries().enumerate()
    {
        let file_names= search_filename_in_mft_entry_by_str(&entry.content, directory_name, 0, false);
        if file_names.is_some()
        {
            let mut files_names = file_names.unwrap();
            for (_, data) in files_names.iter_mut() 
            {
                data.mft_entry_index = index;
                let retrieved_full_path = get_file_full_path(&data);
                for any_file_name in &data.all_names 
                {
                    let joined;
                    if retrieved_full_path.is_empty() {
                        joined = format!(r"{}\{}",volume_letter, any_file_name);
                    } else {
                        joined = format!(r"{}\{}\{}",volume_letter, retrieved_full_path, any_file_name);
                    }

                    let joined_u16: Vec<u16> = joined.encode_utf16().collect();
                    let full_path_u16: Vec<u16> = full_path.encode_utf16().collect();
                    let order = compare_ntfs_names(&joined_u16, &full_path_u16);
                    if order == Ordering::Equal 
                    {

                        let mut mft_entry = get_mft_entry_copy(data.mft_entry_index).unwrap();
                        let mut base_index = get_base_record_index(&mft_entry.content) as usize;
                        if base_index != 0 {
                            mft_entry = get_mft_entry_copy(base_index as _).unwrap();
                        } else {
                            base_index = data.mft_entry_index;
                        }

                        if !is_directory(&mft_entry.content) {
                            return None;
                        }

                        println!("[+] Directory path {} found. Entry index: {}", full_path, base_index);
                        return list_files_from_mft_entry(&mft_entry.content);
                    }
                }
            }
        }
    }

    println!("{}", &lc!("[-] Match not found."));
    None
}

/// Lists all files in a directory by reading the `$I30` index of its MFT entry.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry representing the directory.
///
/// # Returns
/// `Some(HashMap<u64, DirectoryFilesList>)` with the files if found, `None` otherwise.
unsafe fn list_files_from_mft_entry(mft_entry: &Vec<u8>) -> Option<HashMap<u64, DirectoryFilesList>>
{
    let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;

    let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return None;
    }

    if (*file_record_segment_header).flags & 0x02 == 0 {
        println!("{}", &lc!("[x] Selected entry is not a directory."));
        return None;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + (*file_record_segment_header).first_attribute_offset as usize) as *mut AttributeHeader;
    let mut attribute_list: *mut ResidentAttributeHeader = ptr::null_mut();
    let mut index_root: *mut IndexRootAttributeHeader = ptr::null_mut();
    let mut extended_entry_index_root = IndexRootAttributeHeader::default();
    let mut index_allocation_attributes: Vec<*mut NonResidentAttributeHeader> = vec![];
    let bytes_per_mft_file_records = get_ntfs_data().bytes_per_file_record_segment;
    let mut listed_files: HashMap<u64, DirectoryFilesList> = HashMap::new();
    let mut found_extendend_entry = false;

    while (attribute_ptr as isize - file_record_segment_header as isize) < bytes_per_mft_file_records as isize
    {
        if (*attribute_ptr).attribute_type == INDEX_ROOT_ATTRIBUTE  {
            if (*attribute_ptr).name_length != 0 {
                let name_bytes_ptr = (attribute_ptr as *const u8)
                    .add((*attribute_ptr).name_offset as usize);
                let len_bytes = (*attribute_ptr).name_length as usize * 2;
                let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
        
                let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_ptr).name_length as usize);
                for chunk in name_bytes.chunks_exact(2) {
                    utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                }
        
                if let Ok(name) = String::from_utf16(&utf16) {
                    if name.to_ascii_lowercase() == lc!("$i30") {
                        index_root = attribute_ptr as *mut _;
                    }
                }
            }

        } else if (*attribute_ptr).attribute_type == INDEX_ALLOCATION_ATTRIBUTE  { 
            if (*attribute_ptr).name_length != 0 {

                let name_bytes_ptr = (attribute_ptr as *const u8)
                    .add((*attribute_ptr).name_offset as usize);
                let len_bytes = (*attribute_ptr).name_length as usize * 2;
                let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
        
                let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_ptr).name_length as usize);
                for chunk in name_bytes.chunks_exact(2) {
                    utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                }
        
                if let Ok(name) = String::from_utf16(&utf16) {
                    if name.to_ascii_lowercase() == lc!("$i30") {
                        index_allocation_attributes.push(attribute_ptr as *mut _);
                    }
                }
            }
         
        } else if (*attribute_ptr).attribute_type == ATTRIBUTE_LIST_ATTRIBUTE {
            attribute_list = attribute_ptr as *mut _;
        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }
        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    if index_root == ptr::null_mut() {
        if attribute_list != ptr::null_mut() 
        {
            let mut attribute_list_entry = (attribute_list as usize + (*attribute_list).attribute_offset as usize) as *mut AttributeListEntry;
            let mut analyzed_bytes = (*attribute_list).attribute_offset as u32;

            while analyzed_bytes < (*attribute_list).attribute_length 
            {
                if (*attribute_list_entry).attribute_type == INDEX_ROOT_ATTRIBUTE 
                {
                    let name_bytes_ptr = (attribute_list_entry as *const u8).add((*attribute_list_entry).name_offset as usize);
                    let len_bytes = (*attribute_list_entry).name_length as usize * 2;
                    let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
            
                    let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_list_entry).name_length as usize);
                    for chunk in name_bytes.chunks_exact(2) {
                        utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                    }
            
                    if let Ok(name) = String::from_utf16(&utf16) {
                        if name.to_ascii_lowercase() == lc!("$i30") {
                            let index = (*attribute_list_entry).next_mft_entry_index();
                            let extended_entry = get_mft_entry_copy(index as _);
                            if extended_entry.is_none() {
                                return None;
                            }

                            let extended_entry = extended_entry.unwrap();
                            
                            let directories = list_files_from_index_root_extended_mft_entry(&extended_entry.content, &mut extended_entry_index_root);
                            if directories.is_none() {
                                return None;
                            }

                            let directories = directories.unwrap();
                            listed_files.extend(directories);
                            found_extendend_entry = true;

                            break;
                        }

                    }
                    
                } else if (*attribute_list_entry).attribute_type == TERMINATOR_ATTRIBUTE {
                    break;
                }

                attribute_list_entry = (attribute_list_entry as usize + (*attribute_list_entry).entry_length as usize) as _;
                analyzed_bytes += (*attribute_list_entry).entry_length as u32;

            }
        } else {
            return None;   
        }
    }

    let mut runs: Vec<RunEntry> = vec![];
    let mut last_cluster_index = 0i64;

    if index_root != ptr::null_mut() {
        if found_extendend_entry { // Something weird happened, we have two INDEX_ROOT for the same entry
            return None;
        }

        list_files_from_index_root(index_root, &mut listed_files);
    } else if !found_extendend_entry { // No INDEX_ROOT
        return None;
    }

    if found_extendend_entry {
        index_root = std::mem::transmute(&extended_entry_index_root);
    }

    if !index_allocation_attributes.is_empty(){
        for index_allocation_attr in index_allocation_attributes { // Get data run list from all INDEX ALLOCATION attrs
            get_data_run_list_from_non_resident_attribute(index_allocation_attr, &mut last_cluster_index, &mut 0, &mut 0, &mut false, mft_entry, &mut runs);
        }
    } 

    if attribute_list != ptr::null_mut() {
        // Look for INDEX ALLOCATION attrs in the attribute list
        get_data_run_list_from_resident_attribute_list_index_allocation_i30(attribute_list, &mut runs) 
    }

    if runs.is_empty() { // No additional entries in INDEX ALLOCATION
        sort_and_print_all_directories(&mut listed_files); 
        return Some(listed_files);
    }

    runs.sort_by_key(|run| run.first_vcn); // In this scenario sorting may be unnecessary, but w/e

    let wrapper = get_index_allocation_content(runs);
    if wrapper.is_none() {
        return None;
    }

    let wrapper = wrapper.unwrap();
    for content_wrapper in wrapper 
    {
        let mut content = content_wrapper.content;
        let content_len = content.len();
        let mut block_ptr = content.as_mut_ptr() as *mut IndexAllocationBlock;
        if content_len < (*index_root).index_block_size as usize || content_wrapper.offset == -1 {
            continue;
        }
        while (block_ptr as usize - content.as_mut_ptr() as usize) < content_len
        {
            let signature_str = String::from_utf8_lossy(&(*block_ptr).signature);
            if signature_str != lc!("INDX") {
                block_ptr = (block_ptr as usize + (*index_root).index_block_size as usize) as *mut _;
                continue;
            }

            let max_len = content_len - (block_ptr as usize - content.as_mut_ptr() as usize);
            fix_sequence_number(block_ptr as _, max_len); //Index allocation blocks also use sequence numbers to check the integrity of the data

            let index_node_header: *mut IndexNodeHeader = addr_of_mut!((*block_ptr).index_node_header);
            let mut index_entry: *mut IndexEntryHeader = (index_node_header as usize + (*index_node_header).entries_offset as usize) as *mut _;
            let mut total_entries_size = (*index_node_header).total_entry_size as i32;

            // (*index_entry).flags & 0x02) != 0 -> Last entry in the node; It does not contain a valid filename
            while ((*index_entry).flags & 0x02) == 0 && (index_entry as usize - content.as_mut_ptr() as usize) < content_len && total_entries_size > 0
            {
                let fixed_file_name: *mut FileNameAttributeHeaderFixed = (index_entry as usize + size_of::<IndexEntryHeader>()) as *mut _;
                if (*index_entry).file_reference() != 0 && (*fixed_file_name).parent_record_number() != 0 {
          
                    let file_ptr = (fixed_file_name as *mut u8).add(size_of::<FileNameAttributeHeaderFixed>()) as *const u16;
                    let file_content: &[u16] = slice::from_raw_parts(file_ptr, (*fixed_file_name).filename_length as usize);
                    let file_name = utf16_ptr_to_string(&file_content, (*fixed_file_name).filename_length as usize);

                    if file_name.is_some() {
                        let name = file_name.unwrap();
                        if let Some(value) = listed_files.get_mut(&(*index_entry).file_reference()) {
                            if (*fixed_file_name).namespace == 2 {
                                value.short_name = name;
                            } else {
                                value.filename = name;
                            } 
                        } else {
                            let mut listed_file = DirectoryFilesList::default();
                            listed_file.record_number = (*index_entry).file_reference();
                            listed_file.parent_record_number = (*fixed_file_name).parent_record_number();
                            if (*fixed_file_name).flags & 0x10000000 != 0 {
                                listed_file.entry_type = "Directory".to_string();
                            } else {
                                listed_file.entry_type = "File".to_string();
                            } 
        
                            if (*fixed_file_name).namespace == 2 { // I don't know if this is needed, DOS names do not seem to be used in $i30
                                listed_file.short_name = name;
                            } else {
                                listed_file.filename = name;
                            }
        
                            listed_files.insert((*index_entry).file_reference(), listed_file);
                        }
                    }
                }
                
                total_entries_size -= (*index_entry).entry_size as i32;
                index_entry = (index_entry as usize + (*index_entry).entry_size as usize) as *mut _;
            }

            block_ptr = (block_ptr as usize + (*index_root).index_block_size as usize) as *mut _;
        }  
    }

    sort_and_print_all_directories(&mut listed_files);   
    Some(listed_files)

}

/// Auxiliar function to list all files in a INDEX ROOT attribute from an extended file record.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry representing the directory.
///
/// # Returns
/// `Some(HashMap<u64, DirectoryFilesList>)` with the files if found, `None` otherwise.
unsafe fn list_files_from_index_root_extended_mft_entry(mft_entry: &Vec<u8>, out_index_root: &mut IndexRootAttributeHeader) -> Option<HashMap<u64, DirectoryFilesList>>
{
    let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;
    let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return None;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + (*file_record_segment_header).first_attribute_offset as usize) as *mut AttributeHeader;
    let mut index_root: *mut IndexRootAttributeHeader = ptr::null_mut();
    let bytes_per_mft_file_records = get_ntfs_data().bytes_per_file_record_segment;
    let mut listed_files: HashMap<u64, DirectoryFilesList> = HashMap::new();

    while (attribute_ptr as isize - file_record_segment_header as isize) < bytes_per_mft_file_records as isize
    {
        if (*attribute_ptr).attribute_type == INDEX_ROOT_ATTRIBUTE  {
            if (*attribute_ptr).name_length != 0 {
                let name_bytes_ptr = (attribute_ptr as *const u8)
                    .add((*attribute_ptr).name_offset as usize);
                let len_bytes = (*attribute_ptr).name_length as usize * 2;
                let name_bytes = slice::from_raw_parts(name_bytes_ptr, len_bytes);
        
                let mut utf16: Vec<u16> = Vec::with_capacity((*attribute_ptr).name_length as usize);
                for chunk in name_bytes.chunks_exact(2) {
                    utf16.push(u16::from_le_bytes([chunk[0], chunk[1]]));
                }
        
                if let Ok(name) = String::from_utf16(&utf16) {
                    if name.to_ascii_lowercase() == lc!("$i30") {
                        index_root = attribute_ptr as *mut _;
                        break;
                    }
                }
            }

        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }
        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    if index_root == ptr::null_mut() {
        None
    } else{
        *out_index_root = *index_root;
        list_files_from_index_root(index_root, &mut listed_files);
        Some(listed_files)
    }

}

/// Retrieves all file names contained in an index root attribute and adds them
/// to `listed_files`.
///
/// # Parameters
/// - `index_root`: Pointer to the index root attribute header.
/// - `listed_files`: Map to store the retrieved file entries.
unsafe fn list_files_from_index_root(index_root: *mut IndexRootAttributeHeader, listed_files: &mut HashMap<u64, DirectoryFilesList>)
{
    let index_node_header: *mut IndexNodeHeader = addr_of_mut!((*index_root).index_node_header);
    let mut index_entry: *mut IndexEntryHeader = (index_node_header as usize + (*index_node_header).entries_offset as usize) as *mut _;
    let mut total_entries_size = (*index_node_header).total_entry_size as i32;
    while (*index_entry).flags & 0x02 == 0 && total_entries_size > 0
    {

        let fixed_file_name: *mut FileNameAttributeHeaderFixed = (index_entry as usize + size_of::<IndexEntryHeader>()) as *mut _;
        if (*index_entry).file_reference() != 0 && (*fixed_file_name).parent_record_number() != 0 {

            let file_ptr = (fixed_file_name as *mut u8).add(size_of::<FileNameAttributeHeaderFixed>()) as *const u16;
            let file_content: &[u16] = slice::from_raw_parts(file_ptr, (*fixed_file_name).filename_length as usize);
            let file_name = utf16_ptr_to_string(&file_content, (*fixed_file_name).filename_length as usize);
            
            if file_name.is_some() {
                let name = file_name.unwrap();
                if let Some(value) = listed_files.get_mut(&(*index_entry).file_reference()) {
                    if (*fixed_file_name).namespace == 2 {
                        value.short_name = name;
                    } else {
                        value.filename = name;
                    } 
                } else {
                    let mut listed_file = DirectoryFilesList::default();
                    listed_file.record_number = (*index_entry).file_reference();
                    listed_file.parent_record_number = (*fixed_file_name).parent_record_number();
                    if (*fixed_file_name).flags & 0x10000000 != 0 {
                        listed_file.entry_type = "Directory".to_string();
                    } else {
                        listed_file.entry_type = "File".to_string();
                    } 

                    if (*fixed_file_name).namespace == 2 {
                        listed_file.short_name = name;
                    } else {
                        listed_file.filename = name;
                    }

                    listed_files.insert((*index_entry).file_reference(), listed_file);
                }

            }
        }
        
        total_entries_size -= 1;
        index_entry = (index_entry as usize + (*index_entry).entry_size as usize) as *mut _;
    }

}

pub unsafe fn show_info_mft_entry(input_directory: &str, name_to_search: &str) 
{
    let mut split: Vec<&str> = input_directory.split_terminator('\\').collect(); 
    if split.is_empty() {
        return;
    } 
    
    let volume_letter = *split.first().unwrap();
    let mut index = 5; // root entry
    let mut next_entry: Option<ContentWrapper>; 
    loop 
    {
        split.remove(0);
        next_entry = get_mft_entry_copy(index as _);
        if next_entry.is_none() {
            break;
        }

        if split.is_empty() {

            let last_dir_entry = next_entry.unwrap();
            let ind = search_file_name_in_index_i30(&last_dir_entry.content, name_to_search);
            if ind.is_none() {
                break;
            }

            index = ind.unwrap();
            show_info_mft_entry_by_index(index as _);
            return;
        }

        let mft_entry = next_entry.unwrap();
        let ind = search_file_name_in_index_i30(&mft_entry.content, split[0]);
        if ind.is_none() {
            break;
        }

        index = ind.unwrap();
    }

    println!("{}", &lc!("[-] Search in $I30 index failed, fallback to sequential search..."));
    for (index, entry) in iter_mft_entries().enumerate()
    {
        let file_names= search_filename_in_mft_entry_by_str(&entry.content, name_to_search, 0, false);
        if file_names.is_some()
        {
            let mut files_names = file_names.unwrap();
            for (_, file_data) in files_names.iter_mut() 
            {
                file_data.mft_entry_index = index;
                let retrieved_full_path = get_file_full_path(&file_data);
                for any_file_name in &file_data.all_names 
                {
                    let mut joined;
                    if retrieved_full_path.is_empty() {
                        joined = format!(r"{}", volume_letter);
                    } else {
                        joined = format!(r"{}\{}",volume_letter, retrieved_full_path);
                    } 

                    let joined_u16: Vec<u16> = joined.encode_utf16().collect();
                    let full_path_u16: Vec<u16> = input_directory.encode_utf16().collect();
                    let order = compare_ntfs_names(&joined_u16, &full_path_u16);
                    if order == Ordering::Equal 
                    {
                        joined = format!(r"{}\{}", joined, any_file_name);

                        let mft_entry = get_mft_entry_copy(file_data.mft_entry_index).unwrap();
                        let mut base_index = get_base_record_index(&mft_entry.content) as usize;
                        if base_index == 0 {
                           base_index = file_data.mft_entry_index;
                        }
                        
                        if get_mft_len() < base_index {
                            return; 
                        }

                        println!("[+] Entry {} matched. Record index: {}", joined, base_index);
                        show_info_mft_entry_by_index(base_index);
                        return;
                    }
                }
            }   
        }
    }
}

pub unsafe fn show_info_mft_entry_by_regex(input_file_name: Regex, only_hidden: bool, verbose: bool) 
{
    let volume_letter = ".";
    let mut analyzed_entries: Vec<usize> = vec![];
    for (index, entry) in iter_mft_entries().enumerate()
    {

        if only_hidden && !is_hidden(&entry.content) {
            continue;
        }

        let file_names= search_filename_in_mft_entry_by_regex(&entry.content, &input_file_name);
        if file_names.is_some()
        {
            let mut files_names = file_names.unwrap();
            for (_, file_data) in files_names.iter_mut() 
            {
                file_data.mft_entry_index = index;
                let retrieved_full_path = get_file_full_path(&file_data);
                for any_file_name in &file_data.all_names 
                { 
                    let mut joined;
                    if retrieved_full_path.is_empty() {
                        joined = format!(r"{}", volume_letter);
                    } else {
                        joined = format!(r"{}\{}",volume_letter, retrieved_full_path);
                    } 

                    let mft_entry = get_mft_entry_copy(file_data.mft_entry_index).unwrap();
                    let mut base_index = get_base_record_index(&mft_entry.content) as usize;
                    if base_index == 0 {
                        base_index = file_data.mft_entry_index;
                    }
                    
                    if get_mft_len() < base_index {
                        continue; 
                    }

                    if !analyzed_entries.contains(&index)
                    {
                        analyzed_entries.push(index);

                        joined = format!(r"{}\{}", joined, any_file_name);
                        println!("[+] Entry {} matched. Record index: {}", joined, base_index);
        
                        if verbose {
                            show_info_mft_entry_by_index(file_data.mft_entry_index);
                        } else {
                            show_info_mft_entry_by_index_minimal(file_data.mft_entry_index);
                        }
                    }
                }
            }   
        }
    }
}

pub unsafe fn show_info_mft_entry_by_index(index: usize)
{
    let mut output: Vec<String> = vec![];
    output.push(format!("[-] Record index: {}\n", index));
    let mft_entry = get_mft_entry_copy(index);
    if mft_entry.is_none() {
        return;
    }

    let mft_entry = mft_entry.unwrap();
    let mft_entry_ptr = mft_entry.content.as_ptr() as *const FileRecordSegmentHeader;

    let signature_str = String::from_utf8_lossy(&(*mft_entry_ptr).signature);
    if signature_str != lc!("FILE") {
        output.push(format!("[x] MFT entry signature not detected.\n"));
        let _ = handle_strings(&output);
        return;
    }

    let frn: String = (*mft_entry_ptr).fsutil_id_hex();
    output.push(format!("{}{}\n", lc!("[-] File Reference Number: 0x"), frn));
    output.push(format!("{}{}\n", lc!("[-] Hidden entry: "), (*mft_entry_ptr).flags & 0x1 == 0));

    if (*mft_entry_ptr).flags & 0x2 != 0 {
       output.push(format!("{}\n", lc!("[-] Entry type: directory")));
    } else {
        output.push(format!("{}\n", lc!("[-] Entry type: file")));
        let mut size = 0;
        let mut compression_unit = 0;
        let mut compressed = false;
        let _ = get_data_run_list_from_entry(&mft_entry.content, &mut 0, &mut size, &mut compression_unit,  &mut compressed, &mut 0);
        output.push(format!("{}{}\n", lc!("[-] Size: "), size));
        output.push(format!("{}{}\n", lc!("[-] Compressed: "), (compression_unit != 0 && compressed)));
    }

    let standard_information_attribute = get_mft_entry_standard_attribute(&mft_entry.content);
    if let Some(si) = standard_information_attribute {
        output.push(format!("{}{}\n", lc!("[-] Creation time: "), si.creation_time()));
        output.push(format!("{}{}\n", lc!("[-] Modification time: "), si.modification_time()));
        output.push(format!("{}{}\n", lc!("[-] Last time accessed: "), si.accessed_time()));
    }
        
    let file_names = search_filename_in_mft_entry_by_str(&mft_entry.content, "", 0, true);
    if file_names.is_some() {
        let file_names = file_names.unwrap();
        if file_names.len() != 0 {
            output.push(format!("{}\n",lc!("[-] Filenames:")));
            for (_, file_data) in &file_names {
                let retrieved_full_path = get_file_full_path(&file_data);
                for any_file_name in &file_data.all_names 
                {
                    let joined;
                    if retrieved_full_path.is_empty() {
                        joined = format!(r"\{}", any_file_name);
                    } else {
                        joined = format!(r"\{}\{}", retrieved_full_path, any_file_name);
                    }
                    output.push(format!("\t- {}\n", joined));
                }
            }
        }
    }

    if entry_has_reparse_point(&mft_entry.content) {
        let mut target_path = String::default();
        let _ = untangle_reparse_point(&mft_entry.content, &mut target_path, true, &mut false);
        if target_path != String::default() {
            output.push(format!("{}{}\n", lc!("[-] Reparse point target: "), target_path));
        }
    }
    output.push(format!("{}\n",lc!("-----------------------------------------------")));

    let _ = handle_strings(&output);
}

pub unsafe fn show_info_mft_entry_by_index_minimal(index: usize)
{
    let mut output: Vec<String> = vec![];
    let mft_entry = get_mft_entry_copy(index);
    if mft_entry.is_none() {
        return;
    }

    let mft_entry = mft_entry.unwrap();
        
    let file_names = search_filename_in_mft_entry_by_str(&mft_entry.content, "", 0, true);
    if file_names.is_some() {
        let file_names = file_names.unwrap();
        if file_names.len() != 0 {
            output.push(format!("{}\n",lc!("[-] Filenames:")));
            for (_, file_data) in &file_names {
                let retrieved_full_path = get_file_full_path(&file_data);
                for any_file_name in &file_data.all_names 
                {
                    let joined;
                    if retrieved_full_path.is_empty() {
                        joined = format!(r"\{}", any_file_name);
                    } else {
                        joined = format!(r"\{}\{}", retrieved_full_path, any_file_name);
                    }
                    output.push(format!("\t- {}\n", joined));
                }
            }
        }
    }

    output.push(format!("{}\n",lc!("-----------------------------------------------")));

    let _ = handle_strings(&output);
}

/// Displays information about unused MFT entries.
pub unsafe fn show_hidden_entries() 
{
    for (index, mft_entry) in iter_mft_entries().enumerate() {  
        if is_hidden(&mft_entry.content){
            show_info_mft_entry_by_index(index);
        }
    }
}

pub unsafe fn decompress_lznt1_unit(unit_stored: &[u8], unit_size: usize) -> Result<Vec<u8>, ()> 
{
    let mut out = vec![0u8; unit_size];
    let mut final_size: u32 = 0;

    let ntdll = dinvoke_rs::dinvoke::get_module_base_address(&lc!("ntdll.dll"));
    let function_ptr: RtlDecompressBuffer;
    let ret_value: Option<i32>;

    // It seems RtlDecompressBuffer parses the LZNT1 headers and all, I'm just passing the whole logical unit and it seems to be working
    dinvoke_rs::dinvoke::dynamic_invoke!(
        ntdll,
        &lc!("RtlDecompressBuffer"),
        function_ptr,
        ret_value,
        COMPRESSION_FORMAT_LZNT1,
        out.as_mut_ptr(),
        out.len() as u32,
        unit_stored.as_ptr(),
        unit_stored.len() as u32,
        &mut final_size as *mut u32,
    );

    if ret_value.unwrap() != 0 { 
        return Err(()); 
    }

    let n = final_size as usize;
    if n == 0 || n > unit_size { 
        return Err(()); 
    }

    out.truncate(n);
    Ok(out)
}

/*
    For my future self: The file content is divided into compression units, which comprise as many clusters as indicated by clusters_per_unit. 
    The idea is to iterate over the list of VCNs in the stream content, grouping them by compression unit. 
    If a compression unit begins with a sparse VCN, it is assumed that it is not compressed. If it begins with a real VCN, then it may be compressed, 
    in which case we pass only the content of the real VCNs (without sparse) to decompress_lznt1_unit. If decompression is successful, 
    it will be padded with zeros at the end, so we will have the complete content of the unit. If not, the content of the unit is assembled 
    by simply joining the content of the VCNs that compose it (here the sparse ones are taken into account).
*/
fn process_units(vcn_list: &[VCN], cluster_size: usize, clusters_per_unit: usize, file_size: u64, stream_marked_compressed: bool) -> Option<Vec<u8>> 
{
    if clusters_per_unit <= 0 { // Can this even happen?
        return None; 
    } 

    let bytes_per_unit = clusters_per_unit * cluster_size;
    let total_clusters_needed = ((file_size + (cluster_size as u64) - 1) / (cluster_size as u64)) as usize; // round up

    if vcn_list.len() < total_clusters_needed {
        return None;
    }

    let mut final_output = Vec::with_capacity(file_size as usize);
    let mut unit_index = 0usize;
    let mut bytes_remaining = file_size as usize;

    while bytes_remaining > 0 {
        let start = unit_index * clusters_per_unit;
        let end = (start + clusters_per_unit).min(vcn_list.len());
        let unit_vcns = &vcn_list[start..end];

        let logical_len = bytes_remaining.min(bytes_per_unit);

        let starts_sparse = unit_vcns.first().map(|v| v.is_sparse).unwrap_or(true);
        let first_sparse  = unit_vcns.iter().position(|v| v.is_sparse);

        // I don't know whether I should keep this check or not
        //let only_tail_sparse = has_sparse && !starts_sparse && !has_sparse_middle; 

        // Unit candidate to LZNT1 decompression
        let mut produced: Option<Vec<u8>> = None;
        if stream_marked_compressed && !starts_sparse {
            let run_end = first_sparse.unwrap_or(unit_vcns.len());
            // Adjacent real vcns
            let mut stored_prefix = Vec::new();
            for i in 0..run_end {
                let v = &unit_vcns[i];
                let off = i * cluster_size;
                if off >= logical_len { 
                    break; 
                }

                // In case we don't have to take the whole content of the last VCN
                // because it would exceed the file size
                let take = (logical_len - off).min(v.content.len()); 
                stored_prefix.extend_from_slice(&v.content[..take]);
            }

            if !stored_prefix.is_empty() {
                match unsafe { decompress_lznt1_unit(&stored_prefix, bytes_per_unit) } {
                    Ok(mut dec) => {
                        if dec.len() > logical_len { 
                            dec.truncate(logical_len); 
                        } else if dec.len() < logical_len { 
                            dec.resize(logical_len, 0); // Fill with zeros at the end if needed
                        }

                        produced = Some(dec);
                    }
                    Err(_) => {
                        // Decompression failed, we will just assemble the content later
                    }
                }
            }
        }

        // Uncompressed logic unit
        if produced.is_none() {
            // We start from a whole 0's buffer and we just overwrite the bytes of the real content (so we already have the sparse vcns content in place)
            let mut unit_buf = vec![0u8; logical_len]; 
            for (i, v) in unit_vcns.iter().enumerate() {
                if v.is_sparse { 
                    continue; 
                }

                let off = i * cluster_size;
                if off >= logical_len { 
                    break; 
                }
                let n = (logical_len - off).min(v.content.len());
                unit_buf[off..off + n].copy_from_slice(&v.content[..n]);
            }
            produced = Some(unit_buf);
        }

        final_output.extend_from_slice(&produced.unwrap());
        bytes_remaining -= logical_len;
        unit_index += 1;
    }

    Some(final_output)
}

/// We replace USN by the corresponding value in USA
/// 
/// Works both for Index Allocation Block and File Record
unsafe fn fix_sequence_number(buffer: *mut u8, max_len: usize)
{
    let ntfs_data = get_ntfs_data();

    let index_allocation_block = buffer as *const IndexAllocationBlock;
    let usa_offset =  (*index_allocation_block).usa_offset as usize;
    let usa_size =  (*index_allocation_block).usa_count as usize * 2;

    if usa_offset + usa_size > max_len{
        return;
    }

    let mut usa_ptr =  (buffer as usize + usa_offset + 2) as *mut u16;
    let sector_size = ntfs_data.bytes_per_sector;
    for i in 1..(usa_size/2) {
        let sector_end = i * sector_size as usize;
        let dst = sector_end - 2;
        let dst_ptr = (buffer as usize + dst) as *mut u16;
        *dst_ptr = *usa_ptr;
        usa_ptr = usa_ptr.add(1);
    }
}

unsafe fn entry_has_reparse_point(mft_entry: &Vec<u8>) -> bool 
{
    let first_file_record_segment_header = *(mft_entry.as_ptr() as *const FileRecordSegmentHeader);

    let signature_str = String::from_utf8_lossy(&first_file_record_segment_header.signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return false;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + first_file_record_segment_header.first_attribute_offset as usize) as *mut AttributeHeader;
    let mut attribute_list: *mut ResidentAttributeHeader = ptr::null_mut();

    loop 
    {
        if (*attribute_ptr).attribute_type == REPARSE_POINT_ATTRIBUTE  { 
            return true;
        } else if (*attribute_ptr).attribute_type == ATTRIBUTE_LIST_ATTRIBUTE {
            attribute_list = attribute_ptr as *mut _;
        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }
        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    if attribute_list == ptr::null_mut() {
        return false;
    }
    
    let mut attribute_list_entry = (attribute_list as usize + (*attribute_list).attribute_offset as usize) as *mut AttributeListEntry;
    let mut analyzed_bytes = (*attribute_list).attribute_offset as u32;

    while analyzed_bytes < (*attribute_list).attribute_length 
    {
        if (*attribute_list_entry).attribute_type == REPARSE_POINT_ATTRIBUTE {
            return true;
        } else if (*attribute_list_entry).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }

        attribute_list_entry = (attribute_list_entry as usize + (*attribute_list_entry).entry_length as usize) as _;
        analyzed_bytes += (*attribute_list_entry).entry_length as u32;

    }

    false
}

/// Retrieves the content of a file associated with an MFT entry containing
/// a `reparse_point` attribute.  
/// If `retrieve_target` is `true`, returns the target path instead of the file content.
///
/// # Parameters
/// - `mft_entry`: Raw content of the MFT entry.
/// - `full_path`: Mutable reference to store the resolved target path if requested.
/// - `retrieve_target`: Whether to return the target path instead of the file content.
///
/// # Returns
/// `Some(Vec<u8>)` with the file content or `None` if not found.
unsafe fn untangle_reparse_point(mft_entry: &Vec<u8>, full_path: &mut String, retrieve_target: bool, is_wof: &mut bool) -> Option<Vec<u8>>
{

    let first_file_record_segment_header = *(mft_entry.as_ptr() as *const FileRecordSegmentHeader);

    let signature_str = String::from_utf8_lossy(&first_file_record_segment_header.signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return None;
    }

    let mut attribute_ptr = (mft_entry.as_ptr() as usize + first_file_record_segment_header.first_attribute_offset as usize) as *mut AttributeHeader;
    let mut attribute_list: *mut ResidentAttributeHeader = ptr::null_mut();

    loop 
    {
        if (*attribute_ptr).attribute_type == REPARSE_POINT_ATTRIBUTE  
        { 
            let reparse_point_attribute = attribute_ptr as *mut ReparsePointSymlinkAttributeHeader;
            if (*reparse_point_attribute).reparse_tag != REPARSE_POINT_SYMLINK && (*reparse_point_attribute).reparse_tag != REPARSE_POINT_MOUNT_POINT{
                if (*reparse_point_attribute).reparse_tag == IO_REPARSE_TAG_WOF {
                    println!("{}", &lc!("[x] WOF compressed data detected. Operation not supported."));
                    *is_wof = true;
                } else {
                    println!("{}{:x}.", &lc!("[x] Unsupported reparse point detected: "), {(*reparse_point_attribute).reparse_tag});
                }
                
                return None; // We only analyze symbolic links and mount points for now.
            }


            let mut path_buffer_ptr = reparse_point_attribute as usize + size_of::<ReparsePointSymlinkAttributeHeader>();
            if (*reparse_point_attribute).reparse_tag == REPARSE_POINT_MOUNT_POINT {
                path_buffer_ptr -= 4; // Mount point structure is similar to symlink but 4 bytes smaller (corresponding to field "flags")  
            }

            let path_buffer_offset = path_buffer_ptr - mft_entry.as_ptr() as usize;
           
            let print_name_offset = path_buffer_offset + (*reparse_point_attribute).print_name_offset as usize;
            if print_name_offset + (*reparse_point_attribute).print_name_length as usize >= mft_entry.len() {
                return None;
            }

            let print_name = &mft_entry[print_name_offset..print_name_offset + (*reparse_point_attribute).print_name_length as usize]; 
            let print_name_u16: Vec<u16> = print_name.chunks(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
            let mut print_name_str = String::from_utf16(&print_name_u16).unwrap();

            if retrieve_target {
                *full_path = print_name_str;
                return None;
            }

            if (*reparse_point_attribute).reparse_tag == REPARSE_POINT_SYMLINK && (*reparse_point_attribute).flags == 1 { // relative path
                print_name_str = resolve_relative_path(full_path, &print_name_str)
            }

            let split: Vec<&str> = print_name_str.rsplitn(2, '\\').collect();
            return read_file_from_mft(split[1], split[0]);

        } else if (*attribute_ptr).attribute_type == ATTRIBUTE_LIST_ATTRIBUTE {
            attribute_list = attribute_ptr as *mut _;
        } else if (*attribute_ptr).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }
        attribute_ptr = (attribute_ptr as usize + (*attribute_ptr).length as usize) as _;
    }

    if attribute_list == ptr::null_mut() {
        return None;
    }

    let mut attribute_list_entry = (attribute_list as usize + (*attribute_list).attribute_offset as usize) as *mut AttributeListEntry;
    let mut analyzed_bytes = (*attribute_list).attribute_offset as u32;

    while analyzed_bytes < (*attribute_list).attribute_length 
    {
        if (*attribute_list_entry).attribute_type == REPARSE_POINT_ATTRIBUTE {
            let index = (*attribute_list_entry).next_mft_entry_index();

            let new_mft_entry = get_mft_entry_copy(index as _);
            if new_mft_entry.is_none() {
                return None;
            }

            return untangle_reparse_point(&new_mft_entry.unwrap().content, full_path, retrieve_target, is_wof);
            
        } else if (*attribute_list_entry).attribute_type == TERMINATOR_ATTRIBUTE {
            break;
        }

        attribute_list_entry = (attribute_list_entry as usize + (*attribute_list_entry).entry_length as usize) as _;
        analyzed_bytes += (*attribute_list_entry).entry_length as u32;

    }

    None
}

fn sort_and_print_all_directories(listed_files: &mut HashMap<u64, DirectoryFilesList>)
{
    let mut values: Vec<&DirectoryFilesList> = listed_files.values().collect();

    values.sort_by(|a, b| {
        match (a.filename.is_empty(), b.filename.is_empty()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.filename.cmp(&b.filename),
        }
    });

    let mut i = 0;
    for v in values {
        match v.short_name.as_str() {
            "" => println!("- {} ({})", v.filename, v.entry_type),
            _ => println!("- {} / {} ({})", v.filename, v.short_name, v.entry_type),
        }

        i+=1;
    } 
    
    println!("\n{}{}", &lc!("[-] Items: "), i);
}

unsafe fn get_base_record_index(mft_entry: &Vec<u8>) -> u64 
{
    let file_record_segment_header = mft_entry.as_ptr() as *const FileRecordSegmentHeader;

    let signature_str = String::from_utf8_lossy(&(*file_record_segment_header).signature);
    if signature_str != lc!("FILE") {
        println!("{}", &lc!("[x] MFT entry signature does not match."));
        return 0;
    }

    (*file_record_segment_header).base_record_index()
}