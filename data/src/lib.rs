#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::{sync::RwLock, time::{SystemTime, UNIX_EPOCH}};
use chrono::{DateTime, Duration, Local, TimeZone, Utc};
use once_cell::sync::Lazy;
use windows::Win32::Foundation::HANDLE;

pub type SetFilePointerEx = unsafe extern "system" fn (HANDLE, i64, *mut i64, u32) -> bool;
//pub type DeviceIoControl = unsafe extern "system" fn (HANDLE, u32, PVOID, u32, PVOID, u32, *mut u32, *mut OVERLAPPED) -> bool;
pub type RtlDecompressBuffer = unsafe extern "system" fn (u16, *mut u8, u32, *const u8, u32, *mut u32) -> i32;

//const FSCTL_GET_NTFS_VOLUME_DATA: u32 = 0x00090064;

pub const STANDARD_INFORMATION_ATTRIBUTE: u32 = 0x10;
pub const ATTRIBUTE_LIST_ATTRIBUTE: u32 = 0x20;
pub const FILE_NAME_ATTRIBUTE: u32 = 0x30;
pub const DATA_ATTRIBUTE: u32 = 0x80;
pub const INDEX_ROOT_ATTRIBUTE: u32 = 0x90;
pub const INDEX_ALLOCATION_ATTRIBUTE: u32 = 0xA0;
pub const REPARSE_POINT_ATTRIBUTE: u32 = 0xC0;
pub const TERMINATOR_ATTRIBUTE: u32 = 0xFFFFFFFF;
pub const REPARSE_POINT_SYMLINK: u32 = 0xA000000C;
pub const REPARSE_POINT_MOUNT_POINT: u32 = 0xA0000003;
pub const IO_REPARSE_TAG_WOF: u32 = 0x80000017;
pub const COMPRESSION_FORMAT_LZNT1: u16 = 0x0002;
pub const WOF_PROVIDER_WIM: u32 = 1;
pub const WOF_PROVIDER_FILE: u32 = 2;
pub const WIM_PROVIDER_HASH_SIZE: usize = 20;

pub enum Command {
    ReadFile,
    ReadByIndex,
    Rebuild,
    Ls,
    Show,
    ShowByRegex,
    ShowByIndex,
    ShowHidden,
    SetTarget,
    Output,
    Help,
    Exit,
}
impl Command {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            s if s == lc!("read_file") => Some(Self::ReadFile),
            s if s == lc!("read_by_index") => Some(Self::ReadByIndex),
            s if s == lc!("rebuild") => Some(Self::Rebuild),
            s if s == lc!("ls") => Some(Self::Ls),
            s if s == lc!("show") => Some(Self::Show),
            s if s == lc!("show_by_regex") => Some(Self::ShowByRegex),
            s if s == lc!("show_by_index") => Some(Self::ShowByIndex),
            s if s == lc!("show_hidden") => Some(Self::ShowHidden),
            s if s == lc!("set_target") => Some(Self::SetTarget),
            s if s == lc!("output") => Some(Self::Output),
            s if s == lc!("help") => Some(Self::Help),
            s if s == lc!("exit") => Some(Self::Exit),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct ContentWrapper {
    pub offset: i64, // offset in bytes from the beginning of the volume where the contents are located
    pub content: Vec<u8>
}

// Structure describing the volume information returned by FSCTL_GET_NTFS_VOLUME_DATA.
// https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_volume_data_buffer
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NTFSVolumeDataBuffer {
    pub volume_serial_number: i64,            // LARGE_INTEGER
    pub number_sectors: i64,                  // LARGE_INTEGER
    pub total_clusters: i64,                  // LARGE_INTEGER
    pub free_clusters: i64,                   // LARGE_INTEGER
    pub total_reserved: i64,                  // LARGE_INTEGER
    pub bytes_per_sector: u32,
    pub bytes_per_cluster: u32,
    pub bytes_per_file_record_segment: u32, // Usually 1024 bytes (1KB)
    pub clusters_per_file_record_segment: u32,
    pub mft_valid_data_length: i64,           // LARGE_INTEGER
    pub mft_start_lcn: i64,                   // LARGE_INTEGER
    pub mft2_start_lcn: i64,                  // LARGE_INTEGER
    pub mft_zone_start: i64,                  // LARGE_INTEGER
    pub mft_zone_end: i64,                    // LARGE_INTEGER
}

// Basic structure of the header of a File Record in MFT.
// https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header
// https://handmade.network/forums/articles/t/7002-tutorial_parsing_the_mft
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FileRecordSegmentHeader {
    pub signature: [u8; 4], // "FILE" signature (0x46, 0x49, 0x4C, 0x45)
    pub usa_offset: u16,
    pub usa_count: u16,
    pub log_sequence: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16, // The different flags bits indicate different things, the first one is whether this entry it is in use or not (0x1) and the second one is whether it is a directory (0x2).
    pub real_size_of_file_record: u32,
    pub allocated_size_of_file_record: u32,
    // In the case of an extended MFT entry, this field points to the base entry; entries have indices 0 - n  
    // this seems a good way to determine if an MFT entry its an extension record (0 = base record, otherwise extension record)
    pub base_file_record: u64, 
    pub next_attribute_instance: u16,
    pub unused: u16,
    pub record_number: u32
}
impl FileRecordSegmentHeader {
    pub fn frn64(&self) -> u64 {
        ( (self.sequence_number as u64) << 48 )
        |  (self.record_number   as u64)
    }

    /// Build the exact 16 bytes expected by fsutil (and NtCreateFile):
    /// - first 8 bytes to zero
    /// - then 8 bytes with FRN64 in big-endian
    pub fn frn128_be_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        // FRN64 in big-endian from the eighth byte onward
        buf[8..16].copy_from_slice(&self.frn64().to_be_bytes());
        buf
    }

    /// Print that buffer as a 32-digit hex string,
    /// Equal output to what fsutil shows you (without the "0x" at the start).
    pub fn fsutil_id_hex(&self) -> String {
        self
            .frn128_be_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    pub fn base_record_index(&self) -> u64 {
        self.base_file_record & 0x0000FFFFFFFFFFFF
    }

}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AttributeHeader {
    pub attribute_type: u32, // The type of attribute. We'll be interested in $DATA (0x80), and $FILE_NAME (0x30).
    pub length: u32, // The length of the attribute in the file record.
    pub non_resident: u8, // 0 = attribute's contents is stored within the file record in the MFT; 1 = it's stored elsewhere
    pub name_length: u8,
    pub name_offset: u16,
    pub flags: u16,
    pub attribute_id: u16
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]

pub struct ResidentAttributeHeader {
    pub base_header: AttributeHeader,
    pub attribute_length: u32,
    pub attribute_offset: u16,
    pub indexed: u8,
    pub unused: u8
}

#[repr(C, packed)]
pub struct NonResidentAttributeHeader {
    pub base_header: AttributeHeader,
    pub first_cluster: u64,
    pub last_cluster: u64, 
    pub data_runs_offset: u16,
    pub compression_unit: u16, 
    pub unused: u32, 
    pub attribute_allocated: u64, // How many bytes are reserved in total on disk for the "attribute" (if $DATA, it is the size of the content of the file on disk).
    pub attribute_size: u64, // The logical size of the attribute -> The final size of the attribute's content at the end, sparse data included
    pub stream_data_size: u64 // Valid bytes within the stream (sparse, EFS, compression), does not indicate the final size of the attribute at all
}

#[repr(C, packed)]
pub struct AttributeListEntry {
    pub attribute_type: u32,
    pub entry_length: u16,
    pub name_length: u8,
    pub name_offset: u8,
    pub start_vcn: u64,
    pub base_file_reference: u64, // This determines both the index of the entry where the attribute lives and the sequence number as usual.
    pub attribute_id: u16
    // Here you can optionally include the name of the attribute if it is named, but there doesn't have to be anything
}

impl AttributeListEntry {
    pub fn next_mft_entry_index(&self) -> u64 {
        self.base_file_reference & 0x0000FFFFFFFFFFFF
    }

    pub fn sequence_number(&self) -> u16 {
        (self.base_file_reference >> 48) as u16
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct StandardInformationAttributeHeader {
    pub resident_attribute: ResidentAttributeHeader,
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_modified_time: u64,
    pub access_time: u64
    // I don't care about other fields atm
}

impl StandardInformationAttributeHeader {
    pub fn creation_time(&self) -> String  {
        self.filetime_to_datetime(self.creation_time)
    }

    pub fn modification_time(&self) -> String  {
        self.filetime_to_datetime(self.modification_time)
    }

    pub fn accessed_time(&self) -> String  {
        self.filetime_to_datetime(self.access_time)
    }

    fn filetime_to_datetime(&self, filetime: u64) -> String  {
        let windows_epoch = Utc.with_ymd_and_hms(1601, 1, 1, 0, 0, 0).unwrap();
        let seconds = filetime / 10_000_000;
        let nanos = (filetime % 10_000_000) * 100;
        let utc_time = windows_epoch + Duration::seconds(seconds as i64) + Duration::nanoseconds(nanos as i64);

        let local_time: DateTime<Local> = utc_time.with_timezone(&Local);
        local_time.format("%d/%m/%Y %H:%M").to_string()
    }
}

#[repr(C, packed)]
pub struct FileNameAttributeHeader {
    pub resident_attribute: ResidentAttributeHeader,
    pub parent_and_sequence_number: u64,
    pub creation_time: u64,
    pub modification_time: u64,
    pub metadata_modification_time: u64,
    pub read_time: u64,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub repase: u32,
    pub filename_length: u8, // The length of the filename in wide chars
    pub namespace: u8, // If this = 2 then it's the DOS name of the file (short name)
}

impl FileNameAttributeHeader {
    pub fn parent_record_number(&self) -> u64 {
        self.parent_and_sequence_number & 0x0000FFFFFFFFFFFF
    }

    pub fn _sequence_number(&self) -> u16 {
        (self.parent_and_sequence_number >> 48) as u16
    }
}

#[repr(C, packed)]
pub struct FileNameAttributeHeaderFixed { // Used for index entries parsing, the same as FileNameAttributeHeader but removing the attribute header
    pub parent_and_sequence_number: u64,
    pub creation_time: u64,
    pub modification_time: u64,
    pub metadata_modification_time: u64,
    pub read_time: u64,
    pub allocated_size: u64,
    pub real_size: u64,
    pub flags: u32,
    pub repase: u32,
    pub filename_length: u8, // The length of the filename in wide chars
    pub namespace: u8, // If this = 2 then it's the DOS name of the file (short name)
}

impl FileNameAttributeHeaderFixed {
    pub fn parent_record_number(&self) -> u64 {
        self.parent_and_sequence_number & 0x0000FFFFFFFFFFFF
    }

    pub fn _sequence_number(&self) -> u16 {
        (self.parent_and_sequence_number >> 48) as u16
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ReparsePointSymlinkAttributeHeader {
    pub resident_attribute: ResidentAttributeHeader,
    pub reparse_tag: u32, // 0xA000000C for symlink
    pub reparse_data_length: u16, // len following 'reserved' attribute
    pub reserved: u16,

    // symlink attributes, mountpoint has the same but removing the 'flags' field
    pub substitute_name_offset: u16, // Offset inside PathBuffer in bytes -> this is the string we are interested in to know where it points to
    pub substitute_name_length: u16, // length in bytes
    pub print_name_offset: u16, // This is the string shown to the user
    pub print_name_length: u16,
    pub flags: u32 // 0 = absolute path, 1 = relative path

    // Here is located the path buffer, in u16 format, whose length we don't know at compilation time
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WofExternalInfo {
    pub version: u32,   // 1 for WIM, 2 for FILE
    pub provider: u32,  // WOF_PROVIDER_WIM or WOF_PROVIDER_FILE
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileProviderExternalInfoV0 {
    pub version: u32,     // Always 1
    pub algorithm: u32,   // Compression algorithm
    //pub flags: u32, -> According to https://learn.microsoft.com/es-es/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_provider_external_info_v1 we should have this
    // additional field, but it seems it doesn't exist on win10+. 
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WimProviderExternalInfo {
    pub version: u32, // Always 1
    pub flags: u32,
    pub data_source_id: i64,
    pub resource_hash: [u8; WIM_PROVIDER_HASH_SIZE],  
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ReparsePointWOFAttributeHeader {
    pub resident_attribute: ResidentAttributeHeader,
    pub reparse_tag: u32, // 0xA000000C for symlink
    pub reparse_data_length: u16, // len following 'reserved' attribute
    pub reserved: u16,
    pub wof_external_info: WofExternalInfo
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ReparsePointWOFFileProvider {
    pub wof_attribute_header: ReparsePointWOFAttributeHeader,
    pub file_provider_info: FileProviderExternalInfoV0
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ReparsePointWOFWimProvider {
    pub wof_attribute_header: ReparsePointWOFAttributeHeader,
    pub wim_provider_info: WimProviderExternalInfo
}

/* pub static mut WOF_FILE_PROVIDER_REPARSE_POINT_EXAMPLE: ReparsePointWOFFileProvider = unsafe {std::mem::zeroed()};
pub static mut SYMLINK_REPARSE_POINT_EXAMPLE: ReparsePointSymlinkAttributeHeader = unsafe {std::mem::zeroed()};
pub static mut SYMLINK_PATH_BUFFER: [u8;255] = [0;255];
pub static mut SYMLINK_PATH_BUFFER_LEN: usize = 0usize; */

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IndexNodeHeader {
    pub entries_offset: u32,  // offset to the first entry from this same structure, not from the beginning of the attribute
    pub total_entry_size: u32,  // total bytes occupied by all entries in the node
    pub allocated_entry_size: u32,  // reserved space
    pub flags: u8,   // 0x00 = leaf node, 0x01 = some of its entries point to sub-node
    pub reserved: [u8;3], // padding
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IndexRootAttributeHeader {
    pub resident_attribute: ResidentAttributeHeader,
    pub name: [u8; 8],
    pub indexed_attr_type: u32,  // for windows always 0x30 = $FILE_NAME -> i.e. by which attribute the index is ordered
    pub collation_rule: u32, // in windows 0x01 = File-name collation, i.e. the UNICODE order of the filenames is used
    pub index_block_size: u32,  // INDX blocks size
    pub clusters_per_block:  u8,
    pub reserved: [u8;3], // padding
    pub index_node_header: IndexNodeHeader
    // Here below are the index entries in the resident attribute
    // If there is not IndexAllocation attribute, then the b+tree contains only leaf entries
}

#[repr(C, packed)]
pub struct IndexEntryHeader {
    pub file_reference: u64,  // 48 bits mft entry index + 16 bits sequence number
    pub entry_size: u16,  // total bytes of this entry
    pub stream_size: u16,  // bytes of the embedded FILE_NAME
    pub flags: u16,  // 0x01 = there is a vcn at the end pointing to subnode, 0x02 = last entry of the node, no filename attribute (I think?)
    pub reserved: u16,
    // followed by FileNameAttributeHeaderFixed (if flags != 0x02) + VCN (u64) of sub-node (if flags = 0x01) 
}

impl IndexEntryHeader {
    pub fn file_reference(&self) -> u64 {
        self.file_reference & 0x0000FFFFFFFFFFFF
    }

    pub fn _sequence_number(&self) -> u16 {
        (self.file_reference >> 48) as u16
    }
}

#[repr(C, packed)]
pub struct IndexAllocationBlock {
    pub signature: [u8; 4], // "INDX" signature (0x49 0x4E 0x44 0x58)
    pub usa_offset: u16,
    pub usa_count: u16,
    pub lsn: u64,
    pub vcn_this_block: u64,
    pub index_node_header: IndexNodeHeader
}

// Very well explained here https://www.youtube.com/watch?v=AbApUDui8wM&ab_channel=%C3%86THERAcademy
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct _RunHeader {
    // The LEAST significant 4 bits -> The length of the fragment in clusters
    // The MOST significant 4 bits -> the start cluster from the end of the previous data run (or from the start of the volume if it is the first data run)
    pub raw: u8
}

impl _RunHeader {
    pub fn length_field_bytes(&self) -> u8 { 
        self.raw & 0x0F
    }

    pub fn offset_field_bytes(&self) -> u8 { 
        (self.raw >> 4) & 0x0F
    }
}

// I use it to store the data run list of a specific MFT entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RunEntry {
    pub length: u64, // length in clusters
    pub offset: i64, // The cluster from the START of the volume (already traced back to the previous cluster), i.e. the LCN where the clusters of this data run start.
    pub first_vcn: u64, // VCN (Virtual Cluster Number) is an offset relative to the start of the file/stream; LCN (Logical..) is an offset from the start of the volume.
    pub last_vcn: u64 
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FileData { // Structure to store all the names of an entry pointing to the same parent entry 
    pub parent: u64, // The parent number, i.e. the index of the mft entry that corresponds to the directory that contains this file
    pub posix_names: Vec<String>,
    pub win32_names: Vec<String>,
    pub short_names: Vec<String>,
    pub all_names: Vec<String>,
    pub mft_entry_index: usize, // The index of the MFT entry corresponding to this file
}

#[derive(Debug, Default)]
pub struct DirectoryFilesList {
    pub parent_record_number: u64,
    pub record_number: u64,
    pub filename: String,
    pub short_name: String,
    pub entry_type: String
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct VCN {
    pub is_sparse: bool,
    pub content: Vec<u8>, 
}

pub static mut KERNEL32_ADDR: usize = 0;
pub static mut H_VOLUME: HANDLE = HANDLE(0);
pub static mut STARTING_OFFSET: i64 = 0; // This might be useful in the future, idk
pub static VOLUME: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::from(r"\\.\C:")));
pub static OUTPUT_FILE: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::from(r"none")));
pub static NTFS_DATA: Lazy<RwLock<NTFSVolumeDataBuffer>> = Lazy::new(|| RwLock::new(NTFSVolumeDataBuffer::default()));
pub static UPCASE: Lazy<RwLock<Vec<u16>>> = Lazy::new(|| RwLock::new(Vec::new()));

pub fn set_ntfs_data(data: NTFSVolumeDataBuffer)
{
    let mut writer = NTFS_DATA.write().unwrap();
    *writer = data;
}

pub fn get_ntfs_data() -> NTFSVolumeDataBuffer
{
    let data = NTFS_DATA.read().unwrap();
    *data
}

pub static MFT_DATA: Lazy<RwLock<Vec<ContentWrapper>>> = Lazy::new(|| RwLock::new(Vec::new()));

pub fn push_mft_entry(entry: &mut ContentWrapper) {
    let mut data = MFT_DATA.write().unwrap();
    CIPHER.apply(&mut entry.content);
    data.push(entry.clone());
}

pub fn get_mft_entry_copy(index: usize) -> Option<ContentWrapper> {
    if index <= get_mft_len() {
        let data = MFT_DATA.read().unwrap();
        let mut encrypted = data.get(index).cloned().unwrap();
        CIPHER.apply(&mut encrypted.content);
        Some(encrypted)
    } else {
        None
    }
}

pub fn get_mft_len() -> usize {
    let data = MFT_DATA.read().unwrap();
    data.len()
}

pub fn iter_mft_entries() -> impl Iterator<Item = ContentWrapper> {
    (0..get_mft_len()).filter_map(get_mft_entry_copy)
}

// ChatGPT did this
const A: u64 = 1103515245;
const C: u64 = 12345;
const M: u64 = 1 << 31;

const KEY_LEN: usize = 16;
pub static CIPHER: Lazy<XorCipher> = Lazy::new(|| XorCipher::new_random(KEY_LEN));

pub struct XorCipher {
    key: Vec<u8>,
}

impl XorCipher {
    pub fn new_random(key_len: usize) -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("")
            .as_nanos() as u64;
        let mut state = seed;
        let mut key = Vec::with_capacity(key_len);
        for _ in 0..key_len {
            state = (A.wrapping_mul(state).wrapping_add(C)) % M;
            key.push((state & 0xFF) as u8);
        }
        XorCipher { key }
    }
    
    #[inline]
    pub fn apply(&self, data: &mut [u8]) {
        let key = &self.key;
        let key_len = key.len();
        let mut idx = 0;
        for byte in data.iter_mut() {
            *byte ^= key[idx];
            idx += 1;
            if idx == key_len {
                idx = 0;
            }
        }
    }
}