# Description

MFTool is a red team-oriented NTFS parser. Instead of asking Windows for files, it parses the on-disk structures of a mounted NTFS volume directly to build an in-memory copy of the [Master File Table](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table). That in-memory MFT is kept encrypted and is then used to:

- Search the entire disk for files and metadata.
- Retrieve file contents **without opening an OS-level file handle**, enabling access to data that is typically locked by the operating system (e.g., `SAM`, `NTUSER.dat`, `SYSTEM`, `pagefile.sys`, etc.) as well as deleted files (hereafter referred to as "hidden").

Direct NTFS parsing is not new and is widely used in forensics, although this tool has been developed taking into account the needs and requirements from a red team perspective. Also, I wasn't able to find a public tool that performs in the way I pictured it, so I decided to create my own NTFS parser.

# Content

- [How it works](#How-it-works)
- [How to use it](#How-to-use-it)
- [Commands](#Commands)
- [Examples](#Examples)
  - [Retrieving metadata of an entry](#Retrieving-metadata-of-an-entry)
  - [Accessing deleted and locked files](#Accessing-deleted-and-locked-files)
  - [Directory listing and regex-based search](#Directory-listing-and-regex-based-search)
- [Limitations and Known Issues](#Limitations-and-Known-Issues)
- [Links](#Links)

# How it works

MFTool interacts directly with a mounted NTFS volume by opening a handle to it and parsing the on-disk filesystem structures. Instead of relying on Windows APIs, it walks through the Master File Table to build an internal representation of the filesystem.

1. **Boot sector parsing**  
   Once a handle to the volume is opened, MFTool parses the boot sector to locate the offset of the first MFT entry. From there, it follows the cluster chains to enumerate the rest of the entries.

2. **MFT entry reconstruction**  
   Each MFT record is reconstructed by replacing the Update Sequence Number (USN) with the corresponding values from the Update Sequence Array (USA). The reconstructed entries are stored in an encrypted in-memory cache to prevent accidental data leakage. This cache is rebuilt every time a new target volume is selected.

3. **File content retrieval**  
   To read a file, MFTool does not rely on an OS-level file handle. Instead, it parses the file's MFT entry, extracts the unnamed `$DATA` attribute, and follows its data run list to locate the clusters containing the file's content.  
   - Data is read directly from disk offsets, ignoring Windows' file access controls (note that administrative privileges are still required to run the tool, so this should not be considered an ACL bypass per se).  
   - If the file is compressed, the content is split into logical units and decompressed using [`RtlDecompressBuffer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbuffer).  
   - This allows retrieval of normal, locked, and even deleted files in case the content is still present in the disk.   

4. **Searching and directory listing**  
   File search and directory enumeration rely on parsing the `$I30` index attributes (`INDEX_ROOT`, `INDEX_ALLOCATION` structures). This allows for efficient lookups with logarithmic complexity `O(log n)`, and supports both exact name matching and regex-based searches (regex-based searches are not logarithmic tho).

5. **Reparse point handling**  
   The parser currently resolves reparse points of type **symlink** and **mount point**, ensuring correct navigation across linked or mounted paths.  

# How to use it

To build the tool just compile it in `release` mode:

	C:\Path\To\MFTool> cargo build --release

Once executed, the tool will wait for commands out of the list commented in the next section.

# Commands

## set_target
Sets the target volume to be parsed.  
This command expects a string pointing to a mounted NTFS volume, either by drive letter or by volume GUID path (e.g., `\\.\C:` or `\\?\Volume{04171d6a-0000-0000-0000-100000000000}`).  
Once a valid volume path is provided, MFTool rebuilds its in-memory cache of the MFT. From this point, all further interactions with the volume are performed against that cache.

## rebuild
Rebuilds the in-memory MFT cache for the current target volume.  

## ls
Parses the `$I30` index attributes to list the files contained in a directory.  
Both the Win32 name and the DOS (short) name (if any) of each file are displayed.

## show
Given a directory path and a filename, retrieves the metadata stored in the file's MFT entry.

## show_by_id
Same as `show`, but instead of requiring a path and filename, it expects the MFT entry index.

## show_by_regex
Searches for files across the entire volume using a regular expression (expressed as `/regex/`).  
This command performs a sequential search of all MFT entries, so its complexity is linear.  
If invoked with the `hidden` flag, it restricts the search to deleted files (i.e., files whose MFT entries are still present on disk but no longer referenced by the filesystem).

## read_file
Given a directory path, a filename, and a destination path, locates the file's MFT entry inside the specified directory, retrieves its content directly from disk, and writes it to the destination path.  
The process of content retrieval is the same as described in [How it works](#how-it-works).

## read_by_index
Same as `read_file`, but instead of a path and filename, it takes the MFT entry index and retrieves the corresponding file's content, saving it to the specified destination path.

## output

Allows specifying a file where the results of searches executed by the show commands will be stored.
It is recommended for `show_by_regex` as it generates extensive output.

# Examples

All the examples below assume that a `set_target \\.\C:` or similar has already been executed, and therefore the MFT of the target volume is mapped in memory.

## Retrieving metadata of an entry

	> show c:\windows\system32 Dbgcore.dll
	[x] WOF compressed data detected. Operation not supported. -> ignore this
	[-] Record index: 1819638
	[-] File Reference Number: 0x000000000000000000060000001bc3f6
	[-] Hidden entry: false
	[-] Entry type: file
	[-] Size: 194560
	[-] Compressed: false
	[-] Creation time: 14/05/2025 09:12
	[-] Modification time: 14/05/2025 09:12
	[-] Last time accessed: 08/09/2025 13:41
	[-] Filenames:
	        - \Windows\WinSxS\AM4023~1.579\dbgcore.dll
	        - \Windows\System32\dbgcore.dll

This command provides general information about an MFT entry, regardless of whether it corresponds to a file or a directory.

Some relevant fields include:

- `Record index`: the index of the entry. It typically remains stable even if the file is deleted. Can be passed to `show_by_index` to retrieve the same information.
- `File Reference Number (FRN)`: shown in the same format expected by `fsutil`.
- `Hidden entry`: indicates whether the entry corresponds to a deleted file (`true`).
- `Filenames`: lists all hardlinks pointing to the same file.

The FRN can be used not only to query information with `fsutil` but also to open a handle to the file directly by calling [`NtCreateFile`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) with the `FILE_OPEN_BY_FILE_ID` flag.

This is particularly useful in hypothetical scenarios where NTFS structures are corrupted (e.g., a fictitious Bring Your Own VHD technique). Such corruption may allow the creation of files with names considered invalid by Windows, making them "invisible" to most tools and sometimes bypassing signature validation mechanisms. While opening these files by path is usually impossible (due to the commented corruptions), their FRN still allows obtaining a fully functional handle, bypassing those limitations.

## Accessing deleted and locked files

	> read_file c:\windows\system32\config SAM c:\temp\SAM
	[+] Process completed. Output written to 'c:\temp\SAM'.


As described earlier, this command dynamically retrieves the clusters that hold the file's content and assembles them into the specified destination file.

For example, repeating the process with the `SYSTEM` and `SECURITY` files allows dumping the registry hives without making any use of the corresponding registry API functions. The resulting files can then be parsed directly with tools like `secretsdump`.

In the same way, MFTool can access other locked files, such as `pagefile.sys` or `hiberfil.sys`, [extracting sensitive information](https://diverto.github.io/2019/11/05/Extracting-Passwords-from-hiberfil-and-memdumps) they often contain.

This command can also be used to recover deleted files, provided their content has not yet been overwritten on disk.

## Directory listing and regex-based search

	> ls C:\windows
	- AppReadiness (Directory)
	- BitLockerDiscoveryVolumeContents / BITLOC~1 (Directory)
	- Boot (Directory)
	- Branding (Directory)
	- CSC (Directory)
	- CbsTemp (Directory)
	- Containers (Directory)
	- DCEBoot64.exe / DCEBOO~1.EXE (File)
	- DiagTrack (Directory)
	- DigitalLocker / DIGITA~1 (Directory)
	...

The `ls` command enumerates directory contents by parsing the `$I30` attributes directly from memory, with logarithmic complexity.

Also, the `show_by_regex` command can be used to scan the entire volume from memory, locating all files whose names match a given regular expression (for example, finding all `.kdbx` files). While this operation is linear in complexity, it is significantly faster than using the Windows API and much stealthier, since almost all processing happens against the in-memory MFT copy:

	> show_by_regex /\.kdbx$/
	[+] Entry .\Users\Superadmin\Secrets.kdbx matched. Record index: 15142
	[-] Filenames:
	        - \Users\Superadmin\SECRET~1.KDB
	        - \Users\Superadmin\Secrets.kdbx
	-----------------------------------------------
	[+] Entry .\Users\Superadmin\EvenMoreSecrets.kdbx matched. Record index: 16781
	[-] Filenames:
	        - \Users\Superadmin\EVENMO~1.KDB
	        - \Users\Superadmin\EvenMoreSecrets.kdbx
	-----------------------------------------------
	...

# Limitations and Known Issues

I am aware that direct disk access is nothing new and has been widely used in forensics. However, the goal of this tool is to show how the same technique can be adapted for red team exercises, enabling a stealthier access to mounted disks in a live environment.

That said, there are several limitations and caveats to be aware of:

- Some parts of the codebase still need refactoring to remove duplication and leftover "legacy" logic from an earlier implementation with slightly different goals.
- Not all NTFS structures and attributes are currently parsed. This may lead to unexpected behavior in certain cases. 
- Currently, retrieval of encrypted files and ADS is not supported.
- I am not an NTFS expert. While I've tried to build a correct implementation based on publicly available documentation, there may still be inaccuracies in the parsing logic. In that case, please open an issue and provide me with detailed information.
- The tool has been successfully tested against NTFS version 3.1 (Windows 10 and 11). Its behavior on other NTFS versions is unknown.
- There is clearly room for improvement: more disk information could be extracted (e.g., by parsing NTFS Journals or $SECURITY_DESCRIPTOR attributes).
- The command management and text output are not the cleanest or most user-friendly. I didn't spend much time polishing that part, so feel free to improve it!
- Overall, this is simply a proof of concept that is not fully prepared to be used in a real engagement.

# Links

- https://flatcap.github.io/linux-ntfs/ntfs/index.html (by far the best link in this list).
- https://harelsegev.github.io/posts/i30-parsers-output-false-entries.-heres-why/
- https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-ntfs_volume_data_buffer
- https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header
- https://handmade.network/forums/articles/t/7002-tutorial_parsing_the_mft
- https://www.youtube.com/watch?v=AbApUDui8wM&ab_channel=%C3%86THERAcademy