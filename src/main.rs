#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::io::Write;
use std::{fs, io};
use data::{Command, KERNEL32_ADDR, OUTPUT_FILE, STARTING_OFFSET};
use parser::{list_files_from_directory, read_file_from_mft, read_mft_entry_by_index, set_target, show_hidden_entries, show_info_mft_entry, show_info_mft_entry_by_index, show_info_mft_entry_by_regex};
use regex_lite::Regex;
use utils::{build_regex_matcher, parse_args, print_help};

fn main()  
{
    unsafe 
    {
        KERNEL32_ADDR = dinvoke_rs::dinvoke::get_module_base_address(&lc!("kernel32.dll")); 
        if KERNEL32_ADDR == 0 {
            println!("{}", &lc!("[x] Error finding kernel32.dll."));
            return;
        }
        
        loop 
        {
            print!("> ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();

            let trimmed_input = input.trim();
            let mut args = parse_args(trimmed_input);
            if args.len() == 0 {
                continue;
            }
            let command = args.remove(0);

            match Command::from_str(&command) {
                Some(Command::ReadFile) => {
                    if args.len() != 3 {
                        println!("{}", &lc!(r"Usage: read_file c:\windows\system32\config SAM c:\windows\temp\SAM"));
                        continue;
                    }

                    let file_name = args[1].to_string();

                    let ret = read_file_from_mft(&args[0], &file_name);
                    if ret.is_some() {
                        let file_contents = ret.unwrap();
                        let ret= fs::write( &args[2], &file_contents);
                        if ret.is_err() {
                            let error = ret.err().unwrap();
                            println!("{}'{}': {}.", &lc!("[x] Error creating file "), args[2], error);
                        } else{
                            println!("{}'{}'.", &lc!("[+] Process completed. Output written to "), args[2]);
                        }
                    } else {
                        let full_path = if args[0].ends_with('\\') {
                            &format!("{}{}", args[0], args[1])
                        } else {
                            &format!("{}\\{}", args[0], args[1])
                        };
                        println!("{}'{}'.", &lc!("[x] Error reading the contents of the file "), full_path);
                    }
                }

                Some(Command::ReadByIndex) => {
                    if args.len() != 2 {
                        println!("{}", &lc!(r"Usage: read_by_index 12871 c:\windows\temp\SAM"));
                        continue;
                    }
                    let index = args[0].parse();
                    if index.is_err(){
                        println!("{}", &lc!("[x] Invalid input."));
                        continue;
                    }

                    let index = index.unwrap();
                    let ret = read_mft_entry_by_index(index);
                    if ret.is_some() {
                        let file_contents = ret.unwrap();
                        let ret= fs::write( &args[1], &file_contents);
                        if ret.is_err() {
                            let error = ret.err().unwrap();
                            println!("{}'{}': {}.", &lc!("[x] Error creating file "), args[1], error);
                        } else{
                            println!("{}'{}'.", &lc!("[+] Process completed. Output written to "), args[1]);
                        }
                    } else {
                        println!("{}'{}'.", &lc!("[x] Error reading the contents of the entry "), index);
                    }
                }
                
                Some(Command::Rebuild) => {
                    set_target("");
                    println!("{}", &lc!("[+] Process completed."));
                }

                Some(Command::Ls) => {
                    if args.len() < 1 {
                        println!("{}", &lc!(r"Usage: ls c:\windows\system32\config"));
                        continue;
                    }

                    let _ = list_files_from_directory(&args[0]);
                }

                Some(Command::Show) => {
                    if args.len() < 2 {
                        println!("{}", &lc!(r"Usage: show c:\windows\system32 ntdll.dll"));
                        continue;
                    }

                    let name = args[1].to_string();
                    show_info_mft_entry(&args[0], &name);             
                }

                Some(Command::ShowByRegex) => {
                    if args.len() < 1 {
                        println!("{}", &lc!(r"Usage: show_by_regex /someregex/ [hidden] [verbose]"));
                        continue;
                    }

                    let regex: Result<Regex, regex_lite::Error> = build_regex_matcher(&args[0]);
                    if regex.is_ok() {

                        // I'm sorry for this code, im too lazy to change it :)
                        let only_hidden = if (args.len() > 1 && args[1] == "hidden") ||  (args.len() > 2 && args[2] == "hidden"){ 
                            true
                        } else {
                            false
                        };

                        let verbose = if (args.len() > 1 && args[1] == "verbose") ||  (args.len() > 2 && args[2] == "verbose"){ 
                            true
                        } else {
                            false
                        };

                        show_info_mft_entry_by_regex(regex.unwrap(), only_hidden, verbose);
                    } else {
                        println!("[x] Invalid input.");
                    }                    
                }

                Some(Command::ShowByIndex)  => {
                    if args.len() < 1 {
                        println!("{}", &lc!(r"Usage: show_by_index 1251"));
                        continue;
                    }

                    let index = args[0].parse();
                    if index.is_err(){
                        println!("{}", &lc!("[x] Invalid input."));
                        continue;
                    }

                    let index = index.unwrap();
                    show_info_mft_entry_by_index(index);
                }

                Some(Command::ShowHidden) => {
                    show_hidden_entries();
                }

                Some(Command::SetTarget) => {
                    if args.len() != 1 {
                        println!("{}",&lc!(r"Usage: set_target \\.\C: [offset]"));
                        continue;
                    }

                    if args.len() >= 2 {
                        STARTING_OFFSET = args[2].parse().unwrap(); // This is useful if you set a PhysicalDriveX as target (you need to know the offset tho)
                    }

                    let ret = set_target(&args[0]);
                    if ret {
                        println!("{}", &lc!("[+] Process completed."));
                    } 
                }

                Some(Command::Output) => {
                    if args.len() != 1 {
                        println!("{}",&lc!(r"Usage: output C:\Path\To\Output.txt ('none' to disable it)"));
                        continue;
                    }

                    let mut output = OUTPUT_FILE.write().unwrap();
                    *output = args[0].to_string();
                }
    
                Some(Command::Help) => {
                    print_help();
                }
    
                Some(Command::Exit) => {
                    break;
                }
    
                None => {
                    println!("{}", &lc!("[-] Unknown command."));
                }    
            }
        }
    }
    
}