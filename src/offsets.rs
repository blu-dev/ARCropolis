use skyline::hooks::{getRegionAddress, Region};
use aarch64_decode::{ decode_a64, Instr };
use std::{iter::StepBy, ops::Range};

// default 9.0.1 offsets
pub static mut LOOKUP_STREAM_HASH_OFFSET: usize = 0x335a350;
pub static mut IDK_OFFSET: usize = 0x335f150;
pub static mut ADD_IDX_TO_TABLE1_AND_TABLE2_OFFSET: usize = 0x33595a0;
pub static mut PARSE_EFF_OFFSET: usize = 0x3379e14;
pub static mut PARSE_EFF_NUTEXB_OFFSET: usize = 0x337a2f0;
pub static mut PARSE_PARAM_OFFSET: usize = 0x3539714;
pub static mut PARSE_MODEL_XMB_OFFSET:usize = 0x33fad28;
pub static mut PARSE_ARC_FILE_OFFSET:usize = 0x3588f3c;
pub static mut PARSE_FONT_FILE_OFFSET:usize = 0x3576f28;
pub static mut PARSE_NUMSHB_FILE_OFFSET:usize = 0x33e1d50;
pub static mut PARSE_NUMATB_NUTEXB_OFFSET:usize = 0x3408384;
pub static mut PARSE_NUMSHEXB_FILE_OFFSET:usize = 0x33e3c44;
pub static mut PARSE_NUMATB_FILE_OFFSET:usize = 0x340791c;
pub static mut PARSE_NUMDLB_FILE_OFFSET:usize = 0x33dc6a8;
pub static mut PARSE_LOG_XMB_OFFSET:usize = 0x33fadf4;
pub static mut PARSE_MODEL_XMB_2_OFFSET:usize = 0x3406f44;
pub static mut TITLE_SCREEN_VERSION_OFFSET:usize = 0x35ba960;
pub static mut PARSE_NUS3BANK_FILE_OFFSET:usize = 0x35528f4;

pub struct TextIter<InnerIter: Iterator<Item = usize> + Sized> {
    inner: InnerIter
}

impl TextIter<StepBy<Range<usize>>> {
    fn new() -> Self {
        unsafe {
            let text = getRegionAddress(Region::Text) as usize;
            let rodata = getRegionAddress(Region::Rodata) as usize;

            Self {
                inner: (text..rodata).step_by(4)
            }
        }
    }
}

impl<InnerIter: Iterator<Item = usize> + Sized> Iterator for TextIter<InnerIter> {
    type Item = (usize, Instr);

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = self.inner.next()? as *const u32;
        let raw_instr = unsafe { *ptr };
        Some((ptr as usize, decode_a64(raw_instr).unwrap_or(Instr::Nop)))
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

macro_rules! find_offsets {
    (
        $(
            ($out_variable:expr, $search_pattern:expr)
        ),*
        $(,)?
    ) => {
        $(
            unsafe {
                let text_ptr = getRegionAddress(Region::Text) as *const u8;
                let text_size = (getRegionAddress(Region::Rodata) as usize) - (text_ptr as usize);
                let text = std::slice::from_raw_parts(text_ptr, text_size);

                if let Some(offset) = find_subsequence(text, $search_pattern) {
                    $out_variable = offset
                } else {
                    println!("Error: no offset found for '{}'. Defaulting to 8.1.0 offset. This most likely won't work.", stringify!($out_variable));
                }
            }
        )*
    };
}

pub fn search_offsets() {
    unsafe {
        // All of this was written during Smash 9.0.0


        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Stp64LdstpairPre,
        //     Stp64LdstpairOff,
        //     Stp64LdstpairOff,
        //     Stp64LdstpairOff,
        //     Add64AddsubImm,
        //     Orr32LogImm,
        //     Subs32AddsubShift,
        //     BOnlyCondbranch,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        // ) {
        //     IDK_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Stp64LdstpairPre,
        //     Stp64LdstpairOff,
        //     Stp64LdstpairOff,
        //     Add64AddsubImm,
        //     Ldr32LdstPos,
        //     Subs32AddsubShift,
        //     BOnlyCondbranch,
        //     Ldr64LdstPos,
        //     Orr64LogShift,
        //     Orr64LogShift,
        // ) {
        //     ADD_IDX_TO_TABLE1_AND_TABLE2_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr32LdstPos,
        //     Add64AddsubShift,
        //     Cbz32Compbranch,
        //     Subs64SAddsubImm,
        //     Csinc64Condsel,
        //     Sbfm64MBitfield,
        //     Add64AddsubShift,
        //     Ldr64LdstImmpost,
        // ) {
        //     LOOKUP_STREAM_HASH_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     Orr64LogShift,
        //     AdrpOnlyPcreladdr,
        //     Ldr64LdstPos,
        //     Stur64LdstUnscaled,
        //     Stp64LdstpairOff,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        // ) {
        //     PARSE_EFF_NUTEXB_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr32LdstPos,
        //     Subs32AddsubShift,
        //     Orr64LogShift,
        //     BOnlyCondbranch,
        //     Ldr64LdstPos,
        //     Add64AddsubShift,
        //     Ldrb32LdstPos,
        //     Cbz32Compbranch,
        //     Ubfm64MBitfield,
        //     Ldr32LdstRegoff,
        // ) {
        //     PARSE_EFF_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     Cbz64Compbranch,
        //     Add64AddsubImm,
        //     Stp64LdstpairOff,
        //     Ldrsw64LdstPos,
        //     Add64AddsubShift,
        //     Str64LdstPos,
        //     Ldrsw64LdstPos,
        //     Add64AddsubShift,
        //     Str64LdstPos
        // ) {
        //     PARSE_PARAM_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     Ldr64LdstPos,
        //     Orr64LogShift,
        //     Ldr64LdstPos,
        //     BlOnlyBranchImm,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Str32LdstPos,
        //     Ldr64LdstPos,
        // ) {
        //     PARSE_MODEL_XMB_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     Orr64LogShift,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr32LdstPos,
        //     Subs32AddsubShift,
        //     BOnlyCondbranch,
        // ) {
        //     PARSE_ARC_FILE_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     Ldrb32LdstPos,
        //     Cbz32Compbranch,
        //     Ret64RBranchReg,
        //     Ldr64LdstPos,
        //     Cbz64Compbranch,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Br64BranchReg,
        // ) {
        //     PARSE_FONT_FILE_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     Orr64LogShift,
        //     AdrpOnlyPcreladdr,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr32LdstPos,
        //     Subs32AddsubShift,
        // ) {
        //     PARSE_NUMATB_NUTEXB_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     AdrpOnlyPcreladdr,
        //     Add64AddsubImm,
        //     Str64LdstPos,
        //     AdrpOnlyPcreladdr,
        //     BOnlyBranchImm,
        //     Orr64LogShift,
        //     Movz32Movewide,
        //     Orr32LogImm,
        // ) {
        //     PARSE_NUMSHEXB_FILE_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     Orr64LogShift,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        //     Ldr32LdstPos,
        //     Subs32AddsubShift,
        //     BOnlyCondbranch,
        // ) {
        //     PARSE_NUMATB_FILE_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     Str64LdstImmpre,
        //     Stp64LdstpairOff,
        //     Add64AddsubImm,
        //     Orr64LogShift,
        //     BlOnlyBranchImm,
        //     Cbz64Compbranch,
        //     Ldp64LdstpairOff,
        //     Orr64LogShift,
        // ) {
        //     PARSE_NUMDLB_FILE_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     Orr64LogShift,
        //     Orr32LogImm,
        //     Orr32LogImm,
        //     BlOnlyBranchImm,
        //     Orr64LogShift,
        //     Cbnz64Compbranch,
        //     AdrpOnlyPcreladdr,
        //     Ldr64LdstPos,
        // ) {
        //     PARSE_LOG_XMB_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Ldr64LdstPos,
        //     BOnlyBranchImm,
        //     UdfOnlyPermUndef,
        //     AdrpOnlyPcreladdr,
        //     Add64AddsubImm,
        //     Str64LdstPos,
        //     Ldr64LdstPos,
        //     Cbz64Compbranch,
        //     Ldr64LdstPos,
        //     Ldr64LdstPos,
        // ) {
        //     PARSE_MODEL_XMB_2_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => Str64LdstImmpre,
        //     Stp64LdstpairOff,
        //     Stp64LdstpairOff,
        //     Add64AddsubImm,
        //     Sub64AddsubImm,
        //     Orr64LogShift,
        //     Orr64LogShift,
        //     Add64AddsubImm,
        //     Orr32LogImm,
        //     Orr32LogShift,
        // ) {
        //     TITLE_SCREEN_VERSION_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => AdrpOnlyPcreladdr,
        //     Ldr64LdstPos,
        //     Orr32LogShift,
        //     BlOnlyBranchImm,
        //     Ldr64LdstPos,
        //     Ldr32LdstPos,
        //     Subs32AddsubShift,
        //     BOnlyCondbranch,
        //     Ldr64LdstPos,
        //     Add64AddsubExt,
        // ) {
        //     smash::resource::LOADED_TABLES_OFFSET = offset
        // }

        // if let Some(offset) = mnemonic_macro::mnemonic_search!(
        //     => AdrpOnlyPcreladdr,
        //     Ldr64LdstPos,
        //     Strb32LdstPos,
        //     Ldrh32LdstPos,
        //     Strh32LdstPos,
        //     Cbz64Compbranch,
        //     Add64AddsubImm,
        //     And64LogImm,
        //     Subs32SAddsubImm,
        //     BOnlyCondbranch,
        // ) {
        //     smash::resource::RES_SERVICE_OFFSET = offset
        // }

        // find_offsets!(
        //     (IDK_OFFSET, IDK_SEARCH_CODE),
        //     (ADD_IDX_TO_TABLE1_AND_TABLE2_OFFSET, ADD_IDX_TO_TABLE1_AND_TABLE2_SEARCH_CODE),
        //     (LOOKUP_STREAM_HASH_OFFSET, LOOKUP_STREAM_HASH_SEARCH_CODE),
        //     // (PARSE_EFF_NUTEXB_OFFSET, &[u8;0]),
        //     // (PARSE_EFF_OFFSET, &[u8;0]),
        //     // (PARSE_PARAM_OFFSET, &[u8;0]),
        //     // (PARSE_MODEL_XMB_OFFSET, &[u8;0]),
        //     // (PARSE_ARC_FILE_OFFSET, &[u8;0]),
        //     // (PARSE_FONT_FILE_OFFSET, &[u8;0]),
        //     // (PARSE_NUMATB_NUTEXB_OFFSET, &[u8;0]),
        //     // (PARSE_NUMSHEXB_FILE_OFFSET, &[u8;0]),
        //     // (PARSE_NUMATB_FILE_OFFSET, &[u8;0]),
        //     // (PARSE_NUMDLB_FILE_OFFSET, &[u8;0]),
        //     // (PARSE_LOG_XMB_OFFSET, &[u8;0]),
        //     // (PARSE_MODEL_XMB_2_OFFSET, &[u8;0]),
        //     (TITLE_SCREEN_VERSION_OFFSET, TITLE_SCREEN_VERSION_SEARCH_CODE),
        // );
    }
}

// #[allow(dead_code)]
// pub fn expand_table2() {
//     let loaded_tables = LoadedTables::get_instance();

//     unsafe {
//         nn::os::LockMutex(loaded_tables.mutex);
//     }

//     let mut table2_vec = loaded_tables.table_2().to_vec();

//     table2_vec.push(Table2Entry {
//         data: 0 as *const u8,
//         ref_count: AtomicU32::new(0),
//         is_used: false,
//         state: FileState::Unused,
//         file_flags2: false,
//         flags: 45,
//         version: 0xFFFF,
//         unk: 0,
//     });

//     loaded_tables.table2_len = table2_vec.len() as u32;
//     let mut table2_array = table2_vec.into_boxed_slice();
//     loaded_tables.table2 = table2_array.as_ptr() as *mut Table2Entry;

//     unsafe {
//         nn::os::UnlockMutex(loaded_tables.mutex);
//     }
// }

// pub fn shared_redirection() {
//     let str_path = "rom:/skyline/redirect.txt";

//     let s = match fs::read_to_string(str_path) {
//         Err(why) => {
//             println!("[HashesMgr] Failed to read \"{}\" \"({})\"", str_path, why);
//             return;
//         }
//         Ok(s) => s,
//     };

//     for entry in string_to_static_str(s).lines() {
//         let mut values = entry.split_whitespace();

//         let loaded_tables = LoadedTables::get_instance();
//         let arc = loaded_tables.get_arc();
//         let path = values.next().unwrap();
//         println!("Path to replace: {}", path);
//         let hash = hash40(path);

//         unsafe {
//             let hashindexgroup_slice =
//                 slice::from_raw_parts(arc.file_info_path, (*loaded_tables).table1_len as usize);

//             let t1_index = match hashindexgroup_slice
//                 .iter()
//                 .position(|x| x.path.hash40.as_u64() == hash)
//             {
//                 Some(index) => index as u32,
//                 None => {
//                     println!(
//                         "[ARC::Patching] Hash {} not found in table1, skipping",
//                         hash
//                     );
//                     continue;
//                 }
//             };
//             println!("T1 index found: {}", t1_index);

//             let file_info = arc.lookup_file_information_by_t1_index(t1_index);
//             println!("Path index: {}", file_info.path_index);

//             let mut file_index = arc.lookup_fileinfoindex_by_t1_index(t1_index);
//             println!("File_info_index: {}", file_index.file_info_index);

//             // Make sure it is flagged as a shared file
//             if (file_info.flags & 0x00000010) == 0x10 {
//                 let path = values.next().unwrap();
//                 println!("Replacing path: {}", path);
//                 let hash = hash40(path);

//                 let t1_index = match hashindexgroup_slice
//                     .iter()
//                     .position(|x| x.path.hash40.as_u64() == hash)
//                 {
//                     Some(index) => index as u32,
//                     None => {
//                         println!(
//                             "[ARC::Patching] Hash {} not found in table1, skipping",
//                             hash
//                         );
//                         continue;
//                     }
//                 };

//                 println!("T1 index found: {}", t1_index);
//                 file_index.file_info_index = t1_index;
//                 file_index.file_info_index = t1_index;
//                 println!("New file_info_index: {}", file_index.file_info_index);
//             }
//         }
//     }

//     //hashes.insert(hash40(hs), hs);
// }
