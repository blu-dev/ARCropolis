#![feature(proc_macro_hygiene)]
#![feature(str_strip)]
#![feature(asm)]

use std::fs::File;
use std::io::prelude::*;
use std::ffi::CStr;
use std::net::IpAddr;


use skyline::{hook, hooks::InlineCtx, install_hooks, libc, nn, println};


mod config;
use config::CONFIG;

mod hashes;
mod stream;

mod replacement_files;
use replacement_files::{ FileCtx, ARC_FILES, INCOMING };

mod offsets;
use offsets::{ TITLE_SCREEN_VERSION_OFFSET, INFLATE_OFFSET, MEMCPY_1_OFFSET, MEMCPY_2_OFFSET, MEMCPY_3_OFFSET, INFLATE_DIR_FILE_OFFSET, MANUAL_OPEN_OFFSET, INITIAL_LOADING_OFFSET };

use owo_colors::OwoColorize;

mod runtime;
use runtime::{ LoadedTables, ResServiceState, Table2Entry };

mod selector;
//use selector::workspace_selector;

mod logging;
use log::{ trace, info };

use smash_arc::{ArcLookup, FileInfo, FileInfoFlags, FileInfoIndex, FilePath, FileSystemHeader, Hash40, LoadedArc, LoadedDirInfo};

fn get_filectx_by_index<'a>(table2_idx: u32) -> Option<(parking_lot::MappedRwLockReadGuard<'a, FileCtx>, &'a mut Table2Entry)> {
    let tables = LoadedTables::get_instance();

    let table2entry = match tables.get_t2_mut(table2_idx) {
        Ok(entry) => entry,
        Err(_) => {
            return None;
        }
    };

    match get_from_info_index!(table2_idx) {
        Ok(file_ctx) => {
            info!("[ARC::Loading | #{}] Hash matching for file: '{}'", table2_idx.green(), file_ctx.path.display().bright_yellow());
            Some((file_ctx, table2entry))
        }
        Err(_) => None,
    }
}

fn replace_file_by_index(table2_idx: u32) {
    if let Some((file_ctx, table2entry)) = get_filectx_by_index(table2_idx) {
        if table2entry.data == 0 as _ {
            return;
        }

        if file_ctx.extension == Hash40::from("nutexb") {
            replace_textures_by_index(&file_ctx, table2entry);
            return;
        }

        let orig_size = file_ctx.get_subfile().decomp_size as usize;

        let file_slice = file_ctx.get_file_content().into_boxed_slice();

        info!("[ResInflateThread | #{}] Replacing '{}'", table2_idx.green(), hashes::get(file_ctx.hash).unwrap_or(&"Unknown").bright_yellow());

        unsafe {
            let mut data_slice = std::slice::from_raw_parts_mut(table2entry.data as *mut u8, orig_size);
            data_slice.write(&file_slice).unwrap();
        }
    }
}

fn replace_textures_by_index(file_ctx: &FileCtx, table2entry: &mut Table2Entry) {
    let orig_size = file_ctx.orig_subfile.decomp_size as usize;

    let file_slice = file_ctx.get_file_content().into_boxed_slice();

    info!("[ResInflateThread | #{}] Replacing '{}'", file_ctx.index.green(), hashes::get(file_ctx.hash).unwrap_or(&"Unknown").bright_yellow());

    if orig_size > file_slice.len() {
        let data_slice = unsafe { std::slice::from_raw_parts_mut(table2entry.data as *mut u8, orig_size) };
        // Copy the content at the beginning
        data_slice[0..file_slice.len() - 0xB0].copy_from_slice(&file_slice[0..file_slice.len() - 0xB0]);
        // Copy our new footer at the end
        data_slice[orig_size - 0xB0..orig_size].copy_from_slice(&file_slice[file_slice.len() - 0xB0..file_slice.len()]);
    } else {
        let mut data_slice = unsafe { std::slice::from_raw_parts_mut(table2entry.data as *mut u8, file_ctx.filesize as _) };
        data_slice.write(&file_slice).unwrap();
    }
}

#[hook(offset = INFLATE_OFFSET, inline)]
fn inflate_incoming(ctx: &InlineCtx) {
    unsafe {
        let arc = LoadedTables::get_instance().get_arc();
        let res_service = ResServiceState::get_instance();

        // Replace all this mess by Smash-arc
        let info_index= (res_service.processing_file_idx_start + *ctx.registers[27].x.as_ref() as u32) as usize;
        let file_info = arc.get_file_infos()[info_index];

        let path_idx = file_info.hash_index as usize;
        let table2_idx = file_info.hash_index_2;

        let hash = arc.get_file_paths()[path_idx].path.hash40();

        info!("[ResInflateThread | #{}] Incoming '{}', FileInfo: {}, FileInfoIndice: {}", path_idx.green(), hashes::get(hash).unwrap_or(&"Unknown").bright_yellow(), info_index.purple(), table2_idx.red());

        let mut incoming = INCOMING.write();

        if let Ok(context) = get_from_info_index!(table2_idx) {
            *incoming = Some(context.index);
            info!("[ResInflateThread | #{}] Added index {} to the queue", path_idx.green(), context.index.green());
        } else {
            *incoming = None;
        }
    }
}

#[hook(offset = 0x33b6798, inline)]
fn loading_incoming(ctx: &InlineCtx) {
    unsafe {
        let arc = LoadedTables::get_instance().get_arc();

        let path_idx = *ctx.registers[25].x.as_ref() as u32;
        let hash = arc.get_file_paths()[path_idx as usize].path.hash40();

        info!("[ResLoadingThread | #{}] Incoming '{}'", path_idx.bright_yellow(), hashes::get(hash).unwrap_or(&"Unknown").bright_yellow());
    }
}

/// For small uncompressed files
#[hook(offset = MEMCPY_1_OFFSET, inline)]
fn memcpy_uncompressed(_ctx: &InlineCtx) {
    trace!("[ResInflateThread | Memcpy1] Entering function");

    let incoming = INCOMING.read();

    if let Some(index) = *incoming {
        replace_file_by_index(index);
    }
}

/// For uncompressed files a bit larger
#[hook(offset = MEMCPY_2_OFFSET, inline)]
fn memcpy_uncompressed_2(_ctx: &InlineCtx) {
    trace!("[ResInflateThread | Memcpy2] Entering function");

    let incoming = INCOMING.read();

    if let Some(index) = *incoming {
        replace_file_by_index(index);
    }
}

/// For uncompressed files being read in multiple chunks
#[hook(offset = MEMCPY_3_OFFSET, inline)]
fn memcpy_uncompressed_3(_ctx: &InlineCtx) {
    trace!("[ResInflateThread | Memcpy3] Entering function");

    let incoming = INCOMING.read();

    if let Some(index) = *incoming {
        replace_file_by_index(index);
    }
}

#[repr(C)]
pub struct InflateFile {
    pub content: *const u8,
    pub size: u64,
}

#[hook(offset = INFLATE_DIR_FILE_OFFSET)]
fn load_directory_hook(unk1: *const u64, out_data: &InflateFile, comp_data: &InflateFile) -> u64 {
    trace!("[LoadFileFromDirectory] Incoming filesize: {:x}", out_data.size);

    // Let the file be inflated
    let result: u64 = original!()(unk1, out_data, comp_data);

    let incoming = INCOMING.read();

    if let Some(index) = *incoming {
        if index == 0 {
            return result;
        }

        replace_file_by_index(index);
    }

    result
}

#[hook(offset = TITLE_SCREEN_VERSION_OFFSET)]
fn change_version_string(arg1: u64, string: *const u8) {
    let original_str = unsafe { CStr::from_ptr(string as _).to_str().unwrap() };

    if original_str.contains("Ver.") {
        let new_str = format!(
            "Smash {}\nARCropolis Ver. {}\0",
            original_str,
            env!("CARGO_PKG_VERSION").to_string()
        );

        original!()(arg1, skyline::c_str(&new_str))
    } else {
        original!()(arg1, string)
    }
}

#[hook(offset = MANUAL_OPEN_OFFSET)]
unsafe fn manual_hook(page_path: *const u8, unk2: *const u8, unk3: *const u64, unk4: u64) {
    let original_page = CStr::from_ptr(page_path as _).to_str().unwrap();

    let is_manual = if original_page.contains("contents.htdocs/help/html/") {
        if original_page.ends_with("index.html") {
            selector::workspace_selector();
            true
        } else {
            false
        }
    } else {
        false
    };

    if is_manual != true {
        original!()(page_path, unk2, unk3, unk4)
    }
}

#[hook(offset = 0x35b3f40, inline)]
fn initial_loading(_ctx: &InlineCtx) {
    logging::init(CONFIG.read().logger.as_ref().unwrap().logger_level.into()).unwrap();

    // Check if an update is available
    if skyline_update::check_update(IpAddr::V4(CONFIG.read().updater.as_ref().unwrap().server_ip), "ARCropolis", env!("CARGO_PKG_VERSION"), CONFIG.read().updater.as_ref().unwrap().beta_updates) {
        skyline::nn::oe::RestartProgramNoArgs();
    }
    
    // Lmao gross
    let changelog = if let Ok(mut file) = File::open("sd:/atmosphere/contents/01006A800016E000/romfs/changelog.md") {
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        Some(format!("Changelog\n\n{}", &content))
    } else {
        None
    };

    if let Some(text) = changelog {
        skyline_web::DialogOk::ok(text);
        std::fs::remove_file("sd:/atmosphere/contents/01006A800016E000/romfs/changelog.md").unwrap();
    }

    // Discover files
    unsafe {
        nn::oe::SetCpuBoostMode(nn::oe::CpuBoostMode::Boost);

        unshared();
        lazy_static::initialize(&ARC_FILES);

        nn::oe::SetCpuBoostMode(nn::oe::CpuBoostMode::Disabled);
    }
}

// Before the tables are initialized, so they're automatically initialized with the right size
#[hook(offset = 0x35c6488, inline)]
unsafe fn before_loaded_tables(_ctx: &InlineCtx) {
    //unshared();
}

pub fn expand_table<T: Clone>(source: &[T]) -> Vec<T> {
    let mut vec = Vec::with_capacity(source.len() + 1);
    vec.extend_from_slice(source);
    vec
}

pub fn find_file_info_index_in_dir_info(arc: &LoadedArc, file_path: &FilePath, dir: &LoadedDirInfo) -> Option<usize> {
    (dir.file_info_start_index as usize .. (dir.file_info_start_index + dir.file_info_count) as usize).find(|index| {
        if arc.get_file_infos()[*index as usize].hash_index_2 == file_path.path.index() {
            println!("Matching FileInfoIndex found for FileInfo index: {}", index);
            true
        } else {
            false
        }
    })
}

pub unsafe fn unshared() {
    let tables = LoadedTables::get_instance();
    //println!("{:?}", tables);

    let arc = tables.get_arc_mut();

    // Get the index of the FilePath for this specific entry. Marth's original c00 numshb path.index() is 143623. This has to be changed to 156923 (FileInfoIndices.len() + 1) for testing purposes.
    let file_path_index = arc.get_file_path_index_from_hash(Hash40::from("fighter/marth/model/body/c00/model.numshb")).unwrap();

    // Get the FilePath for the hash
    let mut file_path = &mut *(&arc.get_file_paths()[file_path_index as usize] as *const FilePath as *mut FilePath);
    
    let dir = arc.get_loaded_dir_info_from_hash(Hash40::from("fighter/marth/c00")).unwrap();
    let info_index = find_file_info_index_in_dir_info(arc, file_path, dir).unwrap();
    println!("File_path path.index(): {}", file_path.path.index());


    /// FileInfoIndices

    // Here, we'll make a new FileInfoIndices table so we can add a new entry for the FilePath to refer to
    let mut new_fileinfoindices = expand_table(arc.get_file_info_indices());
    // Copy the original FileInfoIndex
    let mut new_fileinfoindex = arc.get_file_info_indices()[file_path.path.index() as usize].clone();
    // Set the FileInfo index to our new FileInfo
    new_fileinfoindex.file_info_index = info_index as u32;
    // Add our edited copy to the end of our new table
    new_fileinfoindices.push(new_fileinfoindex);
    info!("New FileInfoIndices table len: {}", new_fileinfoindices.len());
    info!("New FileInfoIndex: {:#?}", new_fileinfoindex);


    /// FileInfos

    // Get the original FileInfo so we can copy it
    //let mut new_fileinfo = new_fileinfos[arc.get_file_info_indices()[file_path.path.index() as usize].file_info_index as usize].clone();
    let info_data_len = arc.get_file_info_to_datas().len() as u32;

    let mut new_fileinfo = &mut arc.get_file_infos_mut()[info_index];
    let original_fileinfo = new_fileinfo.clone();

    println!("FileInfo before: {:#?}", new_fileinfo);

    // Set the FileInfoIndices index of the FileInfo to our new FileInfoIndex
    //println!("New FileInfo hash_index_2: {}", new_fileinfoindices.len());
    new_fileinfo.hash_index_2 = new_fileinfoindices.len() as u32 - 1;
    new_fileinfo.info_to_data_index = info_data_len;
    new_fileinfo.flags.set_is_redirect(true); // Is this actually necessary? Seems unused in Smash's code

    println!("FileInfo after: {:#?}", new_fileinfo);


    /// FileInfoToDatas
    
    let mut new_info_to_datas = expand_table(arc.get_file_info_to_datas());
    let mut new_info_to_data = arc.get_file_in_folder_mut(&original_fileinfo, smash_arc::Region::EuFrench).clone();
    println!("Original InfoToData: {:#?}", new_info_to_data);
    // new_info_to_data.file_info_index_and_flag
    new_info_to_data.file_data_index = arc.get_file_datas().len() as u32;
    new_info_to_datas.push(new_info_to_data);
    println!("New InfoToData: {:#?}", new_info_to_data);

    // FileDatas

    let mut new_filedatas = expand_table(arc.get_file_datas());
    let mut new_filedata = arc.get_file_data(&original_fileinfo, smash_arc::Region::EuFrench).clone();
    new_filedatas.push(new_filedata);
    println!("New FileData table len: {}", new_filedatas.len());

    

    //println!("FileInfo after: {:#?}", new_fileinfo);

    /// Table pointers replacement
    // Set the new FileInfoIndex for this path
    file_path.path.set_index(new_fileinfoindices.len() as u32 - 1);
    println!("Edited File_path path.index(): {}", file_path.path.index());

    let mut new_table2 = expand_table(LoadedTables::get_instance().table_2());
    let mut new_table2entry = new_table2[0].clone();

    //println!("FileInfo after: {:#?}", new_fileinfo);

    // Add our edited copy to the end of our new table
    new_table2.push(new_table2entry);

    LoadedTables::get_instance().get_t1_mut(file_path_index).unwrap().table2_index = new_fileinfoindices.len() as u32 - 1;

    // Free the original FileInfoIndex table and replace by our own
    // let orig_pointer = arc.file_info_indices;
    // skyline::libc::free(orig_pointer as *mut libc::c_void);
    arc.file_info_indices = Box::leak(new_fileinfoindices.into_boxed_slice()).as_mut_ptr();
    //arc.file_infos = Box::leak(new_fileinfos.into_boxed_slice()).as_mut_ptr();
    arc.file_info_to_datas = Box::leak(new_info_to_datas.into_boxed_slice()).as_mut_ptr();
    arc.file_datas = Box::leak(new_filedatas.into_boxed_slice()).as_mut_ptr();
    // let orig_pointer = arc.file_infos;
    // skyline::libc::free(orig_pointer as *mut libc::c_void);

    LoadedTables::get_instance().table2 = Box::leak(new_table2.into_boxed_slice()).as_mut_ptr();
    LoadedTables::get_instance().table2_len += 1;

    

    //println!("Table2: {:#?}", LoadedTables::get_instance().table_2());

    
    // Write the new counts in the FileSystemHeader so Smash-arc is aware of the changes
    let mut fs_header = &mut *(arc.fs_header as *mut FileSystemHeader);
    // Increase the FileInfoIndice count
    fs_header.file_info_index_count += 1;
    fs_header.file_info_sub_index_count += 1;
    fs_header.sub_file_count += 1;
}

#[skyline::main(name = "arcropolis")]
pub fn main() {
    // Load hashes from rom:/skyline/hashes.txt if the file is present
    hashes::init();
    // Look for the offset of the various functions to hook
    offsets::search_offsets();

    install_hooks!(
        initial_loading,
        inflate_incoming,
        //loading_incoming,
        memcpy_uncompressed,
        memcpy_uncompressed_2,
        memcpy_uncompressed_3,
        load_directory_hook,
        manual_hook,
        before_loaded_tables,
        change_version_string,
        stream::lookup_by_stream_hash,
    );

    println!(
        "ARCropolis v{} - File replacement plugin is now installed",
        env!("CARGO_PKG_VERSION")
    );
}
