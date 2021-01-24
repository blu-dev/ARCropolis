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

use smash_arc::{ArcLookup, FileInfo, FileInfoIndex, FilePath, FileSystemHeader, Hash40, FileInfoFlags };

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

#[hook(offset = INITIAL_LOADING_OFFSET, inline)]
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

        //unshared();
        lazy_static::initialize(&ARC_FILES);

        nn::oe::SetCpuBoostMode(nn::oe::CpuBoostMode::Disabled);
    }
}

// Before the tables are initialized, so they're automatically initialized with the right size
#[hook(offset = 0x35c641c, inline)]
unsafe fn before_loaded_tables(_ctx: &InlineCtx) {
    unshared();
}

pub unsafe fn unshared() {
    let tables = LoadedTables::get_instance();
    //println!("{:?}", tables);

    let arc = tables.get_arc_mut();

    // Get the index of the FilePath for this specific entry. Marth's original c00 numshb path.index() is 143623. This has to be changed to 156923 (FileInfoIndices.len() + 1) for testing purposes.
    let file_path_index = arc.get_file_path_index_from_hash(Hash40::from("fighter/marth/model/body/c00/model.numshb")).unwrap();

    // Here, we'll make a new FileInfoIndices table so we can add a new entry for the FilePath to refer to
    let file_info_indices = arc.get_file_info_indices();
    // Allocate a new table, copy the original content
    let mut new_fileinfoindices: Box<Vec<FileInfoIndex>> = Box::new(Vec::new());
    new_fileinfoindices.extend_from_slice(file_info_indices);
    // We don't need the original FileInfoIndices table anymore, drop it
    drop(file_info_indices);

    // Get the FilePath for the hash
    let mut file_path = &mut *(&arc.get_file_paths()[file_path_index as usize] as *const FilePath as *mut FilePath);


    /// FileInfoIndices

    // Copy the original FileInfoIndex
    let mut new_fileinfoindex = arc.get_file_info_indices()[file_path.path.index() as usize].clone();
    //println!("FileInfoIndex before: {:#?}", new_fileinfoindex);
    // Increment the FileInfo count by one for our future new entry
    new_fileinfoindex.file_info_index = arc.get_file_infos().len() as u32;
    //println!("FileInfoIndex after: {:#?}", new_fileinfoindex);
    // Add our edited copy to the end of our new table
    new_fileinfoindices.push(new_fileinfoindex);
    info!("FileInfoIndices table new size: {}", new_fileinfoindices.len());
    // We drop this since we won't need it anymore
    drop(new_fileinfoindex);


    /// FileInfos

    // Make a new FileInfo table so we can add a new entry for the FileInfoIndex to refer to
    let file_infos = arc.get_file_infos();
    // Allocate a new table, copy the original content
    let mut new_fileinfos: Box<Vec<FileInfo>> = Box::new(Vec::new());
    new_fileinfos.extend_from_slice(file_infos);
    // We don't need the original FileInfo table anymore, drop it
    drop(file_infos);

    // Get the original FileInfo so we can copy it
    let mut new_fileinfo = arc.get_file_info_from_path_index(file_path_index).clone();

    //println!("FileInfo before: {:#?}", new_fileinfo);

    // Set the FileInfoIndices index of the FileInfo to our new FileInfoIndex
    new_fileinfo.hash_index_2 = new_fileinfoindices.len() as u32;
    new_fileinfo.flags.set_is_redirect(false); // Is this actually necessary? Seems unused in Smash's code

    //println!("FileInfo after: {:#?}", new_fileinfo);

    // Add our edited copy to the end of our new table
    new_fileinfos.push(new_fileinfo);
    info!("FileInfos table new size: {}", new_fileinfos.len());
    // We drop the new FileInfo now that it has been pushed to the table
    drop(new_fileinfo);


    /// Table pointers replacement

    // Now that all the tables have been extended and we don't need to reference Set the index to point to the new entry at the end of the FileInfoIndices table
    file_path.path.set_index(new_fileinfoindices.len() as u32 - 1);
    info!("File_path path.index: {}", file_path.path.index());
    drop(file_path);

    // Free the original FileInfoIndex table and replace by our own
    let orig_pointer = arc.file_info_indices;
    //skyline::libc::free(orig_pointer as *mut libc::c_void);
    arc.file_info_indices = Box::leak(new_fileinfoindices.into_boxed_slice()).as_mut_ptr();

    arc.file_infos = Box::leak(new_fileinfos.into_boxed_slice()).as_mut_ptr();

    
    // Write the new counts in the FileSystemHeader so Smash-arc is aware of the changes
    let mut fs_header = &mut *(arc.fs_header as *mut FileSystemHeader);
    // Increase the FileInfoIndice count
    fs_header.file_info_index_count += 1;
    fs_header.file_info_count += 1;
    drop(fs_header);

    // We have everything we need here
    drop(arc);
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
