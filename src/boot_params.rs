//! This file contains declarations pertinent to the x86 Linux
//! boot protocol

#![allow(dead_code)]

pub const BOOT_CODE_CS_GDT_INDEX: u16 = 2;
pub const BOOT_CODE_SS_GDT_INDEX: u16 = 3;
pub const BOOT_CODE_LDT_GDT_INDEX: u16 = 6;
pub const BOOT_CODE_TSS_GDT_INDEX: u16 = 8;

pub const BOOT_CODE_CS: u16 = BOOT_CODE_CS_GDT_INDEX << 3;
pub const BOOT_CODE_DS: u16 = BOOT_CODE_SS_GDT_INDEX << 3;
pub const BOOT_CODE_LDT: u16 = BOOT_CODE_LDT_GDT_INDEX << 3;
pub const BOOT_CODE_TSS: u16 = BOOT_CODE_TSS_GDT_INDEX << 3;

#[repr(C, packed)]
pub struct ScreenInfo {
    pub orig_x: u8,
    pub orig_y: u8,
    pub ext_mem_k: u16,
    pub orig_video_page: u16,
    pub orig_video_mode: u8,
    pub orig_video_cols: u8,
    pub flags: u8,
    pub unused2: u8,
    pub orig_video_ega_bx: u16,
    pub unused3: u16,
    pub orig_video_lines: u8,
    pub orig_video_is_vga: u8,
    pub orig_video_points: u16,
    pub lfb_width: u16,
    pub lfb_height: u16,
    pub lfb_depth: u16,
    pub lfb_base: u32,
    pub lfb_size: u32,
    pub cl_magic: u16,
    pub cl_offset: u16,
    pub lfb_linelength: u16,
    pub red_size: u8,
    pub red_pos: u8,
    pub green_size: u8,
    pub green_pos: u8,
    pub blue_size: u8,
    pub blue_pos: u8,
    pub rsvd_size: u8,
    pub rsvd_pos: u8,
    pub vesapm_seg: u16,
    pub vesapm_off: u16,
    pub pages: u16,
    pub vesa_attributes: u16,
    pub capabilities: u32,
    pub ext_lfb_base: u32,
    pub _reserved: [u8; 2],
}

static_assertions::const_assert_eq!(std::mem::size_of::<ScreenInfo>(), 64);

#[repr(C, packed)]
pub struct ApmBiosInfo {
    pub version: u16,
    pub cseg: u16,
    pub offset: u32,
    pub cseg_16: u16,
    pub dseg: u16,
    pub flags: u16,
    pub cseg_len: u16,
    pub cseg_16_len: u16,
    pub dseg_len: u16,
}

static_assertions::const_assert_eq!(std::mem::size_of::<ApmBiosInfo>(), 20);

#[repr(C, packed)]
pub struct IstInfo {
    pub signature: u32,
    pub command: u32,
    pub event: u32,
    pub perf_level: u32,
}

static_assertions::const_assert_eq!(std::mem::size_of::<IstInfo>(), 16);

#[repr(C, packed)]
pub struct SysDescTable {
    pub length: u16,
    pub table: [u8; 14],
}

static_assertions::const_assert_eq!(std::mem::size_of::<SysDescTable>(), 16);

#[repr(C, packed)]
pub struct OlpcOfwHeader {
    pub ofw_magic: u32,
    pub ofw_version: u32,
    pub cif_handler: u32,
    pub irq_desc_table: u32,
}

static_assertions::const_assert_eq!(std::mem::size_of::<OlpcOfwHeader>(), 16);

#[repr(C, packed)]
pub struct EfiInfo {
    pub efi_loader_signature: u32,
    pub efi_systab: u32,
    pub efi_memdesc_size: u32,
    pub efi_memdesc_version: u32,
    pub efi_memmap: u32,
    pub efi_memmap_size: u32,
    pub efi_systab_hi: u32,
    pub efi_memmap_hi: u32,
}

static_assertions::const_assert_eq!(std::mem::size_of::<EfiInfo>(), 32);

#[repr(C, packed)]
pub struct SetupHeader {
    pub setup_sects: u8,
    pub root_flags: u16,
    pub syssize: u32,
    pub ram_size: u16,
    pub vid_mode: u16,
    pub root_dev: u16,
    pub boot_flag: u16,
    pub jump: u16,
    pub header: u32,
    pub version: u16,
    pub realmode_swtch: u32,
    pub start_sys_seg: u16,
    pub kernel_version: u16,
    pub type_of_loader: u8,
    pub loadflags: u8,
    pub setup_move_size: u16,
    pub code32_start: u32,
    pub ramdisk_image: u32,
    pub ramdisk_size: u32,
    pub bootsect_kludge: u32,
    pub heap_end_ptr: u16,
    pub ext_loader_ver: u8,
    pub ext_loader_type: u8,
    pub cmd_line_ptr: u32,
    pub initrd_addr_max: u32,
    pub kernel_alignment: u32,
    pub relocatable_kernel: u8,
    pub min_alignment: u8,
    pub xloadflags: u16,
    pub cmdline_size: u32,
    pub hardware_subarch: u32,
    pub hardware_subarch_data: u64,
    pub payload_offset: u32,
    pub payload_length: u32,
    pub setup_data: u64,
    pub pref_address: u64,
    pub init_size: u32,
    pub handover_offset: u32,
    pub kernel_info_offset: u32,
}

static_assertions::const_assert_eq!(std::mem::size_of::<SetupHeader>(), 123);

#[repr(C, packed)]
pub struct BootE820Entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
}

static_assertions::const_assert_eq!(std::mem::size_of::<BootE820Entry>(), 20);

#[repr(C, packed)]
pub struct BootParams {
    pub screen_info: ScreenInfo,
    pub apm_bios_info: ApmBiosInfo,
    pub _pad2: [u8; 4],
    pub tboot_addr: u64,
    pub ist_info: IstInfo,
    pub acpi_rsdp_addr: u64,
    pub _pad3: [u8; 8],
    pub hd0_info: [u8; 16],
    pub hd1_info: [u8; 16],
    pub sys_desc_table: SysDescTable,
    pub olpc_ofw_header: OlpcOfwHeader,
    pub ext_ramdisk_image: u32,
    pub ext_ramdisk_size: u32,
    pub ext_cmd_line_ptr: u32,
    pub _pad4: [u8; 116],
    pub edid_info: [u8; 128],
    pub efi_info: EfiInfo,
    pub alt_mem_k: u32,
    pub scratch: u32,
    pub e820_entries: u8,
    pub eddbuf_entries: u8,
    pub edd_mbr_sig_buf_entries: u8,
    pub kbd_status: u8,
    pub secure_boot: u8,
    pub _pad5: u16,
    pub sentinel: u8,
    pub _pad6: u8,
    pub setup_header: SetupHeader,
    pub _pad7: [u8; 36],
    pub edd_mbr_sig_buffer: [u32; 16],
    pub e820_table: [BootE820Entry; 128],
    pub _pad8: [u8; 48],
    pub eddbuf: [u8; 492],
    pub _pad9: [u8; 276],
}

static_assertions::const_assert_eq!(std::mem::size_of::<BootParams>(), 4096);

impl Default for BootParams {
    fn default() -> BootParams {
        unsafe { std::mem::zeroed() }
    }
}
