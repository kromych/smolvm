//! Functions and data-structures for working with descriptor tables.
//! Functionality to manipulate segment registers, build segement
//! descriptors and selectors.

// The MIT License (MIT)

// Copyright (c) 2015 Gerd Zellweger
// Copyright (c) 2015 The libcpu Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#![allow(dead_code)]

use bitflags::*;

pub const CR0_PE: u64 = 0x1;
pub const CR0_PG: u64 = 0x8000_0000;

pub const CR4_PAE: u64 = 0x20;

pub const EFER_SCE: u64 = 0x001;
pub const EFER_LME: u64 = 0x100;
pub const EFER_LMA: u64 = 0x400;
pub const EFER_NXE: u64 = 0x800;

pub const MSR_CR_PAT: u32 = 0x00000277;
pub const MSR_CR_PAT_DEFAULT: u64 = 0x0007040600070406;

/// System-Segment and Gate-Descriptor Types 64-bit mode
/// See also Intel 3a, Table 3-2 System Segment and Gate-Descriptor Types.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SystemDescriptorTypes64 {
    Ldt = 0b0010,
    TssAvailable = 0b1001,
    TssBusy = 0b1011,
    CallGate = 0b1100,
    InterruptGate = 0b1110,
    TrapGate = 0b1111,
}

/// Data Segment types for descriptors.
/// See also Intel 3a, Table 3-1 Code- and Data-Segment Types.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataSegmentType {
    /// Data Read-Only
    ReadOnly = 0b0000,
    /// Data Read-Only, accessed
    ReadOnlyAccessed = 0b0001,
    /// Data Read/Write
    ReadWrite = 0b0010,
    /// Data Read/Write, accessed
    ReadWriteAccessed = 0b0011,
    /// Data Read-Only, expand-down
    ReadExpand = 0b0100,
    /// Data Read-Only, expand-down, accessed
    ReadExpandAccessed = 0b0101,
    /// Data Read/Write, expand-down
    ReadWriteExpand = 0b0110,
    /// Data Read/Write, expand-down, accessed
    ReadWriteExpandAccessed = 0b0111,
}

/// Code Segment types for descriptors.
/// See also Intel 3a, Table 3-1 Code- and Data-Segment Types.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodeSegmentType {
    /// Code Execute-Only
    Execute = 0b1000,
    /// Code Execute-Only, accessed
    ExecuteAccessed = 0b1001,
    /// Code Execute/Read
    ExecuteRead = 0b1010,
    /// Code Execute/Read, accessed
    ExecuteReadAccessed = 0b1011,
    /// Code Execute-Only, conforming
    ExecuteConforming = 0b1100,
    /// Code Execute-Only, conforming, accessed
    ExecuteConformingAccessed = 0b1101,
    /// Code Execute/Read, conforming
    ExecuteReadConforming = 0b1110,
    /// Code Execute/Read, conforming, accessed
    ExecuteReadConformingAccessed = 0b1111,
}

macro_rules! bit {
    ($x:expr) => {
        1 << $x
    };
}

pub const PAGE_SHIFT: u64 = 12;
pub const PAGE_SIZE: u64 = 1 << PAGE_SHIFT;

pub const fn get_pfn(phys_addr: u64) -> u64 {
    phys_addr >> PAGE_SHIFT
}

bitflags! {
    /// PML4 configuration bit description.
    #[repr(transparent)]
    pub struct PML4Flags: u64 {
        /// Present; must be 1 to reference a page-directory-pointer table
        const P       = bit!(0);
        /// Read/write; if 0, writes may not be allowed to the 512-GByte region
        /// controlled by this entry (see Section 4.6)
        const RW      = bit!(1);
        /// User/supervisor; if 0, user-mode accesses are not allowed
        /// to the 512-GByte region controlled by this entry.
        const US      = bit!(2);
        /// Page-level write-through; indirectly determines the memory type used to
        /// access the page-directory-pointer table referenced by this entry.
        const PWT     = bit!(3);
        /// Page-level cache disable; indirectly determines the memory type used to
        /// access the page-directory-pointer table referenced by this entry.
        const PCD     = bit!(4);
        /// Accessed; indicates whether this entry has been used for linear-address translation.
        const A       = bit!(5);
        /// If IA32_EFER.NXE = 1, execute-disable
        /// If 1, instruction fetches are not allowed from the 512-GByte region.
        const XD      = bit!(63);
    }
}

bitflags! {
    /// PDPT configuration bit description.
    #[repr(transparent)]
    pub struct PDPTFlags: u64 {
        /// Present; must be 1 to map a 1-GByte page or reference a page directory.
        const P       = bit!(0);
        /// Read/write; if 0, writes may not be allowed to the 1-GByte region controlled by this entry
        const RW      = bit!(1);
        /// User/supervisor; user-mode accesses are not allowed to the 1-GByte region controlled by this entry.
        const US      = bit!(2);
        /// Page-level write-through.
        const PWT     = bit!(3);
        /// Page-level cache disable.
        const PCD     = bit!(4);
        /// Accessed; if PS set indicates whether software has accessed the 1-GByte page
        /// else indicates whether this entry has been used for linear-address translation
        const A       = bit!(5);
        /// Dirty; if PS indicates whether software has written to the 1-GByte page referenced by this entry.
        /// else ignored.
        const D       = bit!(6);
        /// Page size; if set this entry maps a 1-GByte page; otherwise, this entry references a page directory.
        /// if not PS this is ignored.
        const PS      = bit!(7);
        /// Global; if PS && CR4.PGE = 1, determines whether the translation is global; ignored otherwise
        /// if not PS this is ignored.
        const G       = bit!(8);
        /// Indirectly determines the memory type used to access the 1-GByte page referenced by this entry.
        const PAT     = bit!(12);
        /// If IA32_EFER.NXE = 1, execute-disable
        /// If 1, instruction fetches are not allowed from the 512-GByte region.
        const XD      = bit!(63);
    }
}

bitflags! {
    /// PD configuration bits description.
    #[repr(transparent)]
    pub struct PDFlags: u64 {
        /// Present; must be 1 to map a 2-MByte page or reference a page table.
        const P       = bit!(0);
        /// Read/write; if 0, writes may not be allowed to the 2-MByte region controlled by this entry
        const RW      = bit!(1);
        /// User/supervisor; user-mode accesses are not allowed to the 2-MByte region controlled by this entry.
        const US      = bit!(2);
        /// Page-level write-through.
        const PWT     = bit!(3);
        /// Page-level cache disable.
        const PCD     = bit!(4);
        /// Accessed; if PS set indicates whether software has accessed the 2-MByte page
        /// else indicates whether this entry has been used for linear-address translation
        const A       = bit!(5);
        /// Dirty; if PS indicates whether software has written to the 2-MByte page referenced by this entry.
        /// else ignored.
        const D       = bit!(6);
        /// Page size; if set this entry maps a 2-MByte page; otherwise, this entry references a page directory.
        const PS      = bit!(7);
        /// Global; if PS && CR4.PGE = 1, determines whether the translation is global; ignored otherwise
        /// if not PS this is ignored.
        const G       = bit!(8);
        /// Indirectly determines the memory type used to access the 2-MByte page referenced by this entry.
        /// if not PS this is ignored.
        const PAT     = bit!(12);
        /// If IA32_EFER.NXE = 1, execute-disable
        /// If 1, instruction fetches are not allowed from the 512-GByte region.
        const XD      = bit!(63);
    }
}

bitflags! {
    /// PT Entry bits description.
    #[repr(transparent)]
    pub struct PTFlags: u64 {
        /// Present; must be 1 to map a 4-KByte page.
        const P       = bit!(0);
        /// Read/write; if 0, writes may not be allowed to the 4-KByte region controlled by this entry
        const RW      = bit!(1);
        /// User/supervisor; user-mode accesses are not allowed to the 4-KByte region controlled by this entry.
        const US      = bit!(2);
        /// Page-level write-through.
        const PWT     = bit!(3);
        /// Page-level cache disable.
        const PCD     = bit!(4);
        /// Accessed; indicates whether software has accessed the 4-KByte page
        const A       = bit!(5);
        /// Dirty; indicates whether software has written to the 4-KByte page referenced by this entry.
        const D       = bit!(6);
        /// Global; if CR4.PGE = 1, determines whether the translation is global (see Section 4.10); ignored otherwise
        const G       = bit!(8);
        /// If IA32_EFER.NXE = 1, execute-disable
        /// If 1, instruction fetches are not allowed from the 512-GByte region.
        const XD      = bit!(63);
    }
}
