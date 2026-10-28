//! Process management syscalls
use crate::config::PAGE_SIZE;
use crate::mm::{MapPermission, PageTable, PageTableEntry, PTEFlags, VirtAddr};
use crate::task::{
    change_program_brk, current_user_token, exit_current_and_run_next, get_syscall_times,
    mmap_current, munmap_current, suspend_current_and_run_next,
};
use crate::timer::get_time_us;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Look up the PTE of the page containing user address `addr`.
fn user_pte(addr: usize) -> Option<PageTableEntry> {
    let page_table = PageTable::from_token(current_user_token());
    let pte = page_table.translate(VirtAddr::from(addr).floor())?;
    if pte.is_valid() {
        Some(pte)
    } else {
        None
    }
}

/// Physical address of user address `addr` according to its PTE.
fn user_pa(pte: PageTableEntry, addr: usize) -> usize {
    pte.ppn().0 * PAGE_SIZE + (addr & (PAGE_SIZE - 1))
}

/// Check that every page touched by `[addr, addr + len)` is user-accessible
/// and (if `write`) writable.
fn user_range_ok(addr: usize, len: usize, write: bool) -> bool {
    let mut offset = 0;
    while offset < len {
        let va = match addr.checked_add(offset) {
            Some(va) => va,
            None => return false,
        };
        let pte = match user_pte(va) {
            Some(pte) => pte,
            None => return false,
        };
        if !pte.flags().contains(PTEFlags::U) {
            return false;
        }
        if write {
            if !pte.writable() {
                return false;
            }
        } else if !pte.readable() {
            return false;
        }
        offset += PAGE_SIZE - (va & (PAGE_SIZE - 1));
    }
    true
}

/// Copy `data` into the current user address space at `addr`.
fn copy_to_user(addr: usize, data: &[u8]) -> bool {
    if !user_range_ok(addr, data.len(), true) {
        return false;
    }
    let mut offset = 0;
    while offset < data.len() {
        let va = addr + offset;
        let pte = user_pte(va).unwrap();
        let page_offset = va & (PAGE_SIZE - 1);
        let n = (PAGE_SIZE - page_offset).min(data.len() - offset);
        unsafe {
            core::ptr::copy_nonoverlapping(
                data[offset..offset + n].as_ptr(),
                user_pa(pte, va) as *mut u8,
                n,
            );
        }
        offset += n;
    }
    true
}

/// Read one byte from the current user address space.
fn read_user_u8(addr: usize) -> Option<u8> {
    let pte = user_pte(addr)?;
    if !pte.flags().contains(PTEFlags::U) || !pte.readable() {
        return None;
    }
    Some(unsafe { *(user_pa(pte, addr) as *const u8) })
}

/// Write one byte to the current user address space.
fn write_user_u8(addr: usize, value: u8) -> bool {
    let pte = match user_pte(addr) {
        Some(pte) => pte,
        None => return false,
    };
    if !pte.flags().contains(PTEFlags::U) || !pte.writable() {
        return false;
    }
    unsafe {
        *(user_pa(pte, addr) as *mut u8) = value;
    }
    true
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// get time with second and microsecond
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &time_val as *const TimeVal as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };
    // `TimeVal` may straddle a page boundary, so copy through the page table
    // instead of writing through the raw pointer.
    if copy_to_user(ts as usize, bytes) {
        0
    } else {
        -1
    }
}

/// trace syscall: read/write one byte of the user address space, or query
/// how many times the current task has invoked a syscall.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    match trace_request {
        // read one byte from user address `id`
        0 => match read_user_u8(id) {
            Some(byte) => byte as isize,
            None => -1,
        },
        // write the lowest byte of `data` to user address `id`
        1 => {
            if write_user_u8(id, data as u8) {
                0
            } else {
                -1
            }
        }
        // count of syscall `id` for the current task (current call included)
        2 => get_syscall_times(id) as isize,
        _ => -1,
    }
}

/// Map `[start, start + len)` into the current address space. `prot` is a
/// bitmask: R=1, W=2, X=4.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    trace!("kernel: sys_mmap");
    let start_va = VirtAddr::from(start);
    if !start_va.aligned() || (prot & !0x7) != 0 || (prot & 0x7) == 0 {
        return -1;
    }
    let mut permission = MapPermission::U;
    if prot & 0x1 != 0 {
        permission |= MapPermission::R;
    }
    if prot & 0x2 != 0 {
        permission |= MapPermission::W;
    }
    if prot & 0x4 != 0 {
        permission |= MapPermission::X;
    }
    if mmap_current(start_va, len, permission) {
        0
    } else {
        -1
    }
}

/// Unmap `[start, start + len)` from the current address space.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    let start_va = VirtAddr::from(start);
    if !start_va.aligned() {
        return -1;
    }
    let end_va = match start.checked_add(len) {
        Some(end) => VirtAddr::from(end),
        None => return -1,
    };
    if munmap_current(start_va, end_va) {
        0
    } else {
        -1
    }
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
