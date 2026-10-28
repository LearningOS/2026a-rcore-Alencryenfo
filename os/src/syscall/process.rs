//! Process management syscalls
//!
use alloc::sync::Arc;

use crate::{
    config::PAGE_SIZE,
    fs::{open_file, OpenFlags},
    mm::{translated_refmut, translated_str, MapPermission, PageTableEntry, VirtAddr},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next,
    },
    timer::get_time_us,
};

/// Look up the PTE of the page containing user address `addr`.
fn user_pte(addr: usize) -> Option<PageTableEntry> {
    let task = current_task()?;
    let inner = task.inner_exclusive_access();
    let pte = inner
        .memory_set
        .translate(VirtAddr::from(addr).floor())?;
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
        if !pte.user() {
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

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    //trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        task.exec(all_data.as_slice());
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    //trace!("kernel: sys_waitpid");
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// get time with second and microsecond
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel:pid[{}] sys_get_time", current_task().unwrap().pid.0);
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
    if copy_to_user(ts as usize, bytes) {
        0
    } else {
        -1
    }
}

/// Map `[start, start + len)` into the current address space. `prot` is a
/// bitmask: R=1, W=2, X=4.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    trace!("kernel:pid[{}] sys_mmap", current_task().unwrap().pid.0);
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
    if current_task().unwrap().mmap(start_va, len, permission) {
        0
    } else {
        -1
    }
}

/// Unmap `[start, start + len)` from the current address space.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_munmap", current_task().unwrap().pid.0);
    let start_va = VirtAddr::from(start);
    if !start_va.aligned() {
        return -1;
    }
    let end_va = match start.checked_add(len) {
        Some(end) => VirtAddr::from(end),
        None => return -1,
    };
    if current_task().unwrap().munmap(start_va, end_va) {
        0
    } else {
        -1
    }
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// Create a child process running `path` without copying the address space.
pub fn sys_spawn(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_spawn", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        let new_task = task.spawn(all_data.as_slice());
        let pid = new_task.pid.0;
        add_task(new_task);
        pid as isize
    } else {
        -1
    }
}

/// Set the current process's scheduling priority (must be >= 2).
pub fn sys_set_priority(prio: isize) -> isize {
    trace!("kernel:pid[{}] sys_set_priority", current_task().unwrap().pid.0);
    if prio < 2 {
        return -1;
    }
    current_task().unwrap().set_priority(prio as usize);
    prio
}
