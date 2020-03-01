//! #libunwind-rs
//!
//! `libunwind-rs`  is a library providing safe Rust API for retrieving backtrace from local and
//! remote process, and also from coredumps. Crate is build on a top of [libunwind] library.
//! 
//! [libunwind]: http://www.nongnu.org/libunwind/
extern crate num_derive;

use libunwind_sys::*;
use std::fmt; 
use std::ffi::CStr;
use foreign_types::{foreign_type, ForeignType};
use std::path::Path;
use std::ffi::CString;
use std::mem::MaybeUninit;
use libc::{c_void, c_char, c_ulong};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

/// Error codes.  The unwind routines return the *negated* values of 
/// these error codes on error and a non-negative value on success.
#[derive(Copy, Clone, Debug, PartialEq, Eq,FromPrimitive)]
 pub enum Error {
    ///no error 
    Succsess = 0,
    /// unspecified (general) error 
    Unspec  = -1,        
    /// out of memory 
    NoMem  = -2,     
    /// bad register number 
    BadReg = -3, 
    /// attempt to write read-only register 
    ReadOnlyReg = -4,  
    /// stop unwinding       
    StopUnwind  = -5, 
    /// invalid IP 
    InvalidIp = -6, 
    ///bad frame 
    BadFrame = -7,  
    /// unsupported operation or bad value 
    InVal = -8, 
    /// unwind info has unsupported version 
    BadVersion = -9,  
    /// no unwind info found   
    NoInfo = -10         
}    

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let e = CStr::from_ptr(unw_strerror(self.clone() as i32));
            write!(f,"{}", e.to_string_lossy())
        }
    }
}

///These are backend callback routines that provide access to the
///state of a "remote" process.  This can be used, for example, to
///unwind another process through the ptrace() interface.
pub struct Accessors(unw_accessors_t);

impl Accessors {
    /// Method returns Accessors for ptrace()
    pub fn ptrace() -> &'static   Accessors {
        unsafe { &*(&_UPT_accessors as *const unw_accessors_t as *const Accessors) }
    }
    /// Method returns Accessors for coredump
    pub fn coredump() -> &'static   Accessors {
        unsafe { &*(&_UCD_accessors as *const unw_accessors_t as *const Accessors) }
    }
}
///The endianness (byte order) of a stream of bytes
pub enum Byteorder {
    Default = 0,
    LitleEndian = 1234,
    BigEndian = 3214,
    PdpEndian = 3412
}

foreign_type! { 
/// Struct represents an address space of unwinding procces
    pub unsafe type AddressSpace  {
        type CType = libunwind_sys::unw_addr_space;
        fn drop = unw_destroy_addr_space;
    }
}

impl AddressSpace {
    /// Method constructs `AddressSpace` from given accessors and byteorder 
    /// # Arguments
    ///
    /// * `accessors` - Bunch of Accessors functions (Ptrace, Coredump)
    ///
    /// * `byteorder` - Endianess  of target machine
    pub fn new(accessors: &Accessors, byteorder: Byteorder) -> Result<AddressSpace, Error> {
        unsafe {
            let ptr = unw_create_addr_space(
                &accessors.0 as *const unw_accessors_t as *mut unw_accessors_t,
                byteorder as i32,
            );
            if ptr.is_null() {
                Err(Error::Unspec)
            } else {
                Ok(AddressSpace::from_ptr(ptr))
            }
        }
    }
}

foreign_type! { 
    ///This state is used by accessors 
    pub unsafe type CoredumpState {
        type CType = libunwind_sys::UCD_info;
        fn drop = _UCD_destroy;
    }
}

impl CoredumpState {
    /// Method constructs new CoredumpState from path to core file.  
    /// # Arguments
    ///
    /// * `accessors` - Bunch of Accessors functions (Ptrace, Coredump)
    ///
    /// * `byteorder` - Endianess  of target machine
    pub fn new(core_path: &Path) -> Result<CoredumpState, Error> {
        unsafe {
            let core_path = CString::new(core_path.to_str().unwrap()).unwrap();
            let ui = _UCD_create(core_path.as_ptr());
            if ui.is_null() {
                Err(Error::NoMem)
            } else {
                Ok(CoredumpState::from_ptr(ui))
            }
        }
    }
    
    /// Method maps executable to specified  virtual address.  
    /// # Arguments
    ///
    /// * `file_path` - path to executable
    ///
    /// * `vaddr` - address to map
    pub fn load_file_at_vaddr(&mut self, file_path: &Path, vaddr: usize) {
        unsafe {
            let file_path = CString::new(file_path.to_str().unwrap()).unwrap();
            _UCD_add_backing_file_at_vaddr(self.0.as_ptr(), vaddr as c_ulong, file_path.as_ptr());
        }
    }
    /// Method returns current thread id
    pub fn pid(&mut self) -> i32 {
        unsafe {
            _UCD_get_pid(self.0.as_ptr())
         }
    }
    /// Method returns  the number of threads 
    pub fn num_threads(&mut self) -> i32 {
        unsafe {
            _UCD_get_num_threads(self.0.as_ptr())
         }
    }
    /// Method selects thread by provided thread id
    /// # Arguments
    ///
    /// * `id` - thread identifier
    pub fn select_thread(&mut self, id : i32) {
        unsafe {
            _UCD_select_thread(self.0.as_ptr(), id);
        }
    }

    /// Method gets value for memory address
    /// # Arguments
    ///
    /// * `asp` - AddressSpace struct
    /// 
    /// * `address` - memory address to access
    pub fn access_mem(&mut self, asp: &AddressSpace, address: usize) -> Result<usize, Error> {
        unsafe {
            let mut val: unw_word_t = 0;
            let ret = _UCD_access_mem(asp.0.as_ptr(), address as unw_word_t, &mut val, 0, self.0.as_ptr() as * mut libc::c_void);
            if ret == (Error::Succsess as i32) {
                Ok(val as usize)
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }
}

foreign_type! { 
    ///This state is used by accessors 
    pub unsafe type PtraceState {
        type CType = libc::c_void;
        fn drop = _UPT_destroy;
    }
}

impl PtraceState {
    /// Method constructs constructs new CoredumpState from path to core file.  
    /// # Arguments
    ///
    /// * `pid` - Pid for remote proccess
    pub fn new(pid: u32) -> Result<PtraceState, Error> {
         unsafe {
            let ptr = _UPT_create(pid as _);
            if ptr.is_null() {
                Err(Error::NoMem)
            } else {
                Ok(PtraceState::from_ptr(ptr))
            }
        }
    }
}

///Information about called procedure
#[derive(Clone, Copy)]
pub struct ProcInfo {
    start_ip: usize,
    end_ip: usize 
}

impl ProcInfo {
    ///Method returns start address of procedure
    pub fn start(&self) -> usize {
        self.start_ip 
    }

    ///Method returns end address of procedure
    pub fn end(&self) -> usize {
        self.end_ip 
    }
}

#[derive(Clone)]
pub struct Cursor(unw_cursor_t);
impl Cursor {
    /// Method constructs cursor for coredump unwinding.  
    /// # Arguments
    ///
    /// * `address_space` - configured AddressSpace 
    ///
    /// * `state` - Configured CoredumpState
    pub fn coredump(address_space: &mut AddressSpace, state: &CoredumpState) -> Result<Cursor, Error> {
        unsafe {
            let mut cursor = MaybeUninit::uninit();
            let ret = unw_init_remote(
                cursor.as_mut_ptr(),
                address_space.0.as_ptr(),
                state.0.as_ptr() as *mut c_void,
            );
            if ret == (Error::Succsess as i32) {
                Ok(Cursor(cursor.assume_init()))
         } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }
    
    /// Method constructs cursor for remote  unwinding.  
    /// # Arguments
    ///
    /// * `address_space` - configured AddressSpace 
    ///
    /// * `state` - Configured CoredumpState
    pub fn ptrace(address_space: &mut AddressSpace, state: &PtraceState) -> Result<Cursor, Error> {
        unsafe {
            let mut cursor = MaybeUninit::uninit();
            let ret = unw_init_remote(
                cursor.as_mut_ptr(),
                address_space.0.as_ptr(),
                state.0.as_ptr() as *mut c_void,
            );
            if ret == (Error::Succsess as i32) {
                Ok(Cursor(cursor.assume_init()))
         } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }

    /// Method constructs cursor for local  unwinding.  
    /// # Arguments
    ///
    /// * `f` - function to work with local cursor 
    pub fn local<F, T>(f: F) -> Result<T, Error>
    where
        F: FnOnce(Cursor) -> Result<T, Error>,
    {
        unsafe {
            let mut context = MaybeUninit::uninit();
            let ret = unw_getcontext(context.as_mut_ptr());
            if ret != (Error::Succsess as i32) {
                return   Err(FromPrimitive::from_i32(ret).unwrap());
            }
            let mut context = context.assume_init();

            let mut cursor = MaybeUninit::uninit();
            let ret = unw_init_local(cursor.as_mut_ptr(), &mut context);
            if ret != (Error::Succsess as i32) {
                return   Err(FromPrimitive::from_i32(ret).unwrap());
            }

            f(Cursor(cursor.assume_init()))
        }
    }

    /// Method executes step on cursor.  
    /// # Return
    ///
    /// * `true`  - if step is executed
    ///
    /// * `false` - if cursor ends
    ///
    /// * `Error` - if error while steping is occured
    pub fn step(&mut self) -> Result<bool, Error> {
        unsafe {
            let ret = unw_step(&mut self.0);
            if ret > 0 {
                Ok(true)
            } else if ret == 0 {
                Ok(false)
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }
    
    /// Method returns register value  
    /// # Arguments
    ///
    /// * `id`  - register's identifier
    pub fn register(&mut self, id: i32) -> Result<usize, Error> {
        unsafe {
            let mut value = 0;
            let ret = unw_get_reg(&self.0 as *const _ as *mut _, id, &mut value);
            if ret == (Error::Succsess as i32) {
                Ok(value as usize)
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }
    
    /// Method returns instructions pointer value 
    pub fn ip(&mut self) ->  Result<usize, Error> {
        unsafe {
            let mut value = 0;
            let ret = unw_get_reg(&self.0 as *const _ as *mut _, libunwind_sys::UNW_TDEP_IP as i32, &mut value);
            if ret == (Error::Succsess as i32) {
                Ok(value as usize)
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }
    
    /// Method returns stack pointer value 
    pub fn sp(&mut self) ->  Result<usize, Error> {
        unsafe {
            let mut value = 0;
            let ret = unw_get_reg(&self.0 as *const _ as *mut _, libunwind_sys::UNW_TDEP_SP as i32, &mut value);
            if ret == (Error::Succsess as i32) {
                Ok(value as usize)
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }

    /// Method returns procedure information at crurrent stack frame
    pub fn proc_info(&mut self) -> Result<ProcInfo,Error> {
        unsafe {
            let mut info = MaybeUninit::uninit();
            let ret = unw_get_proc_info(&self.0 as *const _ as *mut _, info.as_mut_ptr());
            if ret == (Error::Succsess as i32) {
                let info = info.assume_init();
                Ok(ProcInfo {
                    start_ip: info.start_ip as usize,
                    end_ip: info.end_ip as usize,
                })
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }
    
    /// Method returns procedure information at crurrent stack frame
    pub fn proc_name(&mut self) -> Result<String, Error> {
        unsafe {
            let mut name_vec = vec![0;256];
            let mut offset = 0;
            let ret = unw_get_proc_name(& self.0 as *const _ as * mut _, name_vec.as_mut_ptr() as * mut c_char, name_vec.len(), &mut offset);
            if ret == (Error::Succsess as i32) {
                let name = CStr::from_ptr(name_vec.as_mut_ptr());
                Ok(name.to_str().unwrap().to_string())
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }
    
    /// Method returns true if frame is signal frame
    pub fn is_signal_frame(&mut self) -> Result<bool, Error> {
        unsafe {
            let ret = unw_is_signal_frame(&self.0 as *const _ as *mut _);
            if ret < 0 {
                Err(FromPrimitive::from_i32(ret).unwrap())
            } else {
                Ok(ret != 0)
            }
        }
    }

}
#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use crate::*;
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_core_unwind() {
        let mut libc_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        libc_path_buf.push("data/libc-2.23.so");
        let mut test_callstack_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_callstack_path_buf.push("data/test_callstack");
        let mut core_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        core_path_buf.push("data/core.test_callstack");
        let test_callstack_start:usize = 0x400000;
        let libc_start:usize = 0x00007f9ac7468000;
   
        let mut  state = CoredumpState::new(&core_path_buf).unwrap();
        state.load_file_at_vaddr(&test_callstack_path_buf, test_callstack_start);
        state.load_file_at_vaddr(&libc_path_buf, libc_start);
        let mut address_space = AddressSpace::new(Accessors::coredump(), Byteorder::Default).unwrap();
        let mut  cursor = Cursor::coredump(&mut address_space, &state).unwrap();
        
        let mut backtrace = String::new();
        loop { 
            let  ip = cursor.ip().unwrap();
            let sp = cursor.sp().unwrap();
            if let Err(_e) = state.access_mem(&address_space, sp) {
                assert!(false);
            }
            let  name = cursor.proc_name().unwrap();
            backtrace.push_str(&format!("0x{:x} in {:?} ()\n", ip, name));
            let  ret = cursor.step().unwrap();
                if ret == false  {
                    break;
                }
        }
        assert!(backtrace.contains("main"), true);
        assert!(backtrace.contains("first"), true);
        assert!(backtrace.contains("second"), true);
        assert!(backtrace.contains("third"), true);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_core_unwind_heap_error() {
        let mut libc_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        libc_path_buf.push("data/libc-2.23.so");
        let mut test_heap_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_heap_path_buf.push("data/test_heapError");
        let mut core_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        core_path_buf.push("data/core.test_heapError");
        let test_heap_start:usize = 0x000055b7b218c000;
        let libc_start:usize = 0x00007f90e058b000;
        
        let mut  state = CoredumpState::new(&core_path_buf).unwrap();
        state.load_file_at_vaddr(&test_heap_path_buf, test_heap_start);
        state.load_file_at_vaddr(&libc_path_buf, libc_start);
        let mut address_space = AddressSpace::new(Accessors::coredump(), Byteorder::Default).unwrap();
        let mut  cursor = Cursor::coredump(&mut address_space, &state).unwrap();
        
        let mut backtrace = String::new();
        loop { 
            let  ip = cursor.ip().unwrap();
            let sp = cursor.sp().unwrap();
            if let Err(_e) = state.access_mem(&address_space, sp) {
                assert!(false);
            }
            let  name = cursor.proc_name().unwrap();
            backtrace.push_str(&format!("0x{:x} in {:?} ()\n", ip, name));
            let  ret = cursor.step().unwrap();
            if ret == false  {
                break;
            }
        }   
        assert!(backtrace.contains("main"), true);
        assert!(backtrace.contains("cfree"), true);
    }
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_core_unwind_canary() {
        let mut libc_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        libc_path_buf.push("data/libc-2.23.so");
        let mut test_canary_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_canary_path_buf.push("data/test_canary");
        let mut core_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        core_path_buf.push("data/core.test_canary");
        let test_canary_start:usize = 0x0000558672376000;
        let libc_start:usize = 0x00007fc14b336000;

        let mut  state = CoredumpState::new(&core_path_buf).unwrap();
        state.load_file_at_vaddr(&test_canary_path_buf, test_canary_start);
        state.load_file_at_vaddr(&libc_path_buf, libc_start);
        let mut address_space = AddressSpace::new(Accessors::coredump(), Byteorder::Default).unwrap();
        let mut  cursor = Cursor::coredump(&mut address_space, &state).unwrap();
        
        let mut backtrace = String::new();
        loop { 
            let  ip = cursor.ip().unwrap();
            let sp = cursor.sp().unwrap();
            if let Err(_e) = state.access_mem(&address_space, sp) {
                assert!(false);
            }
            let  name = cursor.proc_name().unwrap();
            backtrace.push_str(&format!("0x{:x} in {:?} ()\n", ip, name));
            let  ret = cursor.step().unwrap();
            if ret == false  {
                break;
            }
        }   
        assert!(backtrace.contains("main"), true);
        assert!(backtrace.contains("fortify_fail"), true);
    }
    
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_remote_unwind() {
        use std::process::Command;
        use libc::c_void;
        use std::ptr;
        use std::thread;
        use std::time::Duration;
        use std::io;
        
        let mut test_callstack_path_buf  = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_callstack_path_buf.push("data/test_callstack_remote");
        let mut child = Command::new(test_callstack_path_buf.to_str().unwrap())
            .spawn()
            .expect("failed to execute child");
            thread::sleep(Duration::from_millis(10));
        unsafe {
            let ret = libc::ptrace(
            libc::PTRACE_ATTACH,
            child.id() as libc::pid_t,
            ptr::null_mut::<c_void>(),
            ptr::null_mut::<c_void>(),
            );
            if ret != 0 {
                panic!("{}", io::Error::last_os_error());
            }
            loop {
                let mut status = 0;
                let ret = libc::waitpid(child.id() as libc::pid_t, &mut status, 0);
                if ret < 0 {
                    panic!("{}", io::Error::last_os_error());
                }
                if libc::WIFSTOPPED(status) {
                    break;
                }
            }
        }
        let state = PtraceState::new(child.id()).unwrap();
        let mut address_space = AddressSpace::new(Accessors::ptrace(), Byteorder::Default).unwrap();
        let mut  cursor = Cursor::ptrace(&mut address_space, &state).unwrap();
        
        let mut backtrace = String::new();
        loop { 
            let  ip = cursor.ip().unwrap();
            let  name = cursor.proc_name().unwrap();
            backtrace.push_str(&format!("0x{:x} in {:?} ()\n", ip, name));
            let  ret = cursor.step().unwrap();
            if ret == false  {
                break;
            }
        }   
        assert!(backtrace.contains("main"), true);
        assert!(backtrace.contains("first"), true);
        assert!(backtrace.contains("second"), true);
        assert!(backtrace.contains("third"), true);
        child.kill().unwrap();
    }
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_local_unwind() {
        let backtrace = Cursor::local(|mut cursor| {

        let mut backtrace = String::new();
            loop { 
                let  ip = cursor.ip().unwrap();
                let  name = cursor.proc_name().unwrap();
                backtrace.push_str(&format!("0x{:x} in {:?} ()\n", ip, name));
                let  ret = cursor.step().unwrap();
                if ret == false  {
                    break;
                }
            }
        Ok(backtrace)
        }).unwrap();
        
        assert!(backtrace.contains("__rust_maybe_catch_panic"), true);
        assert!(backtrace.contains("start_thread"), true);
    }
}
