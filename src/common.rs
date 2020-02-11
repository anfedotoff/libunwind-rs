//! 'common` module provides basic interface for the libunwind library
use libunwind_sys::*;
use std::fmt; 
use std::ffi::CStr;
use foreign_types::{foreign_type, ForeignType};
use std::path::Path;
use std::ffi::CString;
use std::mem::MaybeUninit;
use libc::{c_void, c_char};
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
    /// Method constructs method constructs new CoredumpState from path to core file.  
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
    pub fn load_file_at_vaddr(&mut self, file_path: &Path, vaddr: u64) {
        unsafe {
            let file_path = CString::new(file_path.to_str().unwrap()).unwrap();
            _UCD_add_backing_file_at_vaddr(&mut *(self as *const _ as  *mut _ ), vaddr, file_path.as_ptr());
        }
    }

}

//TODO Ptrace state. cursor methods local, remote

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
                &mut *(address_space as *const _ as  *mut _),
                state as *const CoredumpState  as *mut c_void,
            );
            if ret == (Error::Succsess as i32) {
                Ok(Cursor(cursor.assume_init()))
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
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
    pub fn register(&mut self, id: i32) -> Result<u64, Error> {
        unsafe {
            let mut value = 0;
            let ret = unw_get_reg(&self.0 as *const _ as *mut _, id, &mut value);
            if ret == (Error::Succsess as i32) {
                Ok(value)
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }
    
    /// Method returns instructions pointer value 
    pub fn ip(&mut self) ->  Result<u64, Error> {
        unsafe {
            let mut value = 0;
            let ret = unw_get_reg(&self.0 as *const _ as *mut _, libunwind_sys::UNW_TDEP_IP as i32, &mut value);
            if ret == (Error::Succsess as i32) {
                Ok(value)
            } else {
                Err(FromPrimitive::from_i32(ret).unwrap())
            }
        }
    }
    
    /// Method returns stack pointer value 
    pub fn sp(&mut self) ->  Result<u64, Error> {
        unsafe {
            let mut value = 0;
            let ret = unw_get_reg(&self.0 as *const _ as *mut _, libunwind_sys::UNW_TDEP_SP as i32, &mut value);
            if ret == (Error::Succsess as i32) {
                Ok(value)
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
                Ok(String::from_utf8_lossy(&name_vec).into_owned())
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
        let test_callstack_start:u64 = 0x400000;
        let libc_start:u64 = 0x00007f9ac7468000;
   
        let mut  state = CoredumpState::new(&core_path_buf).unwrap();
        state.load_file_at_vaddr(&test_callstack_path_buf, test_callstack_start);
        state.load_file_at_vaddr(&libc_path_buf, libc_start);
        let mut address_space = AddressSpace::new(Accessors::coredump(), Byteorder::Default).unwrap();
        let cursor = Cursor::coredump(&mut address_space, &state).unwrap();
         /* unsafe {
              let asp = unw_create_addr_space(&mut _UCD_accessors ,0);
              let ui: * mut UCD_info = _UCD_create(core_path.as_ptr());
              let mut c  = MaybeUninit::uninit();
>>            let mut ret = unw_init_remote(c.as_mut_ptr(),asp,ui as * mut libc::c_void );
              _UCD_add_backing_file_at_vaddr(ui, test_callstack_start, test_callstack_path.as_ptr());
  
              _UCD_add_backing_file_at_vaddr(ui, libc_start, libc_path.as_ptr());
             let mut ip: unw_word_t = 0;
             let mut backtrace = String::new();
             loop {
                unw_get_reg(c.as_mut_ptr(), UNW_TDEP_IP as ::std::os::raw::c_int, &mut ip);
                let mut off  = MaybeUninit::uninit();
                let mut name_vec:Vec<c_char> = vec![0;64];
                unw_get_proc_name(c.as_mut_ptr(), name_vec.as_mut_ptr(),64, off.as_mut_ptr());
                let name = CStr::from_ptr(name_vec.as_mut_ptr());
                backtrace.push_str(&format!("0x{:x} in {:?} ()\n", ip, name.to_str().unwrap()));
                ret = unw_step(c.as_mut_ptr());
                if ret <= 0 {
                    break;
                }
             }
             assert!(backtrace.contains("main"), true);
             assert!(backtrace.contains("first"), true);
             assert!(backtrace.contains("second"), true);
             assert!(backtrace.contains("third"), true);
          }*/
    }

}

