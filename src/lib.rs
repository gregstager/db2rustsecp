/**********************************************************************
** (c) Copyright IBM Corp. 2007 All rights reserved.
** 
** The following sample of source code ("Sample") is owned by International 
** Business Machines Corporation or one of its subsidiaries ("IBM") and is 
** copyrighted and licensed, not sold. You may use, copy, modify, and 
** distribute the Sample in any form without payment to IBM, for the purpose of 
** assisting you in the development of your applications.
** 
** The Sample code is provided to you on an "AS IS" basis, without warranty of 
** any kind. IBM HEREBY EXPRESSLY DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR 
** IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Some jurisdictions do 
** not allow for the exclusion or limitation of implied warranties, so the above 
** limitations or exclusions may not apply to you. IBM shall not be liable for 
** any damages you suffer as a result of using, copying, modifying or 
** distributing the Sample, even if IBM has been advised of the possibility of 
** such damages.
***********************************************************************/

// In numerous cases, we are following the naming conventions as set out
// in db2secPlugin.h that we are being compatible with.
// Those C definitions do not follow Rust conventions.
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

#![allow(unused_variables)]
#![allow(dead_code)]

use std::collections::HashMap;
use std::os::raw::{c_int,c_char,c_void};
use std::ffi::{CString,CStr};
use bitflags::bitflags;


// Type corresponding to SQL_API_RC
type SQL_API_RC = c_int;

#[allow(non_camel_case_types)]
enum Db2LogLevels {
    DB2SEC_LOG_NONE     = 0,
    DB2SEC_LOG_CRITICAL = 1,
    DB2SEC_LOG_ERROR    = 2,
    DB2SEC_LOG_WARNING  = 3,
    DB2SEC_LOG_INFO     = 4,
}

const DB2SEC_USERID_PASSWORD_SERVER_AUTH_FUNCTIONS_VERSION_1 : i32 = 1;

const DB2SEC_MAX_AUTHID_LENGTH           : i32 = 255;
const DB2SEC_MAX_USERID_LENGTH           : i32 = 255;
const DB2SEC_MAX_USERNAMESPACE_LENGTH    : i32 = 255;
const DB2SEC_MAX_PASSWORD_LENGTH         : i32 = 255;
const DB2SEC_MAX_PRINCIPAL_NAME_LENGTH   : i32 = 255;
const DB2SEC_MAX_DBNAME_LENGTH           : i32 = 128;

const DB2SEC_USER_NAMESPACE_UNDEFINED    : i32 = 0;
const DB2SEC_NAMESPACE_SAM_COMPATIBLE    : i32 = 1;
const DB2SEC_NAMESPACE_USER_PRINCIPAL    : i32 = 2;

const DB2SEC_PLUGIN_TYPE_USERID_PASSWORD : i32 = 0;
const DB2SEC_PLUGIN_TYPE_GSSAPI          : i32 = 1;
const DB2SEC_PLUGIN_TYPE_KERBEROS        : i32 = 2;
const DB2SEC_PLUGIN_TYPE_GROUP           : i32 = 3;

const DB2SEC_ID_TYPE_AUTHID              : i32 = 0;


bitflags! {
    #[repr(C)]
    struct ConnectionFlags: u32
    {
       const DB2SEC_USERID_FROM_OS            = 0x0000_0001;
       const DB2SEC_CONNECTION_ISLOCAL        = 0x0000_0002;
       const DB2SEC_VALIDATING_ON_SERVER_SIDE = 0x0000_0004;
    }
}

#[repr(i32)]
#[allow(non_camel_case_types)]
enum Db2rc {
    DB2SEC_PLUGIN_OK = 0,
    DB2SEC_PLUGIN_UNKNOWNERROR = -1,
    DB2SEC_PLUGIN_BADUSER = -2,
    DB2SEC_PLUGIN_INVALIDUSERORGROUP = -3,
    DB2SEC_PLUGIN_USERSTATUSNOTKNOWN = -4,
    DB2SEC_PLUGIN_GROUPSTATUSNOTKNOWN = -5,
    DB2SEC_PLUGIN_UID_EXPIRED  = -6,
    DB2SEC_PLUGIN_PWD_EXPIRED = -7,
    DB2SEC_PLUGIN_USER_REVOKED = -8,
    DB2SEC_PLUGIN_USER_SUSPENDED = -9,
    DB2SEC_PLUGIN_BADPWD = -10,
    DB2SEC_PLUGIN_BAD_NEWPASSWORD = -11,
    DB2SEC_PLUGIN_CHANGEPASSWORD_NOTSUPPORTED = -12,
    DB2SEC_PLUGIN_NOMEM = -13,
    DB2SEC_PLUGIN_DISKERROR = -14,
    DB2SEC_PLUGIN_NOPERM = -15,
    DB2SEC_PLUGIN_NETWORKERROR = -16,
    DB2SEC_PLUGIN_CANTLOADLIBRARY = -17,
    DB2SEC_PLUGIN_CANT_OPEN_FILE = -18,
    DB2SEC_PLUGIN_FILENOTFOUND = -19,
    DB2SEC_PLUGIN_CONNECTION_DISALLOWED = -20,
    DB2SEC_PLUGIN_NO_CRED = -21,
    DB2SEC_PLUGIN_CRED_EXPIRED = -22,
    DB2SEC_PLUGIN_BAD_PRINCIPAL_NAME = -23,

    // These two error messages should not be returned to Db2.
    // They are returned in the logMessage and getConDetails callbacks
    // to this plugin.
    DB2SEC_PLUGIN_NO_CON_DETAILS = -24,
    DB2SEC_PLUGIN_BAD_INPUT_PARAMETERS = -25,

    DB2SEC_PLUGIN_INCOMPATIBLE_VER = -26,
    DB2SEC_PLUGIN_PROCESS_LIMIT = -27,
    DB2SEC_PLUGIN_NO_LICENSES = -28,
    DB2SEC_PLUGIN_ROOT_NEEDED = -29,
    DB2SEC_PLUGIN_UNEXPECTED_SYSTEM_ERROR = -30,
    DB2SEC_PLUGIN_AUTH_SYSERR = -31,
}


// Global variables set during init.
// These are callback into the Db2 engine.
// TODO: Implement as singleton
static mut DB2_GET_CON_DETAILS_CB : Option<GetConDetailsFuncT> = None;
static mut DB2_LOG_MESSAGE_CB : Option<LogMessageFuncT> = None;
static mut DB2_USERPW_MAP : Option<HashMap<String, String> > = None;


//-----------------------------------------------------------------------------
// Function Pointer types for the various API calls and callbacks.

type CValidatePasswordFuncT = extern "C" fn (
    userid : * const c_char,
    useridlen: i32,
    usernamespace : * const c_char,
    usernamespacelen : i32,
    usernamespacetype : i32,
    password : * const c_char,
    passwordlen : i32,
    newpasswd : * const c_char,
    newpasswdlen : i32,
    dbname : * const c_char,
    dbnamelen : i32,
    connection_details : u32,
    token : * mut * mut c_void,
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC;

type CGetAuthIDsFuncT = extern "C" fn (
    userid : * const c_char,
    useridlen: i32,
    usernamespace : * const c_char,
    usernamespacelen : i32,
    usernamespacetype : i32,
    dbname : * const c_char,
    dbnamelen : i32,
    token : * mut * mut c_void,
    SystemAuthID : * mut c_char,
    SystemAuthIDlen : * mut i32,
    InitialSessionAuthID : * mut c_char,
    InitialSessionAuthIDlen : * mut i32,
    username : * mut c_char,
    usernamelen : * mut i32,
    initsessionidtype : * mut i32,
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC;

type CDoesAuthIDExistFuncT = extern "C" fn (
    authid : * const c_char,
    authidlen : i32,
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC;

type CFreeTokenFuncT = extern fn (
    token : * mut c_void,
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC;

type CFreeErrormsgFuncT = extern "C" fn (
  errormsg : * mut c_char,
) -> SQL_API_RC;

type CServerAuthPluginTermFuncT = extern "C" fn (
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC;

type GetConDetailsFuncT = extern "C" fn (
   conDetailsVersion : i32,
   pConDetails : * mut c_void,
) -> SQL_API_RC;

type LogMessageFuncT = extern "C" fn (
   level : i32,
   data : * const c_char, // should be c_void
   length : i32,
) -> SQL_API_RC;


//-----------------------------------------------------------------------------
// Structures

#[repr(C)]
pub struct db2sec_con_details_3 {
    pub clientProtocol : i32,
    pub clientIPAddress : u32,
    pub connect_info_bitmap : u32,
    pub dbnameLen : i32,
    pub dbname : [c_char; DB2SEC_MAX_DBNAME_LENGTH as usize],
    pub clientIP6Address : [u32;4],
    pub clientPlatform : u32,
    pub reserved: [u32;16],
}

// Option used as nullable function pointer
#[repr(C)]
pub struct db2secUseridPasswordServerAuthFunctions_1 {
    version : i32,
    plugintype : i32,
    db2secValidatePassword     : Option<CValidatePasswordFuncT>,
    db2secGetAuthIDs           : Option<CGetAuthIDsFuncT>,
    db2secDoesAuthIDExist      : Option<CDoesAuthIDExistFuncT>,
    db2secFreeToken            : Option<CFreeTokenFuncT>,
    db2secFreeErrormsg         : Option<CFreeErrormsgFuncT>,
    db2secServerAuthPluginTerm : Option<CServerAuthPluginTermFuncT>,
}


// This structure will be used as the token between Db2 calls.
struct TokenBetweenDb2Calls {
    firstVal : i32,
    secondVal : i16,
    authid : String,
}

//-----------------------------------------------------------------------------
// API functions

extern "C" fn ValidatePassword
(
    userid : * const c_char,
    useridlen: i32,
    usernamespace : * const c_char,
    usernamespacelen : i32,
    usernamespacetype : i32,
    password : * const c_char,
    passwordlen : i32,
    newpasswd : * const c_char,
    newpasswdlen : i32,
    dbname : * const c_char,
    dbnamelen : i32,
    connection_details : u32,
    token : * mut * mut c_void,
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC {
    if ! newpasswd.is_null() {
        return Db2rc::DB2SEC_PLUGIN_CHANGEPASSWORD_NOTSUPPORTED as SQL_API_RC;
    }

    let optUserid = match ConvertToOptionalString( userid,
                                                   useridlen,
                                                   "ValidatePassword",
                                                   "userid",
                                                   errormsg, errormsglen ) {
        Ok(o) => o,
        Err(e) => {return e as SQL_API_RC;}
    };

    // Userid is mandatory.
    let localUserid = match optUserid {
        None => {return Db2rc::DB2SEC_PLUGIN_BADUSER as SQL_API_RC},
        Some(s) => s
    };

    let optUserNamespace = match ConvertToOptionalString( usernamespace,
                                                          usernamespacelen,
                                                          "ValidatePassword",
                                                          "usernamespace",
                                                          errormsg, errormsglen ) {
        Ok(o) => o,
        Err(e) => {return e as SQL_API_RC;}
    };

    let optPassword = match ConvertToOptionalString( password,
                                                     passwordlen,
                                                     "ValidatePassword",
                                                     "password",
                                                     errormsg, errormsglen ) {
        Ok(o) => o,
        Err(e) => {return e as SQL_API_RC;}
    };

    let optDbname = match ConvertToOptionalString( dbname,
                                                   dbnamelen,
                                                   "ValidatePassword",
                                                   "dbname",
                                                   errormsg, errormsglen ) {
        Ok(o) => o,
        Err(e) => {return e as SQL_API_RC;}
    };

    let connDetails : ConnectionFlags = ConnectionFlags::from_bits_truncate( connection_details );


    #[cfg(debug_assertions)]
    LogMessageToDb2Diag( Db2LogLevels::DB2SEC_LOG_ERROR,
                             &format!("ValidatePassword: Local connect: {:?}", connDetails ) );

    if let Some(pw) = optPassword {

        // This code is safe because DB2_USERPW_MAP is only allocated and written to
        // during db2secServerAuthPluginInit which is single threaded at that time.
        // Once we are in a multi-threaded env, this is read only.
        unsafe {
            let pwMap = match &DB2_USERPW_MAP {
                None => {return Db2rc::DB2SEC_PLUGIN_BADUSER as SQL_API_RC;}
                Some(lpw) => lpw
            };
       
            match pwMap.get( &localUserid ) {
                None => {
                    AllocateDb2ErrorMessage( "ValidatePassword",
                                            &format!("The password is bad for user: {}", &localUserid ),
                                            errormsg, errormsglen);
                    return Db2rc::DB2SEC_PLUGIN_BADUSER as SQL_API_RC;
                },
                Some(lpw) => {
                    if lpw.ne(&pw) {
                        AllocateDb2ErrorMessage( "ValidatePassword",
                                        "The password is bad for the user",
                                        errormsg, errormsglen);
                        return Db2rc::DB2SEC_PLUGIN_BADPWD as SQL_API_RC;
                    }
                }
            }
        }

        // If we get here, the password is valid
    }
    else {
         /* No password was supplied.  This is okay as long
         * as the following conditions are true:
         *
         *  - The username came from WhoAmI(), and
         *  - If we're on the server side, the connection must
         *    be "local" (originating from the same machine)
         *
         * Note that "DB2SEC_USERID_FROM_OS" means that the userid
         * was obtained from the plugin by calling the function
         * supplied for "db2secGetDefaultLoginContext".
         */

        if ! connDetails.contains( ConnectionFlags::DB2SEC_USERID_FROM_OS |
                                   ConnectionFlags::DB2SEC_CONNECTION_ISLOCAL |
                                   ConnectionFlags::DB2SEC_VALIDATING_ON_SERVER_SIDE ) {
            return Db2rc::DB2SEC_PLUGIN_UNKNOWNERROR as SQL_API_RC;
        }
    }

    // Create an token to pass between calls.
    // firstVal and secondVal are just demo values and not really used.
    let rust_object = Box::new(TokenBetweenDb2Calls { firstVal: 5,
                                                      secondVal: 6,
                                                      authid : localUserid.to_uppercase() });

    unsafe {
        // This transfers ownership of rust_object into the raw pointer token.
        // This is then given back to Db2 to own/manage the memory.
        // Db2 will call FreeToken to deallocate the heap memory.
        *token = Box::into_raw( rust_object ) as * mut c_void;
    }

    Db2rc::DB2SEC_PLUGIN_OK as SQL_API_RC
}

// Note regarding the SystemAuthID ,InitialSessionAuthID and username parameters.
// In db2secPlugin.h these are defined as:
//    char        SystemAuthID[DB2SEC_MAX_AUTHID_LENGTH],
//    char        InitialSessionAuthID[DB2SEC_MAX_AUTHID_LENGTH],
// The equivalent rust definition is:
//    SystemAuthID : & mut [c_char;255],
//    InitialSessionAuthID : & mut [c_char;255],
// However that results in the following warning:
//     warning: `extern` fn uses type `[i8; 255]`, which is not FFI-safe
//        --> src/lib.rs:205:16
//         |
//     205 |     username : [c_char;255],
//         |                ^^^^^^^^^^^^ not FFI-safe
//         |
//         = note: `#[warn(improper_ctypes_definitions)]` on by default
//         = help: consider passing a pointer to the array
//         = note: passing raw arrays by value is not FFI-safe
// The warning can be disabled with the following:
// #[allow(improper_ctypes_definitions)]
//
// Instead we will rely on C's equivalency of arrays and pointers to
// define the arguments like the following.  We just won't have the compiler
// to check the lengths for us, we will need to do that ourselves.
//    SystemAuthID : * mut c_char,
//    InitialSessionAuthID : * mut c_char,

extern fn GetAuthIDs
(
    userid : * const c_char,
    useridlen: i32,
    usernamespace : * const c_char,
    usernamespacelen : i32,
    usernamespacetype : i32,
    dbname : * const c_char,
    dbnamelen : i32,
    token : * mut * mut c_void,
    SystemAuthID : * mut c_char,
    SystemAuthIDlen : * mut i32,
    InitialSessionAuthID : * mut c_char,
    InitialSessionAuthIDlen : * mut i32,
    username : * mut c_char,
    usernamelen : * mut i32,
    initsessionidtype : * mut i32,
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC {
    #[cfg(debug_assertions)]
    LogMessageToDb2Diag( Db2LogLevels::DB2SEC_LOG_WARNING,
                         "Entering GetAuthIDs" );

    unsafe {
        // A token is necessary, it should have been allocated in ValidatePassword.
        if token.is_null() || (*token).is_null() {
            return Db2rc::DB2SEC_PLUGIN_UNKNOWNERROR as SQL_API_RC;
        }

        // We will use the authid that was setup for us during
        // ValidatePassword.  We could just grab the username here, but
        // it's an oppourtunity to show token passing.

        // We don't want to take owership of token, just use it
        // as a read only variable
        let pToken = *token as * const TokenBetweenDb2Calls;

        let authid : & String = &(*pToken).authid;


        std::ptr::copy( authid.as_ptr(),
                        SystemAuthID as *mut u8,
                        authid.len() );

        *SystemAuthIDlen = authid.len() as i32;

        std::ptr::copy( authid.as_ptr(),
                        InitialSessionAuthID as *mut u8,
                        authid.len() );

        *InitialSessionAuthIDlen = authid.len() as i32;

        *initsessionidtype = DB2SEC_ID_TYPE_AUTHID;
    }

    Db2rc::DB2SEC_PLUGIN_OK as SQL_API_RC
}

extern fn DoesAuthIDExist
(
    authid : * const c_char,
    authidlen : i32,
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC {

    let optAuthid = match ConvertToOptionalString( authid,
                                                   authidlen,
                                                   "DoesAuthIdExist",
                                                   "authid",
                                                   errormsg, errormsglen ) {
        Ok(o) => o,
        Err(e) => {return e as SQL_API_RC;}
    };

    // Userid is mandatory.
    let localAuthid = match optAuthid {
        None => {return Db2rc::DB2SEC_PLUGIN_BADUSER as SQL_API_RC},
        Some(s) => s
    };

    // This code is safe because DB2_USERPW_MAP is only allocated and written to
    // during db2secServerAuthPluginInit which is single threaded at that time.
    // Once we are in a multi-threaded env, this is read only.
    unsafe {
        let pwMap = match &DB2_USERPW_MAP {
            None => {return Db2rc::DB2SEC_PLUGIN_UNKNOWNERROR as SQL_API_RC;}
            Some(lpw) => lpw
        };
    
        match pwMap.get( &localAuthid.to_lowercase() ) {
            None => { 
                #[cfg(debug_assertions)]
                LogMessageToDb2Diag( Db2LogLevels::DB2SEC_LOG_WARNING,
                     &format!("DoesAuthidExist: authid not found: {:?}", localAuthid ) );
                Db2rc::DB2SEC_PLUGIN_INVALIDUSERORGROUP as SQL_API_RC
            },
            Some(s) => { Db2rc::DB2SEC_PLUGIN_OK as SQL_API_RC }
        }
    }
}

extern fn FreeToken
(
    token : * mut c_void,
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC {
    // Simply taking ownership of the pointer will call destructors
    // at the end of this function.
    let boxToFree = unsafe { Box::from_raw( token as * mut TokenBetweenDb2Calls) };

    Db2rc::DB2SEC_PLUGIN_OK as SQL_API_RC
}


extern fn FreeErrorMsg
(
  errormsg : * mut c_char,
) -> SQL_API_RC {
    // Any error messages should have been allocated from
    // AllocateDb2ErrorMessage.
    // It used CString::into_raw to pass ownership to Db2.
    // We are taking it back, and memory will be freed when this
    // function ends
    let msgToFree = unsafe { CString::from_raw( errormsg ) };

    // TODO: Remove this block
    if let Ok(newstring) = msgToFree.into_string() {
        #[cfg(debug_assertions)]
        LogMessageToDb2Diag( Db2LogLevels::DB2SEC_LOG_WARNING,
                             &format!( "Freeing this string: {}", newstring ) );
    }

    Db2rc::DB2SEC_PLUGIN_OK as SQL_API_RC
}

extern fn ServerAuthPluginTerm
(
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32
) -> SQL_API_RC
{
    unsafe {
        DB2_GET_CON_DETAILS_CB = None;
        DB2_LOG_MESSAGE_CB = None;
    }

    Db2rc::DB2SEC_PLUGIN_OK as SQL_API_RC
}



#[no_mangle]
pub extern "C" fn db2secServerAuthPluginInit(
    version : i32,
    server_fns : * mut c_void,
    getConDetails_fn : Option<GetConDetailsFuncT>,
    logMessage_fn : Option<LogMessageFuncT>,
    errormsg : * mut * mut c_char,
    errormsglen : * mut i32,
) -> SQL_API_RC {
    // Unrecoverable error if we don't get a logging function.
    match logMessage_fn {
        Some(f) => {unsafe {DB2_LOG_MESSAGE_CB = Some(f);}},
        None =>
        {
            return Db2rc::DB2SEC_PLUGIN_UNKNOWNERROR as SQL_API_RC;
        }
    }

    // At this point we appear to have a valid logging function, so can make use of it.
    LogMessageToDb2Diag( Db2LogLevels::DB2SEC_LOG_WARNING,
                         "RUST based security u/pw plugin is being initialized" );

    // Ensure we have valid pointers, that the are not null.
    if server_fns.is_null() ||
       errormsg.is_null() ||
       errormsglen.is_null() {
        // These pointers should never be null.
        return Db2rc::DB2SEC_PLUGIN_UNKNOWNERROR as SQL_API_RC;
    }

    // Ensure we have a valid getConDetails callback.
    match getConDetails_fn {
        Some(f) => {unsafe {DB2_GET_CON_DETAILS_CB = Some(f);}},
        None =>
        {
            return Db2rc::DB2SEC_PLUGIN_UNKNOWNERROR as SQL_API_RC;
        }
    }

    // Ensure we are given a valid version of the functions.
    // We require at least version 1 of the APIs.
    // Should never have version 0, but we will check.
    if version < DB2SEC_USERID_PASSWORD_SERVER_AUTH_FUNCTIONS_VERSION_1 {
        AllocateDb2ErrorMessage( "db2secServerAuthPluginInit",
                                 "Invalidate function version",
                                 errormsg, errormsglen );

        return Db2rc::DB2SEC_PLUGIN_INCOMPATIBLE_VER as SQL_API_RC;
    }

    // All of the input looks good.  We can now start doing things.
    // If there is any one time initialization, now is the time to do it.

    unsafe {
        // Setup a global map of userid/password.
        // Obviously you wouldn't do this for a real system, this is just a demo.
        let mut pwMap = HashMap::new();

        pwMap.insert(String::from("gstager"), String::from("temp4Now") );
        pwMap.insert(String::from("newton"), String::from("newtonpw") );
        pwMap.insert(String::from("zurbie"), String::from("zurbiepw") );

        DB2_USERPW_MAP = Some( pwMap );
    }

    // Cast the void * parameter to the function structure.
    let serverFns : &mut db2secUseridPasswordServerAuthFunctions_1 =
           unsafe { &mut *(server_fns as *mut db2secUseridPasswordServerAuthFunctions_1) };

    serverFns.version                    = DB2SEC_USERID_PASSWORD_SERVER_AUTH_FUNCTIONS_VERSION_1;
    serverFns.plugintype                 = DB2SEC_PLUGIN_TYPE_USERID_PASSWORD;
    serverFns.db2secValidatePassword     = Some( ValidatePassword );
    serverFns.db2secGetAuthIDs           = Some( GetAuthIDs );
    serverFns.db2secDoesAuthIDExist      = Some( DoesAuthIDExist );
    serverFns.db2secFreeToken            = Some( FreeToken );
    serverFns.db2secFreeErrormsg         = Some( FreeErrorMsg );
    serverFns.db2secServerAuthPluginTerm = Some( ServerAuthPluginTerm );

    Db2rc::DB2SEC_PLUGIN_OK as SQL_API_RC
}


//-----------------------------------------------------------------------------
// Helper function to log messages to the db2diag.log
fn LogMessageToDb2Diag( level : Db2LogLevels, msg : &str  ) {
    unsafe {
        if let Some(logcb) = DB2_LOG_MESSAGE_CB {
            logcb( level as i32, msg.as_ptr() as * const c_char , msg.len() as i32 );
        }
    }
}

//-----------------------------------------------------------------------------
// Helper function to allocate memory for error messages
fn AllocateDb2ErrorMessage( caller : &str,
                            message : &str,
                            errormsg : * mut * mut c_char,
                            errormsglen : * mut i32 ) {
    if errormsg.is_null() || errormsglen.is_null() {
        return;
    }

    let msg = format!("RUSTSECP Error from function {}: {}", caller, message);

    if let Ok(cmsg) = CString::new(msg) {
        unsafe {
            *errormsglen = cmsg.as_bytes().len() as i32;
            *errormsg = cmsg.into_raw();
        }
    }

    // For now, we are not handling allocation errors from new()
}


fn ConvertToOptionalString( cstring : * const c_char,
                            cstringlen : i32,
                            caller : &str,
                            field  : &str,
                            errormsg : * mut * mut c_char,
                            errormsglen : * mut i32 )
   -> Result< Option<String>, Db2rc> {
    // It's OK for the string to be null.  Just return none option.
    if cstring.is_null() || cstringlen == 0 {
        #[cfg(debug_assertions)]
        LogMessageToDb2Diag( Db2LogLevels::DB2SEC_LOG_WARNING,
                             &format!("ToString: from {}, field {} is null", caller, field) );

        return Ok( None );
    }

    let slice = unsafe { CStr::from_ptr( cstring ) };

    match slice.to_str() {
        Ok(s)  => {
            #[cfg(debug_assertions)]
            LogMessageToDb2Diag( Db2LogLevels::DB2SEC_LOG_WARNING,
                                 &format!("ToString: from {}, field {} is {}", caller, field, s) );

            let mut news = String::from( s );
            news.truncate(cstringlen as usize);

            Ok( Some( news ) )
        },
        Err(e) => {
            AllocateDb2ErrorMessage( caller,
                                     &format!("{} is not utf8. Valid up to {}", field, e.valid_up_to() ),
                                     errormsg, errormsglen);
            Err( Db2rc::DB2SEC_PLUGIN_UNKNOWNERROR )
        }
    }
}

