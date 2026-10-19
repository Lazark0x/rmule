//! The macOS **Default app lookup** through LaunchServices: the extension
//! read as a type (`UTTypeCreatePreferredIdentifierForTag`), the type's
//! default app for any role (`LSCopyDefaultApplicationURLForContentType`),
//! and that app's path. No crate in the graph declares the two CoreServices
//! calls, so each waived function that makes one declares it; the Core
//! Foundation calls around them are `core-foundation-sys`'s. Both lookups
//! are deprecated since macOS 12 in favour of Objective-C APIs, and both
//! still answer.

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::{self, NonNull};

use core_foundation_sys::base::{CFIndex, CFRelease, CFTypeRef};
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::{CFStringCreateWithBytes, CFStringRef, kCFStringEncodingUTF8};
use core_foundation_sys::url::{CFURLGetFileSystemRepresentation, CFURLRef};

/// The tag class of a file-name extension: `kUTTagClassFilenameExtension`'s
/// value, built here rather than read from the framework's global.
const FILENAME_EXTENSION: &str = "public.filename-extension";

/// `kLSRolesAll`: the default app for any role, the one a double-click
/// opens with.
const ALL_ROLES: u32 = 0xFFFF_FFFF;

/// The longest path `CFURLGetFileSystemRepresentation` is given room for,
/// with its terminating NUL.
const PATH_MAX: usize = libc::PATH_MAX as usize;

/// The bundle LaunchServices opens files with `extension` with, if any.
pub(super) fn for_extension(extension: &str) -> io::Result<Option<PathBuf>> {
    let tag_class = cf_string(FILENAME_EXTENSION)?;
    let tag = cf_string(extension)?;
    let Some(content_type) = content_type(&tag_class, &tag) else {
        return Ok(None);
    };
    let Some(app) = default_app(&content_type) else {
        return Ok(None);
    };
    file_path(&app).map(Some)
}

/// A Core Foundation object this module holds one reference to, by the
/// create or copy rule, released once on drop. Only this module's waived
/// functions make one, each from the reference its call just returned.
struct Owned(NonNull<c_void>);

impl Owned {
    /// Hold `object`, a reference a create or copy call returned; `None` for
    /// the null such a call answers when it has nothing.
    fn hold(object: CFTypeRef) -> Option<Self> {
        NonNull::new(object.cast_mut()).map(Self)
    }

    /// The object, for a call that borrows it.
    fn get<T>(&self) -> *const T {
        self.0.as_ptr().cast_const().cast()
    }
}

impl Drop for Owned {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: the reference is one this value holds by the create or copy
        // rule, released here once; nothing reads the object after.
        unsafe { CFRelease(self.get()) }
    }
}

/// `text` as a `CFString`.
#[allow(unsafe_code)]
fn cf_string(text: &str) -> io::Result<Owned> {
    let length =
        CFIndex::try_from(text.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `text` is borrowed for the call and `length` is its length in
    // bytes, valid UTF-8 as the encoding says; Core Foundation copies the
    // bytes and keeps no pointer to them. A null allocator is the default.
    let string = unsafe {
        CFStringCreateWithBytes(ptr::null(), text.as_ptr(), length, kCFStringEncodingUTF8, 0)
    };
    Owned::hold(string.cast()).ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))
}

/// The type `tag` names in `tag_class`; an extension no app declares still
/// gets a dynamic type, which no app opens.
#[allow(unsafe_code)]
fn content_type(tag_class: &Owned, tag: &Owned) -> Option<Owned> {
    #[link(name = "CoreServices", kind = "framework")]
    // SAFETY: the declaration is `UTTypeCreatePreferredIdentifierForTag` as
    // CoreServices' `UTType.h` gives it: three `CFStringRef`s in, a
    // `CFStringRef` out by the create rule, or null.
    unsafe extern "C" {
        fn UTTypeCreatePreferredIdentifierForTag(
            tag_class: CFStringRef,
            tag: CFStringRef,
            conforming_to: CFStringRef,
        ) -> CFStringRef;
    }
    let (class, tag) = (tag_class.get(), tag.get());
    // SAFETY: both strings are live `CFString`s, borrowed for the call; a null
    // conforming-to type asks for any. The result is held by `Owned`.
    let found = unsafe { UTTypeCreatePreferredIdentifierForTag(class, tag, ptr::null()) };
    Owned::hold(found.cast())
}

/// The URL of the app LaunchServices opens `content_type` with, for any role.
#[allow(unsafe_code)]
fn default_app(content_type: &Owned) -> Option<Owned> {
    #[link(name = "CoreServices", kind = "framework")]
    // SAFETY: the declaration is `LSCopyDefaultApplicationURLForContentType`
    // as CoreServices' `LSInfo.h` gives it: a `CFStringRef`, an `LSRolesMask`
    // (a `UInt32`) and a `CFErrorRef *` in, a `CFURLRef` out by the copy rule,
    // or null.
    unsafe extern "C" {
        fn LSCopyDefaultApplicationURLForContentType(
            content_type: CFStringRef,
            roles: u32,
            error: *mut CFErrorRef,
        ) -> CFURLRef;
    }
    // SAFETY: `content_type` is a live `CFString`, borrowed for the call; a
    // null error pointer asks for no error object. The URL is held by `Owned`.
    let app = unsafe {
        LSCopyDefaultApplicationURLForContentType(content_type.get(), ALL_ROLES, ptr::null_mut())
    };
    Owned::hold(app.cast())
}

/// The path of the file URL `url`.
#[allow(unsafe_code)]
fn file_path(url: &Owned) -> io::Result<PathBuf> {
    let mut buffer = [0_u8; PATH_MAX];
    let room = CFIndex::try_from(buffer.len())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let out = buffer.as_mut_ptr();
    // SAFETY: `url` is a live `CFURL`, borrowed for the call. `out` points at
    // `buffer`, which lives on this frame, and `room` is its length, past which
    // the call never writes; it keeps no pointer to it.
    let written = unsafe { CFURLGetFileSystemRepresentation(url.get(), 1, out, room) };
    if written == 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    Ok(PathBuf::from(OsStr::from_bytes(&buffer[..end])))
}
