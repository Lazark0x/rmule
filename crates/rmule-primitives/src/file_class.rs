//! The **eD2k File Class** — the network's seven-way file taxonomy, derived
//! from a file name's extension (aMule 2.3.3 `ED2KFileTypesMap`,
//! `OtherFunctions.cpp:656-894`) and named by the `ED2KFTSTR_*` wire labels
//! (`src/include/tags/FileTags.h:122-128`).
//!
//! Two vocabularies live here because aMule keeps two:
//!
//! * [`Ed2kFileClass::search_term`] — what goes on the wire in an
//!   `FT_FILETYPE` tag (`GetED2KFileTypeSearchTerm`, `OtherFunctions.cpp:919`).
//!   Archives and CD-images are **published and searched as `"Pro"`** — the
//!   network has no term for them.
//! * [`Ed2kFileClass::internal_term`] — the *Mule-internal label including the
//!   two extra classes (`GetFileTypeByName`, `OtherFunctions.cpp:935`;
//!   `ED2KFTSTR_ARCHIVE`/`ED2KFTSTR_CDIMAGE` are commented "*Mule internal use
//!   only").
//!
//! [`Ed2kFileClass::display_label`] is the third form: the untranslated
//! description aMule's search list actually prints in its *Type* column
//! (`SearchListCtrl.cpp:238` → `GetFiletypeByName` → `GetFiletypeDesc`,
//! `OtherFunctions.cpp:142`). aMule derives that column from the **file name
//! only** — it never consults the row's `FT_FILETYPE` tag.

/// One eD2k file class. The seven `ED2KFT_*` values that classify a name;
/// aMule's `ED2KFT_ANY` (no class) is this type's `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ed2kFileClass {
    /// `ED2KFT_AUDIO` — music and other sound files.
    Audio,
    /// `ED2KFT_VIDEO` — films and clips.
    Video,
    /// `ED2KFT_IMAGE` — still pictures.
    Image,
    /// `ED2KFT_DOCUMENT` — text and office formats.
    Document,
    /// `ED2KFT_PROGRAM` — executables and installers.
    Program,
    /// `ED2KFT_ARCHIVE` — *Mule-internal only: searched and published as
    /// `"Pro"`, because the network has no term for it.
    Archive,
    /// `ED2KFT_CDIMAGE` — *Mule-internal only, also `"Pro"` on the wire.
    CdImage,
}

impl Ed2kFileClass {
    /// Classify a **file name** by its extension, aMule's `GetED2KFileTypeID`
    /// (`OtherFunctions.cpp:902`): lowercase the text after the last `.` and
    /// look it up. A name with no extension — or an unlisted one — is
    /// unclassifiable (`ED2KFT_ANY`).
    ///
    /// aMule reaches the extension through `CPath::GetExt`, which splits on
    /// the last `.` of the last path component; a search result's name is a
    /// bare file name, so the last `.` of the whole string is the same split.
    /// A leading-dot name (`.bashrc`) has no extension in that split and stays
    /// unclassified, matching `wxFileName`.
    #[must_use]
    pub fn from_file_name(name: &str) -> Option<Self> {
        Self::from_name_bytes(name.as_bytes())
    }

    /// [`Ed2kFileClass::from_file_name`] over a name's raw bytes, so a name
    /// that is not valid UTF-8 keeps its class: every listed extension is
    /// ASCII, and the bytes before the last `.` are never decoded.
    #[must_use]
    pub fn from_name_bytes(name: &[u8]) -> Option<Self> {
        let dot = name.iter().rposition(|byte| *byte == b'.')?;
        if dot == 0 {
            return None;
        }
        Self::from_extension(std::str::from_utf8(&name[dot + 1..]).ok()?)
    }

    /// Classify a bare extension (no leading dot, any case).
    #[must_use]
    pub fn from_extension(extension: &str) -> Option<Self> {
        let lowered = extension.to_ascii_lowercase();
        ED2K_FILE_TYPES
            .iter()
            .find(|(known, _)| *known == lowered)
            .map(|(_, class)| *class)
    }

    /// Read a server- or peer-authored `FT_FILETYPE` string back into a class.
    ///
    /// Accepts both vocabularies — the five wire terms and the two internal
    /// ones — because a publisher may be any *Mule. `"Pro"` is inherently
    /// lossy (aMule folds Archive and CD-image into it), so it resolves to
    /// [`Ed2kFileClass::Program`]; the extension is the finer signal and
    /// [`crate::SearchResult::file_class`] prefers it for exactly this reason.
    ///
    /// Matching is ASCII-case-insensitive. aMule compares the term exactly
    /// (`SearchList.cpp:574`); rmule is lenient because the tag is a
    /// counterparty-authored string, and a case difference is not a reason to
    /// throw the classification away.
    #[must_use]
    pub fn from_type_tag(tag: &str) -> Option<Self> {
        let tag = tag.trim();
        Self::ALL
            .into_iter()
            .find(|class| tag.eq_ignore_ascii_case(class.internal_term()))
    }

    /// Every class, in `EED2KFileType` declaration order.
    pub const ALL: [Self; 7] = [
        Self::Audio,
        Self::Video,
        Self::Image,
        Self::Document,
        Self::Program,
        Self::Archive,
        Self::CdImage,
    ];

    /// The `FT_FILETYPE` term for publishing and searching
    /// (`GetED2KFileTypeSearchTerm`): Archive and CD-image ride `"Pro"`.
    #[must_use]
    pub const fn search_term(self) -> &'static str {
        match self {
            Self::Audio => "Audio",
            Self::Video => "Video",
            Self::Image => "Image",
            Self::Document => "Doc",
            Self::Program | Self::Archive | Self::CdImage => "Pro",
        }
    }

    /// The *Mule-internal label (`GetFileTypeByName`), which keeps `"Arc"` and
    /// `"Iso"` distinct from `"Pro"`.
    #[must_use]
    pub const fn internal_term(self) -> &'static str {
        match self {
            Self::Audio => "Audio",
            Self::Video => "Video",
            Self::Image => "Image",
            Self::Document => "Doc",
            Self::Program => "Pro",
            Self::Archive => "Arc",
            Self::CdImage => "Iso",
        }
    }

    /// The untranslated description aMule prints in a *Type* column
    /// (`GetFiletypeDesc`).
    #[must_use]
    pub const fn display_label(self) -> &'static str {
        match self {
            Self::Audio => "Audio",
            Self::Video => "Videos",
            Self::Image => "Pictures",
            Self::Document => "Texts",
            Self::Program => "Programs",
            Self::Archive => "Archives",
            Self::CdImage => "CD-Images",
        }
    }
}

/// aMule 2.3.3's `ED2KFileTypesMap` (`OtherFunctions.cpp:656-894`), verbatim
/// and lowercase, minus the leading dot the C++ map keys carry. Kept as a flat
/// slice rather than a hash map: it is scanned once per rendered row, and the
/// literal order lets a reader diff it against the C++ block.
const ED2K_FILE_TYPES: &[(&str, Ed2kFileClass)] = &[
    // ED2KFT_AUDIO
    ("669", Ed2kFileClass::Audio),
    ("aac", Ed2kFileClass::Audio),
    ("ac3", Ed2kFileClass::Audio),
    ("aif", Ed2kFileClass::Audio),
    ("aifc", Ed2kFileClass::Audio),
    ("aiff", Ed2kFileClass::Audio),
    ("amf", Ed2kFileClass::Audio),
    ("amr", Ed2kFileClass::Audio),
    ("ams", Ed2kFileClass::Audio),
    ("ape", Ed2kFileClass::Audio),
    ("au", Ed2kFileClass::Audio),
    ("aud", Ed2kFileClass::Audio),
    ("audio", Ed2kFileClass::Audio),
    ("cda", Ed2kFileClass::Audio),
    ("dbm", Ed2kFileClass::Audio),
    ("dmf", Ed2kFileClass::Audio),
    ("dsm", Ed2kFileClass::Audio),
    ("dts", Ed2kFileClass::Audio),
    ("far", Ed2kFileClass::Audio),
    ("flac", Ed2kFileClass::Audio),
    ("it", Ed2kFileClass::Audio),
    ("m1a", Ed2kFileClass::Audio),
    ("m2a", Ed2kFileClass::Audio),
    ("m4a", Ed2kFileClass::Audio),
    ("mdl", Ed2kFileClass::Audio),
    ("med", Ed2kFileClass::Audio),
    ("mid", Ed2kFileClass::Audio),
    ("midi", Ed2kFileClass::Audio),
    ("mka", Ed2kFileClass::Audio),
    ("mod", Ed2kFileClass::Audio),
    ("mol", Ed2kFileClass::Audio),
    ("mp1", Ed2kFileClass::Audio),
    ("mp2", Ed2kFileClass::Audio),
    ("mp3", Ed2kFileClass::Audio),
    ("mpa", Ed2kFileClass::Audio),
    ("mpc", Ed2kFileClass::Audio),
    ("mpp", Ed2kFileClass::Audio),
    ("mtm", Ed2kFileClass::Audio),
    ("nst", Ed2kFileClass::Audio),
    ("ogg", Ed2kFileClass::Audio),
    ("okt", Ed2kFileClass::Audio),
    ("psm", Ed2kFileClass::Audio),
    ("ptm", Ed2kFileClass::Audio),
    ("ra", Ed2kFileClass::Audio),
    ("rmi", Ed2kFileClass::Audio),
    ("s3m", Ed2kFileClass::Audio),
    ("snd", Ed2kFileClass::Audio),
    ("stm", Ed2kFileClass::Audio),
    ("ult", Ed2kFileClass::Audio),
    ("umx", Ed2kFileClass::Audio),
    ("wav", Ed2kFileClass::Audio),
    ("wma", Ed2kFileClass::Audio),
    ("wow", Ed2kFileClass::Audio),
    ("xm", Ed2kFileClass::Audio),
    // ED2KFT_VIDEO
    ("3g2", Ed2kFileClass::Video),
    ("3gp", Ed2kFileClass::Video),
    ("3gp2", Ed2kFileClass::Video),
    ("3gpp", Ed2kFileClass::Video),
    ("amv", Ed2kFileClass::Video),
    ("asf", Ed2kFileClass::Video),
    ("avi", Ed2kFileClass::Video),
    ("bik", Ed2kFileClass::Video),
    ("divx", Ed2kFileClass::Video),
    ("dvr-ms", Ed2kFileClass::Video),
    ("flc", Ed2kFileClass::Video),
    ("fli", Ed2kFileClass::Video),
    ("flic", Ed2kFileClass::Video),
    ("flv", Ed2kFileClass::Video),
    ("hdmov", Ed2kFileClass::Video),
    ("ifo", Ed2kFileClass::Video),
    ("m1v", Ed2kFileClass::Video),
    ("m2t", Ed2kFileClass::Video),
    ("m2ts", Ed2kFileClass::Video),
    ("m2v", Ed2kFileClass::Video),
    ("m4b", Ed2kFileClass::Video),
    ("m4v", Ed2kFileClass::Video),
    ("mkv", Ed2kFileClass::Video),
    ("mov", Ed2kFileClass::Video),
    ("movie", Ed2kFileClass::Video),
    ("mp1v", Ed2kFileClass::Video),
    ("mp2v", Ed2kFileClass::Video),
    ("mp4", Ed2kFileClass::Video),
    ("mpe", Ed2kFileClass::Video),
    ("mpeg", Ed2kFileClass::Video),
    ("mpg", Ed2kFileClass::Video),
    ("mps", Ed2kFileClass::Video),
    ("mpv", Ed2kFileClass::Video),
    ("mpv1", Ed2kFileClass::Video),
    ("mpv2", Ed2kFileClass::Video),
    ("ogm", Ed2kFileClass::Video),
    ("ogv", Ed2kFileClass::Video),
    ("pva", Ed2kFileClass::Video),
    ("qt", Ed2kFileClass::Video),
    ("ram", Ed2kFileClass::Video),
    ("ratdvd", Ed2kFileClass::Video),
    ("rm", Ed2kFileClass::Video),
    ("rmm", Ed2kFileClass::Video),
    ("rmvb", Ed2kFileClass::Video),
    ("rv", Ed2kFileClass::Video),
    ("rv9", Ed2kFileClass::Video),
    ("smil", Ed2kFileClass::Video),
    ("smk", Ed2kFileClass::Video),
    ("swf", Ed2kFileClass::Video),
    ("tp", Ed2kFileClass::Video),
    ("ts", Ed2kFileClass::Video),
    ("vid", Ed2kFileClass::Video),
    ("video", Ed2kFileClass::Video),
    ("vivo", Ed2kFileClass::Video),
    ("vob", Ed2kFileClass::Video),
    ("vp6", Ed2kFileClass::Video),
    ("webm", Ed2kFileClass::Video),
    ("wm", Ed2kFileClass::Video),
    ("wmv", Ed2kFileClass::Video),
    ("xvid", Ed2kFileClass::Video),
    // ED2KFT_IMAGE
    ("bmp", Ed2kFileClass::Image),
    ("dcx", Ed2kFileClass::Image),
    ("emf", Ed2kFileClass::Image),
    ("gif", Ed2kFileClass::Image),
    ("ico", Ed2kFileClass::Image),
    ("jfif", Ed2kFileClass::Image),
    ("jpe", Ed2kFileClass::Image),
    ("jpeg", Ed2kFileClass::Image),
    ("jpg", Ed2kFileClass::Image),
    ("pct", Ed2kFileClass::Image),
    ("pcx", Ed2kFileClass::Image),
    ("pic", Ed2kFileClass::Image),
    ("pict", Ed2kFileClass::Image),
    ("png", Ed2kFileClass::Image),
    ("psd", Ed2kFileClass::Image),
    ("psp", Ed2kFileClass::Image),
    ("tga", Ed2kFileClass::Image),
    ("tif", Ed2kFileClass::Image),
    ("tiff", Ed2kFileClass::Image),
    ("wbmp", Ed2kFileClass::Image),
    ("webp", Ed2kFileClass::Image),
    ("wmf", Ed2kFileClass::Image),
    ("wmp", Ed2kFileClass::Image),
    ("xif", Ed2kFileClass::Image),
    ("xpm", Ed2kFileClass::Image),
    // ED2KFT_DOCUMENT
    ("azw", Ed2kFileClass::Document),
    ("chm", Ed2kFileClass::Document),
    ("css", Ed2kFileClass::Document),
    ("diz", Ed2kFileClass::Document),
    ("doc", Ed2kFileClass::Document),
    ("dot", Ed2kFileClass::Document),
    ("epub", Ed2kFileClass::Document),
    ("hlp", Ed2kFileClass::Document),
    ("htm", Ed2kFileClass::Document),
    ("html", Ed2kFileClass::Document),
    ("mobi", Ed2kFileClass::Document),
    ("nfo", Ed2kFileClass::Document),
    ("odp", Ed2kFileClass::Document),
    ("ods", Ed2kFileClass::Document),
    ("odt", Ed2kFileClass::Document),
    ("otp", Ed2kFileClass::Document),
    ("ots", Ed2kFileClass::Document),
    ("ott", Ed2kFileClass::Document),
    ("pdf", Ed2kFileClass::Document),
    ("pps", Ed2kFileClass::Document),
    ("ppt", Ed2kFileClass::Document),
    ("ps", Ed2kFileClass::Document),
    ("rtf", Ed2kFileClass::Document),
    ("stc", Ed2kFileClass::Document),
    ("sti", Ed2kFileClass::Document),
    ("stw", Ed2kFileClass::Document),
    ("sxc", Ed2kFileClass::Document),
    ("sxi", Ed2kFileClass::Document),
    ("sxw", Ed2kFileClass::Document),
    ("text", Ed2kFileClass::Document),
    ("txt", Ed2kFileClass::Document),
    ("wri", Ed2kFileClass::Document),
    ("xls", Ed2kFileClass::Document),
    ("xlt", Ed2kFileClass::Document),
    ("xml", Ed2kFileClass::Document),
    // ED2KFT_PROGRAM
    ("bat", Ed2kFileClass::Program),
    ("cmd", Ed2kFileClass::Program),
    ("com", Ed2kFileClass::Program),
    ("exe", Ed2kFileClass::Program),
    ("hta", Ed2kFileClass::Program),
    ("js", Ed2kFileClass::Program),
    ("jse", Ed2kFileClass::Program),
    ("msc", Ed2kFileClass::Program),
    ("vbe", Ed2kFileClass::Program),
    ("vbs", Ed2kFileClass::Program),
    ("wsf", Ed2kFileClass::Program),
    ("wsh", Ed2kFileClass::Program),
    // ED2KFT_ARCHIVE
    ("7z", Ed2kFileClass::Archive),
    ("ace", Ed2kFileClass::Archive),
    ("alz", Ed2kFileClass::Archive),
    ("arc", Ed2kFileClass::Archive),
    ("arj", Ed2kFileClass::Archive),
    ("bz2", Ed2kFileClass::Archive),
    ("cab", Ed2kFileClass::Archive),
    ("cbr", Ed2kFileClass::Archive),
    ("cbt", Ed2kFileClass::Archive),
    ("cbz", Ed2kFileClass::Archive),
    ("gz", Ed2kFileClass::Archive),
    ("hqx", Ed2kFileClass::Archive),
    ("lha", Ed2kFileClass::Archive),
    ("lzh", Ed2kFileClass::Archive),
    ("msi", Ed2kFileClass::Archive),
    ("pak", Ed2kFileClass::Archive),
    ("par", Ed2kFileClass::Archive),
    ("par2", Ed2kFileClass::Archive),
    ("rar", Ed2kFileClass::Archive),
    ("sea", Ed2kFileClass::Archive),
    ("sit", Ed2kFileClass::Archive),
    ("sitx", Ed2kFileClass::Archive),
    ("tar", Ed2kFileClass::Archive),
    ("tbz2", Ed2kFileClass::Archive),
    ("tgz", Ed2kFileClass::Archive),
    ("uc2", Ed2kFileClass::Archive),
    ("xpi", Ed2kFileClass::Archive),
    ("z", Ed2kFileClass::Archive),
    ("zip", Ed2kFileClass::Archive),
    ("zoo", Ed2kFileClass::Archive),
    // ED2KFT_CDIMAGE
    ("bin", Ed2kFileClass::CdImage),
    ("bwa", Ed2kFileClass::CdImage),
    ("bwi", Ed2kFileClass::CdImage),
    ("bws", Ed2kFileClass::CdImage),
    ("bwt", Ed2kFileClass::CdImage),
    ("ccd", Ed2kFileClass::CdImage),
    ("cue", Ed2kFileClass::CdImage),
    ("dmg", Ed2kFileClass::CdImage),
    ("dmz", Ed2kFileClass::CdImage),
    ("img", Ed2kFileClass::CdImage),
    ("iso", Ed2kFileClass::CdImage),
    ("mdf", Ed2kFileClass::CdImage),
    ("mds", Ed2kFileClass::CdImage),
    ("nrg", Ed2kFileClass::CdImage),
    ("sub", Ed2kFileClass::CdImage),
    ("toast", Ed2kFileClass::CdImage),
];
