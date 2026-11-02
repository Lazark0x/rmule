//! The fields of the add and update forms, and what the Search filters ask.

/// The add-server form's title.
pub const ADD_SERVER_TITLE: &str = " Add server ";
/// The list-update form's title.
pub const UPDATE_LIST_TITLE: &str = " Update server list from URL ";
/// What `Enter` does on the list-update form.
pub const FETCH: &str = "fetch";
/// A server's name.
pub const SERVER_NAME: &str = "Name";
/// A server's address.
pub const SERVER_ADDRESS: &str = "Address";
/// What the address takes.
pub const SERVER_ADDRESS_HINT: &str = "IPv4 or hostname";
/// A server's port.
pub const SERVER_PORT: &str = "Port";
/// The list-update form's one field.
pub const LIST_URL: &str = "URL";
/// The add-link form's title.
pub const ADD_LINK_TITLE: &str = " Add eD2k link ";
/// The add-link form's one field.
pub const LINK: &str = "Link";
/// What it takes.
pub const LINK_HINT: &str = "ed2k://|file|name|size|hash|/";
/// The filter form's heading on its closed line.
pub const FILTERS: &str = "Filters: ";
/// What the filters say with none set.
pub const NO_FILTERS: &str = "none";
/// The class selector's first item.
pub const ANY_CLASS: &str = "Any";
/// The file-type filter.
pub const FILTER_TYPE: &str = "Type";
/// The size floor.
pub const MIN_SIZE: &str = "Min size";
/// The size ceiling.
pub const MAX_SIZE: &str = "Max size";
/// What a size filter takes.
pub const SIZE_HINT: &str = "any (e.g. 700 MB)";
/// The sources floor.
pub const MIN_SOURCES: &str = "Min sources";
/// What it takes.
pub const SOURCES_HINT: &str = "any (e.g. 10)";
/// The extension filter.
pub const EXTENSION: &str = "Extension";
/// What it takes.
pub const EXTENSION_HINT: &str = "any (e.g. avi)";

/// A sources floor on the closed filter line.
#[must_use]
pub fn min_sources_summary(sources: &str) -> String {
    format!("≥{sources} src")
}

/// The URL schemes anything here fetches over.
pub const URL_SCHEMES: [&str; 2] = ["http://", "https://"];
