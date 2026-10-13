//! The Default app lookup against the system the tests run on: a type every
//! macOS and Windows install opens, and the refusals that never ask.

use super::for_extension;

#[test]
fn plain_text_has_an_app() {
    let app = for_extension("txt")
        .expect("the lookup answers")
        .expect("every install opens .txt");
    assert!(app.is_absolute(), "{}", app.display());
    #[cfg(target_os = "macos")]
    assert!(
        app.is_dir() && app.extension().is_some_and(|extension| extension == "app"),
        "{} is an application bundle",
        app.display()
    );
}

#[test]
fn an_extension_that_names_no_type_is_never_asked() {
    assert_eq!(for_extension("").expect("no lookup"), None);
    assert_eq!(for_extension("mk\0v").expect("no lookup"), None);
}
