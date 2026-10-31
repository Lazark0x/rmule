//! A destination whose directory is not there (ADR-0115, step 3): the download
//! directory may not exist yet, and no part file makes it any more, so the
//! move makes it on the rename road and on the Completion Copy road, and one
//! that cannot be made fails the move and keeps the part file.

use super::*;

/// Run the move to its end, the actor answering: a refusal fails here at
/// once, where the actor would wait for a report that never comes.
async fn lands(leg: &Finished, rx: &mut mpsc::Receiver<FinalFileInPlace>, destination: &Path) {
    let moved = complete(&leg.runner, leg.id, &leg.file, Vec::new());
    tokio::pin!(moved);
    tokio::select! {
        result = &mut moved => panic!("the move ended with no report: {result:?}"),
        report = rx.recv() => {
            let report = report.expect("the run reports its file in place");
            assert_eq!(report.path, destination);
            report.written.send(true).unwrap();
        }
    }
    moved.await.unwrap();
}

/// The download directory may not exist yet, and no part file makes it any
/// more (ADR-0115): the rename road makes it, however deep, and lands.
#[tokio::test]
async fn a_rename_into_a_directory_that_is_not_there_makes_it_and_lands() {
    let mut leg = finished_at(300_000, Arc::new(OsCompletionFs), |dir| {
        DownloadPaths::new(
            dir.join("not yet/made/film.mkv"),
            dir.join("temp/film.mkv.part"),
        )
    });
    let destination = leg.paths.final_path().to_path_buf();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    lands(&leg, &mut rx, &destination).await;
    assert_eq!(std::fs::read(&destination).unwrap(), leg.bytes);
    assert_eq!(completed_at(&leg.events()), Some(destination.as_path()));
}

/// The Completion Copy road meets the same missing directory: its copy
/// lands beside a destination whose directory the move made.
#[tokio::test]
async fn a_copy_into_a_directory_that_is_not_there_makes_it_and_lands() {
    let fs = TwoVolumes {
        before: Box::new(|_| {}),
    };
    let mut leg = finished_at(300_000, Arc::new(fs), |dir| {
        DownloadPaths::new(
            dir.join("not yet/made/film.mkv"),
            dir.join("temp/film.mkv.part"),
        )
    });
    let destination = leg.paths.final_path().to_path_buf();
    let mut rx = std::mem::replace(&mut leg.held.in_place_rx, mpsc::channel(1).1);
    lands(&leg, &mut rx, &destination).await;
    assert_eq!(std::fs::read(&destination).unwrap(), leg.bytes);
}

/// A directory that cannot be made, a file standing where it would go, fails
/// the move with the system's own code and keeps the part file and its parts
/// for the next attempt: `EEXIST` is the code here, not a name to take.
#[cfg(unix)]
#[tokio::test]
async fn a_directory_that_cannot_be_made_fails_with_its_code_and_keeps_the_part_file() {
    let leg = finished_at(300_000, Arc::new(OsCompletionFs), |dir| {
        DownloadPaths::new(
            dir.join("dl/in the way/film.mkv"),
            dir.join("temp/film.mkv.part"),
        )
    });
    let in_the_way = leg.paths.final_path().parent().unwrap().to_path_buf();
    std::fs::write(&in_the_way, b"the operator's own file").unwrap();

    let failure = complete(&leg.runner, leg.id, &leg.file, Vec::new())
        .await
        .unwrap_err();

    assert_eq!(
        failure,
        DownloadFailure::CompletedFileNotMoved { os_code: Some(17) }
    );
    assert_eq!(std::fs::read(leg.paths.part_path()).unwrap(), leg.bytes);
    assert_eq!(
        leg.runner.rt.store.verified_parts(leg.id).unwrap().len(),
        1,
        "every verified part is kept"
    );
    assert_eq!(
        std::fs::read(&in_the_way).unwrap(),
        b"the operator's own file"
    );
}
