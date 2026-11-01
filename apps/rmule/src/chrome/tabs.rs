//! The tab bar: one tab per view, plus the brand when the frame is wide
//! enough to carry it.
//!
//! A narrow frame swaps the labels for their compact form rather than clipping
//! one, and the brand is the first thing to go — a clipped label reads as a
//! different word, which is worse than no word at all. Hit testing measures
//! the same spans the renderer drew, so a click cannot land on a tab the
//! operator did not see.

use crate::wrap::display_width;
use ratatui::text::{Line, Span};

use super::ChromeState;
use crate::theme::Theme;
use crate::view::ViewId;
use crate::words::labels;

/// The brand tag on the top border — decoration, not information.
pub(super) const BRAND: &str = labels::BRAND;

/// Dashes the brand insists on keeping between itself and the last tab. The
/// tab bar is the load-bearing furniture, so the brand is priority-dropped
/// (the status bar's discipline) rather than shouldered up against it.
const BRAND_MIN_GAP: usize = 2;

/// The tab texts in order at a given frame width — the single source for both
/// rendering and hit-testing, so the two cannot disagree about where a tab is.
///
/// # The six-tab width budget
///
/// A tab is `" N Title "`, so the bar costs `Σ(len(title) + 4)` plus one `│`
/// per gap. It takes the first form that fits, rather than clipping a label
/// mid-word:
///
/// - **Full** — every tab named. 84 columns ⇒ from an **86-column** frame up.
/// - **Short** — every tab named, the two longest by [`ViewId::short_title`].
///   73 columns ⇒ from a **75-column** frame up, so the canonical 80-column
///   terminal names all six.
/// - **Compact** — inactive tabs shrink to `" N "` and the active one keeps
///   its name: **29–33** columns ⇒ from a **35-column** frame up, far below any
///   frame the rest of the UI is usable in.
fn tab_texts(active: ViewId, frame_width: u16) -> Vec<(String, ViewId)> {
    let named = |title: fn(ViewId) -> &'static str| -> Vec<(String, ViewId)> {
        ViewId::ALL
            .into_iter()
            .map(|view| (format!(" {} {} ", view.number(), title(view)), view))
            .collect()
    };
    let room = usize::from(frame_width.saturating_sub(2));
    for form in [named(ViewId::title), named(ViewId::short_title)] {
        if bar_width(&form) <= room {
            return form;
        }
    }
    ViewId::ALL
        .into_iter()
        .map(|view| {
            let text = if view == active {
                format!(" {} {} ", view.number(), view.short_title())
            } else {
                format!(" {} ", view.number())
            };
            (text, view)
        })
        .collect()
}

/// Rendered width of a tab set: the texts plus one separator per gap.
fn bar_width(tabs: &[(String, ViewId)]) -> usize {
    tabs.iter()
        .map(|(text, _)| display_width(text))
        .sum::<usize>()
        + tabs.len().saturating_sub(1)
}

pub(super) fn tabs_line(active: ViewId, frame_width: u16, theme: &Theme) -> Line<'static> {
    let mut spans = Vec::new();
    for (index, (text, view)) in tab_texts(active, frame_width).into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("│", theme.chrome()));
        }
        let style = if view == active {
            theme.tab_active()
        } else {
            theme.tab_inactive()
        };
        spans.push(Span::styled(text, style));
    }
    Line::from(spans)
}

/// Does the brand tag still fit beside the tab bar with visible border
/// between them? Below that width it is simply not drawn — the tabs are the
/// furniture that carries meaning.
pub(super) fn brand_fits(tabs_w: usize, frame_width: u16) -> bool {
    let inner = usize::from(frame_width.saturating_sub(2));
    tabs_w + display_width(BRAND) + BRAND_MIN_GAP <= inner
}

/// Which tab a click on the top border row hits, against the bar as it was
/// last *drawn* — the form depends on the frame width, so the hit test reads
/// the same cached width the draw used. `column` is the terminal column; the
/// tab line starts one cell in (after the corner glyph).
#[must_use]
pub fn tab_at(chrome: &ChromeState, column: u16) -> Option<ViewId> {
    let mut x = 1u16; // top-left corner occupies column 0
    for (index, (text, view)) in tab_texts(chrome.active, chrome.frame_width.get())
        .into_iter()
        .enumerate()
    {
        if index > 0 {
            x += 1; // the │ separator
        }
        let width = u16::try_from(display_width(&text)).unwrap_or(u16::MAX);
        if (x..x + width).contains(&column) {
            return Some(view);
        }
        x += width;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::draw_frame;
    use super::*;
    use crate::action::Action;
    use crate::fixture::*;
    use crate::golden::assert_golden;
    use crate::state::UiState;

    /// A chrome as if it had already been drawn at `width`. The cached frame
    /// width a click is hit-tested against is written only by `draw_frame`,
    /// and it is private to the chrome module — so this stays here rather
    /// than in the crate's fixture home.
    fn chrome_at(active: ViewId, width: u16) -> ChromeState {
        let chrome = ChromeState {
            active,
            ..ChromeState::default()
        };
        chrome.frame_width.set(width);
        chrome
    }

    #[test]
    fn tab_hit_testing_matches_the_rendered_spans() {
        // Full form (≥86 columns): col 0 corner, cols 1–12 " 1 Networks ",
        // col 13 │, …
        let wide = chrome_at(ViewId::Networks, 100);
        assert_eq!(tab_at(&wide, 1), Some(ViewId::Networks));
        assert_eq!(tab_at(&wide, 12), Some(ViewId::Networks));
        assert_eq!(
            tab_at(&wide, 13),
            None,
            "separator column belongs to no tab"
        );
        assert_eq!(tab_at(&wide, 14), Some(ViewId::Searches));
        // …through " 6 Settings ", the last tab: cols 73–84.
        assert_eq!(tab_at(&wide, 72), None, "separator before the sixth tab");
        assert_eq!(tab_at(&wide, 73), Some(ViewId::Settings));
        assert_eq!(tab_at(&wide, 84), Some(ViewId::Settings));
        assert_eq!(tab_at(&wide, 85), None, "past the sixth tab");
        assert_eq!(tab_at(&wide, 0), None, "corner glyph");
        assert_eq!(tab_at(&wide, 200), None, "past the tabs");

        // Short form (80 columns): " 1 Networks │ 2 Searches │ … │ 6 Settings ".
        let short = chrome_at(ViewId::Networks, 80);
        assert_eq!(tab_at(&short, 12), Some(ViewId::Networks));
        assert_eq!(tab_at(&short, 14), Some(ViewId::Searches));
        assert_eq!(tab_at(&short, 62), Some(ViewId::Settings));
        assert_eq!(tab_at(&short, 73), Some(ViewId::Settings));
        assert_eq!(tab_at(&short, 74), None, "past the sixth tab");

        // Compact form (60 columns): " 1 Networks │ 2 │ 3 │ 4 │ 5 │ 6 ".
        let narrow = chrome_at(ViewId::Networks, 60);
        assert_eq!(tab_at(&narrow, 12), Some(ViewId::Networks));
        assert_eq!(
            tab_at(&narrow, 14),
            Some(ViewId::Searches),
            "digit-only tab"
        );
        assert_eq!(tab_at(&narrow, 17), None, "the separator after it");
        assert_eq!(tab_at(&narrow, 30), Some(ViewId::Settings));
        assert_eq!(tab_at(&narrow, 32), Some(ViewId::Settings));
        assert_eq!(tab_at(&narrow, 33), None, "past the compact bar");
    }

    /// The ladder: each form holds from the width its doc gives, the
    /// default terminal names all six, and nothing overflows any frame.
    #[test]
    fn the_tab_bar_takes_the_first_form_that_fits_rather_than_clipping_a_label() {
        let theme = Theme::default_dark();
        let width_at = |frame: u16| tabs_line(ViewId::Transfers, frame, &theme).width();

        assert_eq!(width_at(200), 84, "six fully-named tabs cost 84 columns");
        assert_eq!(
            width_at(86),
            84,
            "an 86-column frame is the first to hold them"
        );
        assert_eq!(width_at(85), 73, "one column short ⇒ the short form");
        assert_eq!(width_at(80), 73, "the canonical terminal names all six");
        assert_eq!(width_at(75), 73, "the first frame to hold the short form");
        assert_eq!(width_at(74), 33, "one column short ⇒ the compact form");
        assert!(
            tabs_line(ViewId::Settings, 80, &theme)
                .to_string()
                .contains("4 Shared │ 5 Stats")
        );
        for width in 35u16..=200 {
            for active in ViewId::ALL {
                assert!(
                    tabs_line(active, width, &theme).width() <= usize::from(width - 2),
                    "the bar overflows an {width}-column frame on {active:?}"
                );
            }
        }

        // The brand is decoration and yields to any form.
        assert!(!brand_fits(84, 86), "no room beside the full bar at 86");
        assert!(!brand_fits(73, 80), "nor beside the short bar at 80");
        let roomy = u16::try_from(84 + BRAND.chars().count() + BRAND_MIN_GAP + 2).unwrap();
        assert!(brand_fits(84, roomy), "…and it returns once there is room");
        assert!(!brand_fits(84, roomy - 1));
    }

    #[test]
    fn golden_chrome_searches_tab_active() {
        let mut chrome = ChromeState::default();
        chrome.update(&Action::SwitchView(ViewId::Searches), now());
        assert_golden("chrome_searches", 80, 24, |frame| {
            draw_frame(
                frame,
                &UiState::default(),
                &chrome,
                &Theme::default_dark(),
                now(),
            );
        });
    }

    #[test]
    fn the_active_tab_is_accent_inverted_and_inactive_tabs_dim() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let theme = Theme::default_dark();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        terminal
            .draw(|frame| {
                draw_frame(
                    frame,
                    &UiState::default(),
                    &ChromeState::default(),
                    &theme,
                    now(),
                );
            })
            .expect("draw");
        let buffer = terminal.backend().buffer();
        // Column 2 sits inside " 1 Networks " (active); column 16 inside
        // " 2 Searches " (inactive) — see tab_hit_testing above.
        let active = buffer.cell((2u16, 0u16)).expect("active tab cell");
        let inactive = buffer.cell((16u16, 0u16)).expect("inactive tab cell");
        assert_eq!(
            active.style().bg,
            Some(theme.accent),
            "active tab accent-inverted"
        );
        assert_eq!(inactive.style().fg, Some(theme.dim), "inactive tab dim");
    }
}
