//! The theme's tier choice, what shape carries with no colour, and the
//! contrast every palette is held to.

use ratatui::style::{Color, Modifier, Style};

use super::contrast::{Rgb, ratio};
use super::*;
use crate::glyphs::GlyphTier;

/// WCAG 1.4.3 for text.
const MINIMUM: f64 = 4.5;

fn capability(colour: ColourTier, light_ground: Option<bool>) -> Capability {
    Capability {
        colour,
        light_ground,
        glyphs: GlyphTier::Unicode,
    }
}

#[test]
fn an_explicit_choice_paints_what_it_names() {
    let on_light = capability(ColourTier::Truecolor, Some(true));
    assert_eq!(Theme::select(Some("light"), on_light).bg, Theme::light().bg);
    assert_eq!(
        Theme::select(Some("256"), on_light).bg,
        Theme::fallback_256().bg
    );
    assert_eq!(
        Theme::select(Some("dark"), capability(ColourTier::None, None)).bg,
        Theme::default_dark().bg
    );
}

/// A terminal that said what its ground is keeps it and gets the side that
/// reads on it; one that did not gets the opaque ground the pairs are known
/// to read on.
#[test]
fn the_answered_ground_stays_the_terminals_own() {
    for (tier, dark, light) in [
        (ColourTier::Truecolor, Theme::default_dark(), Theme::light()),
        (
            ColourTier::Indexed256,
            Theme::fallback_256(),
            Theme::light_256(),
        ),
    ] {
        let unknown = Theme::select(None, capability(tier, None));
        assert_eq!((unknown.bg, unknown.fg), (dark.bg, dark.fg));
        let on_dark = Theme::select(None, capability(tier, Some(false)));
        assert_eq!((on_dark.bg, on_dark.fg), (Color::Reset, dark.fg));
        let on_light = Theme::select(None, capability(tier, Some(true)));
        assert_eq!((on_light.bg, on_light.fg), (Color::Reset, light.fg));
    }
}

#[test]
fn sixteen_colours_stay_named_and_no_colour_stays_none() {
    let console = Theme::select(None, capability(ColourTier::Ansi16, None));
    assert_eq!(console.bad, Color::LightRed);
    let light = Theme::select(None, capability(ColourTier::Ansi16, Some(true)));
    assert_eq!(light.bad, Color::Red);
    let none = Theme::select(None, capability(ColourTier::None, Some(true)));
    assert!(none.colourless());
}

/// What each theme paints, and against which reference: the design's own
/// grounds, and the VGA colours the Linux console starts with. An own-ground
/// palette is the same pairs on a ground of the side it was picked for.
fn rgb(colour: Color, default: Rgb) -> Rgb {
    const VGA: [Rgb; 16] = [
        (0x00, 0x00, 0x00),
        (0xAA, 0x00, 0x00),
        (0x00, 0xAA, 0x00),
        (0xAA, 0x55, 0x00),
        (0x00, 0x00, 0xAA),
        (0xAA, 0x00, 0xAA),
        (0x00, 0xAA, 0xAA),
        (0xAA, 0xAA, 0xAA),
        (0x55, 0x55, 0x55),
        (0xFF, 0x55, 0x55),
        (0x55, 0xFF, 0x55),
        (0xFF, 0xFF, 0x55),
        (0x55, 0x55, 0xFF),
        (0xFF, 0x55, 0xFF),
        (0x55, 0xFF, 0xFF),
        (0xFF, 0xFF, 0xFF),
    ];
    let cube = |step: u8| if step == 0 { 0 } else { 55 + 40 * step };
    match colour {
        Color::Reset => default,
        Color::Rgb(red, green, blue) => (red, green, blue),
        Color::Indexed(index @ 232..) => {
            let grey = 8 + (index - 232) * 10;
            (grey, grey, grey)
        }
        Color::Indexed(index @ 16..) => {
            let index = index - 16;
            (cube(index / 36), cube(index / 6 % 6), cube(index % 6))
        }
        Color::Indexed(index) => VGA[usize::from(index)],
        Color::Black => VGA[0],
        Color::Red => VGA[1],
        Color::Green => VGA[2],
        Color::Yellow => VGA[3],
        Color::Blue => VGA[4],
        Color::Magenta => VGA[5],
        Color::Cyan => VGA[6],
        Color::Gray => VGA[7],
        Color::DarkGray => VGA[8],
        Color::LightRed => VGA[9],
        Color::LightGreen => VGA[10],
        Color::LightYellow => VGA[11],
        Color::LightBlue => VGA[12],
        Color::LightMagenta => VGA[13],
        Color::LightCyan => VGA[14],
        Color::White => VGA[15],
    }
}

/// Every pair a frame draws text in, measured in every theme. Text roles go
/// on the frame, a panel and a selected row; the scroll bar and the accent's
/// fill add their own.
#[test]
fn every_pair_in_every_theme_reads_at_four_and_a_half_to_one() {
    let black_ground = ((0, 0, 0), (0xAA, 0xAA, 0xAA));
    let white_ground = ((0xFF, 0xFF, 0xFF), (0, 0, 0));
    let unused = ((0, 0, 0), (0, 0, 0));
    for (name, t, (ground, ink)) in [
        ("dark", Theme::default_dark(), unused),
        ("light", Theme::light(), unused),
        ("256", Theme::fallback_256(), unused),
        ("256 light", Theme::light_256(), unused),
        ("16", Theme::ansi(), black_ground),
        ("16 light", Theme::ansi_light(), white_ground),
    ] {
        let text = [
            ("fg", t.fg),
            ("dim", t.dim),
            ("accent", t.accent),
            ("highlight", t.highlight),
            ("good", t.good),
            ("warn", t.warn),
            ("bad", t.bad),
            ("downloading", t.mark_downloading),
            ("failed", t.mark_failed),
            ("have", t.mark_have),
            ("withheld", t.mark_withheld),
            ("had", t.mark_had),
            ("cancelled", t.mark_cancelled),
        ];
        let grounds = [
            ("bg", t.bg),
            ("panel", t.panel),
            ("selection", t.selection),
            ("track", t.scroll_track),
        ];
        let mut pairs = vec![("on_accent", t.on_accent, "accent", t.accent)];
        for (role, colour) in text {
            for (under, fill) in grounds {
                pairs.push((role, colour, under, fill));
            }
        }
        for (role, colour, under, fill) in pairs {
            let measured = ratio(rgb(colour, ink), rgb(fill, ground));
            assert!(
                measured >= MINIMUM,
                "{name}: {role} on {under} is {measured:.2}"
            );
        }
    }
}

/// What protanopia leaves of a colour (Machado 2009, severity 1), in CIELAB.
fn protanope_lab(colour: Rgb) -> [f64; 3] {
    const SEEN: [[f64; 3]; 3] = [
        [0.152_286, 1.052_583, -0.204_868],
        [0.114_503, 0.786_281, 0.099_216],
        [-0.003_882, -0.048_116, 1.051_998],
    ];
    let linear = |channel: u8| {
        let channel = f64::from(channel) / 255.0;
        if channel <= 0.040_45 {
            channel / 12.92
        } else {
            ((channel + 0.055) / 1.055).powf(2.4)
        }
    };
    let rgb = [linear(colour.0), linear(colour.1), linear(colour.2)];
    let [r, g, b] =
        SEEN.map(|row| (row[0] * rgb[0] + row[1] * rgb[1] + row[2] * rgb[2]).clamp(0.0, 1.0));
    let f = |t: f64| {
        if t > 0.008_856 {
            t.cbrt()
        } else {
            7.787 * t + 16.0 / 116.0
        }
    };
    let x = f((0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.950_47);
    let y = f(0.2126 * r + 0.7152 * g + 0.0722 * b);
    let z = f((0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.088_83);
    [116.0 * y - 16.0, 500.0 * (x - y), 200.0 * (y - z)]
}

/// A cancelled result is the operator's own act and a `bad` state is a fault:
/// a protanope, for whom reds fall towards brown, must still tell them apart.
#[test]
fn a_cancelled_mark_stands_apart_from_bad_under_protanopia() {
    for (name, t) in [
        ("dark", Theme::default_dark()),
        ("light", Theme::light()),
        ("256", Theme::fallback_256()),
        ("256 light", Theme::light_256()),
        ("16", Theme::ansi()),
        ("16 light", Theme::ansi_light()),
    ] {
        let lab = |colour| protanope_lab(rgb(colour, (0, 0, 0)));
        let (cancelled, bad) = (lab(t.mark_cancelled), lab(t.bad));
        let distance = cancelled
            .iter()
            .zip(bad)
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f64>()
            .sqrt();
        assert!(distance >= 15.0, "{name}: {distance:.1}");
    }
}

/// The screen a no-colour operator reads, with nothing but shape to go on.
fn modifiers_at(style: Style) -> Modifier {
    style.add_modifier
}

#[test]
fn with_no_colour_shape_carries_the_tab_the_header_and_the_focus() {
    let mono = Theme::mono();
    assert!(modifiers_at(mono.tab_active()).contains(Modifier::REVERSED));
    assert!(modifiers_at(mono.header()).contains(Modifier::UNDERLINED));
    assert_ne!(
        format!("{:?}", mono.pane(true)),
        format!("{:?}", mono.pane(false))
    );
    let colour = Theme::default_dark();
    assert!(!modifiers_at(colour.tab_active()).contains(Modifier::REVERSED));
    assert!(!modifiers_at(colour.header()).contains(Modifier::UNDERLINED));
}

/// What a no-colour user asked for is no colour escape in any cell, with
/// the words and the marker still there to read.
#[test]
fn a_mono_frame_paints_no_colour_and_keeps_the_marker() {
    let theme = Theme::mono();
    let state = crate::fixture::three_downloads();
    let mut view = crate::views::transfers::TransfersView::new();
    let backend = ratatui::backend::TestBackend::new(78, 21);
    let mut terminal = ratatui::Terminal::new(backend).expect("terminal");
    terminal
        .draw(|frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &theme, crate::fixture::now());
        })
        .expect("draw");
    let buffer = terminal.backend().buffer();
    assert!(
        buffer
            .content()
            .iter()
            .all(|cell| cell.fg == Color::Reset && cell.bg == Color::Reset)
    );
    let glyphs: String = buffer.content().iter().map(|cell| cell.symbol()).collect();
    assert!(glyphs.contains('▸'), "{glyphs}");
}

/// A frame drawn in a theme, chrome and view together.
fn framed(theme: &Theme) -> ratatui::buffer::Buffer {
    let state = crate::fixture::three_downloads();
    let chrome = crate::chrome::ChromeState::default();
    let mut view = crate::views::transfers::TransfersView::new();
    let backend = ratatui::backend::TestBackend::new(100, 26);
    let mut terminal = ratatui::Terminal::new(backend).expect("terminal");
    terminal
        .draw(|frame| {
            let now = crate::fixture::now();
            let area = crate::chrome::draw_frame(frame, &state, &chrome, theme, now);
            view.draw(frame, area, &state, theme, now);
        })
        .expect("draw");
    terminal.backend().buffer().clone()
}

/// The console's sixteen colours, by name, are all a frame may send it: an
/// index or a value would be mangled or dropped.
#[test]
fn a_sixteen_colour_frame_sends_only_named_colours() {
    let named = |colour: Color| !matches!(colour, Color::Rgb(..) | Color::Indexed(_));
    for theme in [Theme::ansi(), Theme::ansi_light()] {
        let frame = framed(&theme);
        assert!(frame.content().iter().all(|c| named(c.fg) && named(c.bg)));
        assert!(frame.content().iter().any(|c| c.fg != Color::Reset));
    }
}

/// On the terminal's own ground the frame paints none of its own; the same
/// palette opaque paints it behind every empty cell.
#[test]
fn a_frame_on_the_terminals_own_ground_leaves_it_unpainted() {
    let opaque = Theme::default_dark();
    let own = opaque.on_own_ground();
    let blank = |theme: &Theme| {
        let frame = framed(theme);
        frame.content().iter().filter(|c| c.bg == opaque.bg).count()
    };
    assert!(blank(&opaque) > 0);
    assert_eq!(blank(&own), 0);
}

/// Read off a real table with no colour on it: the pane in focus by its heavy
/// frame, its headers by a line, its selected row by reverse video.
#[test]
fn a_mono_table_shows_its_focus_headers_and_selection_by_shape() {
    let theme = Theme::mono();
    let state = crate::fixture::three_downloads();
    let mut view = crate::views::transfers::TransfersView::new();
    let backend = ratatui::backend::TestBackend::new(78, 21);
    let mut terminal = ratatui::Terminal::new(backend).expect("terminal");
    terminal
        .draw(|frame| {
            let area = frame.area();
            view.draw(frame, area, &state, &theme, crate::fixture::now());
        })
        .expect("draw");
    let buffer = terminal.backend().buffer();
    assert_eq!(buffer[(0, 0)].symbol(), "┏");
    let with = |modifier: Modifier| {
        buffer
            .content()
            .iter()
            .filter(|cell| cell.modifier.contains(modifier) && cell.symbol() != " ")
            .map(|cell| cell.symbol())
            .collect::<String>()
    };
    assert!(with(Modifier::UNDERLINED).contains("File"), "headers");
    assert!(with(Modifier::REVERSED).contains('▸'), "selection");
    let focus = crate::row_selection::focus_point(buffer, &theme).expect("a selected row");
    assert_eq!(buffer[focus].symbol(), "▸");
}

/// ADR-0100: a marked row trades its source tint for the mark's colour,
/// so in every palette a mark must differ from each tint and from the
/// other marks, or the eye reads one as the other.
#[test]
fn every_mark_colour_stands_apart_from_the_source_tints_and_each_other() {
    for t in [
        Theme::default_dark(),
        Theme::light(),
        Theme::fallback_256(),
        Theme::light_256(),
        Theme::ansi(),
        Theme::ansi_light(),
    ] {
        let marks = [
            t.mark_downloading,
            t.mark_failed,
            t.mark_have,
            t.mark_withheld,
            t.mark_had,
            t.mark_cancelled,
        ];
        for (i, mark) in marks.iter().enumerate() {
            for tint in [t.good, t.fg, t.dim] {
                assert_ne!(*mark, tint);
            }
            assert!(!marks[i + 1..].contains(mark), "{mark:?} twice");
        }
    }
}

#[test]
fn the_256_palettes_use_no_rgb_values_anywhere() {
    // The whole point of the hand-tuned theme (spec §5): a non-truecolor
    // terminal must never receive an RGB escape it would mangle.
    for t in [Theme::fallback_256(), Theme::light_256()] {
        for color in [
            t.bg,
            t.panel,
            t.fg,
            t.dim,
            t.accent,
            t.highlight,
            t.good,
            t.warn,
            t.bad,
            t.selection,
            t.scroll_track,
            t.mark_downloading,
            t.mark_failed,
            t.mark_have,
            t.mark_withheld,
            t.mark_had,
            t.mark_cancelled,
        ] {
            assert!(
                matches!(color, Color::Indexed(_)),
                "fallback theme leaked a non-indexed color: {color:?}"
            );
        }
    }
}
