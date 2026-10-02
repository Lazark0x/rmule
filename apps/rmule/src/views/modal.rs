//! The frame every modal shares: a cleared, bordered panel centered over the
//! view, its title on the top border, its lines inside. A view builds the
//! lines and picks the tone; the frame is drawn here once.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};

use super::centered;
use crate::theme::Theme;
use crate::wrap::clamp_u16;

/// One modal's frame, drawn by [`Modal::draw`].
pub(crate) struct Modal {
    title: String,
    border: Style,
    title_style: Style,
    padded: bool,
    min_height: u16,
}

impl Modal {
    /// A modal in the chrome's tone, its title marked as the active tab is.
    pub(crate) fn new(title: impl Into<String>, theme: &Theme) -> Self {
        Self {
            title: title.into(),
            border: theme.chrome(),
            title_style: theme.tab_active(),
            padded: false,
            min_height: 0,
        }
    }

    /// The title in the flash's style rather than the active tab's.
    pub(crate) fn flash_title(mut self, theme: &Theme) -> Self {
        self.title_style = theme.flash();
        self
    }

    /// The whole frame in the tone of a refusal or a removal.
    pub(crate) fn danger(mut self, theme: &Theme) -> Self {
        let bad = Style::new().fg(theme.bad);
        self.border = bad;
        self.title_style = bad;
        self
    }

    /// One blank column between the border and the text on each side.
    pub(crate) fn padded(mut self) -> Self {
        self.padded = true;
        self
    }

    /// Never shorter than `height` rows, borders included.
    pub(crate) fn at_least(mut self, height: u16) -> Self {
        self.min_height = height;
        self
    }

    /// Clear a `width`-wide panel centered in `area`, as tall as `lines` need,
    /// and draw the frame and the lines in it.
    pub(crate) fn draw(
        self,
        frame: &mut Frame,
        area: Rect,
        width: u16,
        theme: &Theme,
        lines: Vec<Line<'static>>,
    ) {
        let modal = centered(area, width, clamp_u16(lines.len() + 2).max(self.min_height));
        let block = Block::bordered()
            .border_style(self.border)
            .style(Style::new().fg(theme.fg).bg(theme.panel))
            .title_top(Line::from(Span::styled(self.title, self.title_style)));
        let inner = block.inner(modal);
        let text = if self.padded {
            Rect::new(
                inner.x + 1,
                inner.y,
                inner.width.saturating_sub(2),
                inner.height,
            )
        } else {
            inner
        };
        frame.render_widget(Clear, modal);
        frame.render_widget(block, modal);
        frame.render_widget(Paragraph::new(lines), text);
    }
}
