//! WCAG relative luminance and contrast. The palette picks its side of a
//! terminal's ground by luminance; the contrast ratio is what the palette
//! test holds every pair to.

/// A colour as three eight-bit channels.
pub type Rgb = (u8, u8, u8);

/// WCAG 2.1 relative luminance, from 0 (black) to 1 (white).
#[must_use]
pub fn luminance((red, green, blue): Rgb) -> f64 {
    let linear = |channel: u8| {
        let channel = f64::from(channel) / 255.0;
        if channel <= 0.040_45 {
            channel / 12.92
        } else {
            ((channel + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)
}

/// Whether dark text reads better than light text on this ground: the
/// luminance at which black and white contrast with it equally.
#[must_use]
pub fn is_light(ground: Rgb) -> bool {
    luminance(ground) > 0.179
}

/// The WCAG contrast ratio of two colours, from 1 to 21.
#[cfg(test)]
pub fn ratio(a: Rgb, b: Rgb) -> f64 {
    let (a, b) = (luminance(a), luminance(b));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}
