//! The Kad-specific field reads layered on [`WireReader`]: node ids and the
//! two IPv4 octet orders Kad rows use. Every other read is the shared reader's.

use std::net::Ipv4Addr;

use rmule_primitives::{WireReader, WireTruncated};

use crate::KadId;

/// Kad's own field shapes, read through the shared bounds-checked reader.
pub(crate) trait KadWireFields {
    /// A 16-byte Kad id.
    fn read_kad_id(&mut self, field: &'static str) -> Result<KadId, WireTruncated>;

    /// The contact-row IPv4 serialization: `a.b.c.d` on the wire as
    /// `[d, c, b, a]` (capture-proven in routing, node and hello fixtures).
    fn read_ipv4_low_octet_first(&mut self, field: &'static str)
    -> Result<Ipv4Addr, WireTruncated>;

    /// The `CKadUDPKey` binding-IP serialization: `a.b.c.d` on disk as
    /// `[a, b, c, d]` — natural order, NOT the low-octet-first order of the
    /// contact IP in the same `nodes.dat` row. aMule's `m_ip` is a network-order
    /// u32 (`theApp->GetPublicIP(false)`), so its LE `WriteUInt32` emits the
    /// octets as-is.
    fn read_ipv4_natural_order(&mut self, field: &'static str) -> Result<Ipv4Addr, WireTruncated>;
}

impl KadWireFields for WireReader<'_> {
    fn read_kad_id(&mut self, field: &'static str) -> Result<KadId, WireTruncated> {
        self.read_array(field).map(KadId::from_bytes)
    }

    fn read_ipv4_low_octet_first(
        &mut self,
        field: &'static str,
    ) -> Result<Ipv4Addr, WireTruncated> {
        let [a, b, c, d] = self.read_array(field)?;
        Ok(Ipv4Addr::new(d, c, b, a))
    }

    fn read_ipv4_natural_order(&mut self, field: &'static str) -> Result<Ipv4Addr, WireTruncated> {
        self.read_array(field).map(Ipv4Addr::from)
    }
}
