//! MS-PAC logon info and UPN/DNS buffers, encoded as the Go outpost did.

use eyre::{Result, eyre};

const NDR_POINTER: u32 = 0x20000;
const GROUP_ATTRIBUTES: u32 = 7;
const NORMAL_ACCOUNT: u32 = 0x200;
pub(crate) const UPN_DNS_HAS_SAM_NAME_AND_SID: u32 = 0x2;

/// An MS-DTYP security identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sid {
    revision: u8,
    authority: u64,
    sub_authorities: Vec<u32>,
}

impl Sid {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let parts: Vec<&str> = value.split('-').collect();
        let [s, revision, authority, subs @ ..] = parts.as_slice() else {
            return Err(eyre!("invalid SID {value:?}"));
        };
        if !s.eq_ignore_ascii_case("S") || subs.len() > 15_usize {
            return Err(eyre!("invalid SID {value:?}"));
        }
        let authority: u64 = authority.parse()?;
        if authority >= 1_u64 << 48_u32 {
            return Err(eyre!("SID authority exceeds 48 bits"));
        }
        Ok(Self {
            revision: revision.parse()?,
            authority,
            sub_authorities: subs.iter().map(|s| s.parse()).collect::<Result<_, _>>()?,
        })
    }

    pub(crate) fn with_rid(&self, rid: u32) -> Self {
        let mut sid = self.clone();
        sid.sub_authorities.push(rid);
        sid
    }

    /// The 8-byte header: revision, subauthority count, big-endian authority.
    fn header(&self) -> [u8; 8] {
        let mut out = [0_u8; 8];
        out[0] = self.revision;
        out[1] = u8::try_from(self.sub_authorities.len()).unwrap_or(u8::MAX);
        out[2..].copy_from_slice(&self.authority.to_be_bytes()[2..]);
        out
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = self.header().to_vec();
        for sub in &self.sub_authorities {
            out.extend_from_slice(&sub.to_le_bytes());
        }
        out
    }
}

fn utf16(value: &str) -> Result<Vec<u8>> {
    let units: Vec<u16> = value.encode_utf16().collect();
    if units.len() > 0x7fff {
        return Err(eyre!("PAC string is too long"));
    }
    Ok(units.iter().flat_map(|u| u.to_le_bytes()).collect())
}

fn len16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| eyre!("PAC field exceeds uint16"))
}

fn len32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| eyre!("PAC field exceeds uint32"))
}

enum Deferred {
    Unicode(Vec<u8>),
    Sid(Sid),
    Groups(Vec<u32>),
}

#[derive(Default)]
struct NdrWriter {
    buf: Vec<u8>,
    next_ref: u32,
    deferred: Vec<Deferred>,
}

impl NdrWriter {
    fn align4(&mut self) {
        let pad = self.buf.len().wrapping_neg() & 3;
        self.buf.resize(self.buf.len() + pad, 0);
    }

    fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn pointer(&mut self, present: bool) {
        if present {
            self.next_ref += 1;
            self.u32(NDR_POINTER + self.next_ref);
        } else {
            self.u32(0);
        }
    }

    fn unicode(&mut self, value: &str) -> Result<()> {
        let encoded = utf16(value)?;
        let len = len16(encoded.len())?;
        self.u16(len);
        self.u16(len);
        self.pointer(true);
        self.deferred.push(Deferred::Unicode(encoded));
        Ok(())
    }

    fn sid(&mut self, sid: &Sid) -> Result<()> {
        self.align4();
        self.u32(len32(sid.sub_authorities.len())?);
        self.buf.extend_from_slice(&sid.header());
        for sub in &sid.sub_authorities {
            self.u32(*sub);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        for item in std::mem::take(&mut self.deferred) {
            self.align4();
            match item {
                Deferred::Unicode(data) => {
                    let chars = len32(data.len() / 2)?;
                    self.u32(chars);
                    self.u32(0);
                    self.u32(chars);
                    self.buf.extend_from_slice(&data);
                }
                Deferred::Sid(sid) => self.sid(&sid)?,
                Deferred::Groups(rids) => {
                    self.u32(len32(rids.len())?);
                    for rid in rids {
                        self.u32(rid);
                        self.u32(GROUP_ATTRIBUTES);
                    }
                }
            }
        }
        Ok(())
    }
}

/// The authentik identity that goes in a user's PAC.
pub(crate) struct PacIdentity<'a> {
    pub(crate) username: &'a str,
    pub(crate) full_name: &'a str,
    pub(crate) user_id: u32,
    pub(crate) primary_group_id: u32,
    pub(crate) group_ids: Vec<u32>,
    pub(crate) upn: &'a str,
    pub(crate) realm: &'a str,
    pub(crate) domain_sid: &'a Sid,
}

impl PacIdentity<'_> {
    /// `PAC_LOGON_INFO` (`KERB_VALIDATION_INFO`, NDR32 with type serialization headers).
    pub(crate) fn logon_info(&self) -> Result<Vec<u8>> {
        let mut w = NdrWriter::default();
        w.buf.extend_from_slice(&[1, 0x10, 8, 0]);
        w.u32(0xcccc_cccc);
        w.u32(0);
        w.u32(0);
        w.pointer(true);
        for _ in 0_u8..6 {
            w.u64(0);
        }
        for value in [self.username, self.full_name, "", "", "", ""] {
            w.unicode(value)?;
        }
        w.u16(0);
        w.u16(0);
        w.u32(self.user_id);
        w.u32(self.primary_group_id);
        w.u32(len32(self.group_ids.len())?);
        w.pointer(!self.group_ids.is_empty());
        if !self.group_ids.is_empty() {
            w.deferred.push(Deferred::Groups(self.group_ids.clone()));
        }
        w.u32(0);
        w.buf.extend_from_slice(&[0; 16]);
        let domain = self
            .realm
            .split('.')
            .next()
            .unwrap_or_default()
            .to_uppercase();
        w.unicode("authentik")?;
        w.unicode(&domain)?;
        w.pointer(true);
        w.deferred.push(Deferred::Sid(self.domain_sid.clone()));
        w.u32(0);
        w.u32(0);
        w.u32(NORMAL_ACCOUNT);
        w.u32(0);
        w.u64(0);
        w.u64(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.pointer(false);
        w.pointer(false);
        w.u32(0);
        w.pointer(false);
        w.flush()?;
        let len = len32(w.buf.len() - 16)?;
        w.buf[8..12].copy_from_slice(&len.to_le_bytes());
        Ok(w.buf)
    }

    /// `PAC_UPN_DNS_INFO` with the SAM name and user SID.
    pub(crate) fn upn_dns_info(&self) -> Result<Vec<u8>> {
        const HEADER_LEN: usize = 20;
        let fields = [
            utf16(self.upn)?,
            utf16(&self.realm.to_lowercase())?,
            utf16(self.username)?,
            self.domain_sid.with_rid(self.user_id).encode(),
        ];
        let align4 = |v: usize| (v + 3) & !3;
        let mut offset = align4(HEADER_LEN);
        let mut out = vec![0_u8; HEADER_LEN];
        let mut header = Vec::with_capacity(HEADER_LEN);
        let mut body = Vec::new();
        for (i, field) in fields.iter().enumerate() {
            header.extend_from_slice(&len16(field.len())?.to_le_bytes());
            header.extend_from_slice(&len16(offset)?.to_le_bytes());
            if i == 1 {
                header.extend_from_slice(&UPN_DNS_HAS_SAM_NAME_AND_SID.to_le_bytes());
            }
            body.resize(offset - HEADER_LEN, 0);
            body.extend_from_slice(field);
            offset = align4(offset + field.len());
        }
        body.resize(offset - HEADER_LEN, 0);
        out.copy_from_slice(&header);
        out.extend_from_slice(&body);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(sid: &Sid) -> PacIdentity<'_> {
        PacIdentity {
            username: "alice",
            full_name: "Alice",
            user_id: 1001,
            primary_group_id: 513,
            group_ids: vec![513, 1100],
            upn: "alice@example.com",
            realm: "EXAMPLE.COM",
            domain_sid: sid,
        }
    }

    #[test]
    fn sid_roundtrip() {
        let sid = Sid::parse("S-1-5-21-1-2-3").expect("parse SID");
        assert_eq!(
            sid.encode(),
            [
                1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0
            ]
        );
        let err = Sid::parse("S-1-x").expect_err("reject bad SID");
        assert!(err.to_string().contains("invalid"));
    }

    #[test]
    fn upn_dns_info_layout() {
        let sid = Sid::parse("S-1-5-21-1-2-3").expect("parse SID");
        let data = identity(&sid).upn_dns_info().expect("encode");
        let u16_at = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
        assert_eq!((u16_at(0), u16_at(2)), (34, 20));
        assert_eq!((u16_at(4), u16_at(6)), (22, 56));
        assert_eq!(&data[8..12], &UPN_DNS_HAS_SAM_NAME_AND_SID.to_le_bytes());
        assert_eq!((u16_at(12), u16_at(14)), (10, 80));
        assert_eq!((u16_at(16), u16_at(18)), (28, 92));
        assert_eq!(data.len(), 120);
    }

    #[test]
    fn logon_info_header() {
        let sid = Sid::parse("S-1-5-21-1-2-3").expect("parse SID");
        let data = identity(&sid).logon_info().expect("encode");
        assert_eq!(&data[..8], &[1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc]);
        let len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        assert_eq!(usize::try_from(len).expect("length"), data.len() - 16);
        assert_eq!(&data[16..20], &(NDR_POINTER + 1).to_le_bytes());
    }
}
