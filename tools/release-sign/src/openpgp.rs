//! Just enough OpenPGP (RFC 4880, v4) to publish a repository: an RSA public
//! key with one user ID, detached signatures and cleartext signatures, all
//! SHA-512.
//!
//! Written here rather than taken from an OpenPGP library because the private
//! key is not ours to hold: Cloud KMS signs, and what OpenPGP needs around
//! that signature — the packet, its hashed subpackets, the trailer — is a few
//! hundred lines. A library would want the key.
//!
//! RSA with PKCS#1 v1.5 because that is what KMS's `RSA_SIGN_PKCS1_4096_SHA512`
//! produces and what OpenPGP's RSA signatures are: the same `DigestInfo`
//! encoding, so KMS's signature is the OpenPGP signature's MPI as it is.

use aws_lc_rs::digest;
use base64::Engine as _;

/// Public-key algorithm 1: RSA (encrypt or sign).
const RSA: u8 = 1;
/// Hash algorithm 10: SHA-512.
const SHA512: u8 = 10;

const TAG_SIGNATURE: u8 = 2;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_USER_ID: u8 = 13;

/// Signature type 0x00: a binary document. 0x01: canonical text. 0x13:
/// positive certification of a user ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigType {
    Binary = 0x00,
    Text = 0x01,
    PositiveCertification = 0x13,
}

/// Whatever holds the private key: KMS in production, a local key in tests.
///
/// `sign` is given the bytes to hash and returns an `RSASSA-PKCS1-v1_5`
/// signature over their SHA-512.
pub(crate) trait Signer {
    fn sign(&self, to_hash: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// An RSA public key as OpenPGP carries it.
#[derive(Debug, Clone)]
pub(crate) struct PublicKey {
    /// When the key was made. Part of the fingerprint, so it has to be the
    /// same every time the key is exported.
    pub(crate) created: u32,
    pub(crate) n: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl PublicKey {
    /// The public-key packet's body.
    #[must_use]
    pub(crate) fn body(&self) -> Vec<u8> {
        let mut b = vec![4];
        b.extend_from_slice(&self.created.to_be_bytes());
        b.push(RSA);
        b.extend(mpi(&self.n));
        b.extend(mpi(&self.e));
        b
    }

    /// The v4 fingerprint: SHA-1 over the key, which is what v4 defines it as.
    #[must_use]
    pub(crate) fn fingerprint(&self) -> [u8; 20] {
        let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(&key_hash_prefix(&self.body()));
        let mut out = [0; 20];
        out.copy_from_slice(ctx.finish().as_ref());
        out
    }

    /// The low 64 bits of the fingerprint.
    #[must_use]
    pub(crate) fn key_id(&self) -> [u8; 8] {
        let fpr = self.fingerprint();
        let mut id = [0; 8];
        id.copy_from_slice(&fpr[12..]);
        id
    }

    /// The transferable public key — the key, one user ID, and the key's own
    /// certification of it — armored, which is what goes in a keyring file.
    ///
    /// Certified at `now`; give it the key's creation time and the export is
    /// the same bytes every time, because PKCS#1 v1.5 signatures are
    /// deterministic.
    pub(crate) fn export(
        &self,
        user_id: &str,
        signer: &dyn Signer,
        now: u32,
    ) -> anyhow::Result<String> {
        Ok(armor(
            "PUBLIC KEY BLOCK",
            &self.certificate(user_id, signer, now)?,
        ))
    }

    /// [`PublicKey::export`] as packets, unarmored: a keyring `gpgv` reads.
    pub(crate) fn certificate(
        &self,
        user_id: &str,
        signer: &dyn Signer,
        now: u32,
    ) -> anyhow::Result<Vec<u8>> {
        let body = self.body();
        let mut to_hash = key_hash_prefix(&body);
        to_hash.push(0xB4);
        to_hash.extend_from_slice(&len32(user_id.len()));
        to_hash.extend_from_slice(user_id.as_bytes());

        let hashed = [
            subpacket(2, &now.to_be_bytes()),
            subpacket(33, &[&[4][..], &self.fingerprint()].concat()),
            // Certify and sign: it certifies its own user ID, and signs
            // repositories.
            subpacket(27, &[0x03]),
            // SHA-512, then SHA-256. Only the first is used here.
            subpacket(21, &[SHA512, 8]),
            subpacket(25, &[1]),
        ]
        .concat();
        let sig = signature(
            self,
            SigType::PositiveCertification,
            &hashed,
            &to_hash,
            signer,
        )?;

        let mut packets = packet(TAG_PUBLIC_KEY, &body);
        packets.extend(packet(TAG_USER_ID, user_id.as_bytes()));
        packets.extend(sig);
        Ok(packets)
    }

    /// A detached signature over `data`, armored: `Release.gpg`,
    /// `repomd.xml.asc`.
    pub(crate) fn detach_sign(
        &self,
        data: &[u8],
        signer: &dyn Signer,
        now: u32,
    ) -> anyhow::Result<String> {
        let sig = signature(self, SigType::Binary, &self.hashed(now), data, signer)?;
        Ok(armor("SIGNATURE", &sig))
    }

    /// `text` as a cleartext-signed message: `InRelease`.
    pub(crate) fn clear_sign(
        &self,
        text: &str,
        signer: &dyn Signer,
        now: u32,
    ) -> anyhow::Result<String> {
        let sig = signature(
            self,
            SigType::Text,
            &self.hashed(now),
            &canonical_text(text),
            signer,
        )?;
        let mut out = String::from("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n");
        for line in text.strip_suffix('\n').unwrap_or(text).split('\n') {
            if line.starts_with('-') {
                out.push_str("- ");
            }
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&armor("SIGNATURE", &sig));
        Ok(out)
    }

    fn hashed(&self, now: u32) -> Vec<u8> {
        [
            subpacket(2, &now.to_be_bytes()),
            subpacket(33, &[&[4][..], &self.fingerprint()].concat()),
        ]
        .concat()
    }
}

/// A v4 signature packet over `data` (already prefixed, for a certification).
fn signature(
    key: &PublicKey,
    kind: SigType,
    hashed: &[u8],
    data: &[u8],
    signer: &dyn Signer,
) -> anyhow::Result<Vec<u8>> {
    let hashed_len = u16::try_from(hashed.len())?;
    let mut head = vec![4, kind as u8, RSA, SHA512];
    head.extend_from_slice(&hashed_len.to_be_bytes());
    head.extend_from_slice(hashed);

    let mut trailer = vec![4, 0xFF];
    trailer.extend_from_slice(&len32(head.len()));

    let to_hash = [data, &head, &trailer].concat();
    let digest = digest::digest(&digest::SHA512, &to_hash);
    let rsa = signer.sign(&to_hash)?;

    let unhashed = subpacket(16, &key.key_id());
    let mut body = head;
    body.extend_from_slice(&u16::try_from(unhashed.len())?.to_be_bytes());
    body.extend(unhashed);
    body.extend_from_slice(&digest.as_ref()[..2]);
    body.extend(mpi(&rsa));
    Ok(packet(TAG_SIGNATURE, &body))
}

/// What a text signature hashes: lines ending CRLF, trailing spaces and tabs
/// removed, and no line ending after the last line — which in a cleartext
/// message belongs to the armor that follows it.
#[must_use]
pub(crate) fn canonical_text(text: &str) -> Vec<u8> {
    text.strip_suffix('\n')
        .unwrap_or(text)
        .split('\n')
        .map(|l| l.trim_end_matches([' ', '\t', '\r']))
        .collect::<Vec<_>>()
        .join("\r\n")
        .into_bytes()
}

fn key_hash_prefix(body: &[u8]) -> Vec<u8> {
    let mut p = vec![0x99];
    p.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
    p.extend_from_slice(body);
    p
}

fn len32(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes()
}

/// A multiprecision integer: its length in bits, then the big-endian bytes
/// with no leading zeros.
#[must_use]
pub(crate) fn mpi(bytes: &[u8]) -> Vec<u8> {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let bytes = &bytes[first..];
    let bits = match bytes.first() {
        Some(top) => (bytes.len() - 1) * 8 + 8 - usize::try_from(top.leading_zeros()).unwrap_or(0),
        None => 0,
    };
    let mut out = u16::try_from(bits)
        .unwrap_or(u16::MAX)
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(bytes);
    out
}

/// One subpacket, which here are all short.
fn subpacket(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::try_from(data.len() + 1).unwrap_or(u8::MAX), kind];
    out.extend_from_slice(data);
    out
}

/// A packet in the new format.
#[must_use]
pub(crate) fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xC0 | tag];
    let n = body.len();
    if n < 192 {
        out.push(u8::try_from(n).unwrap_or(0));
    } else if n < 8384 {
        let m = n - 192;
        out.push(u8::try_from((m >> 8) + 192).unwrap_or(0));
        out.push(u8::try_from(m & 0xFF).unwrap_or(0));
    } else {
        out.push(0xFF);
        out.extend_from_slice(&len32(n));
    }
    out.extend_from_slice(body);
    out
}

/// ASCII armor, with its CRC-24.
#[must_use]
pub(crate) fn armor(kind: &str, data: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    let body = b64.encode(data);
    let mut out = format!("-----BEGIN PGP {kind}-----\n\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push('=');
    out.push_str(&b64.encode(&crc24(data).to_be_bytes()[1..]));
    out.push_str("\n-----END PGP ");
    out.push_str(kind);
    out.push_str("-----\n");
    out
}

#[must_use]
pub(crate) fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00B7_04CE;
    for byte in data {
        crc ^= u32::from(*byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    crc & 0x00FF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_mpi_counts_bits_from_the_top_set_one() {
        assert_eq!(mpi(&[0x01]), vec![0, 1, 1]);
        assert_eq!(mpi(&[0x00, 0x01, 0x00, 0x01]), vec![0, 17, 1, 0, 1]);
        assert_eq!(mpi(&[0xFF]), vec![0, 8, 0xFF]);
    }

    #[test]
    fn packet_lengths_use_the_one_two_and_five_byte_forms() {
        assert_eq!(packet(2, &[0; 10])[..2], [0xC2, 10]);
        let two = packet(2, &[0; 1000]);
        assert_eq!(two[..3], [0xC2, 195, 40]);
        let five = packet(2, &[0; 10_000]);
        assert_eq!(five[..6], [0xC2, 0xFF, 0, 0, 0x27, 0x10]);
    }

    #[test]
    fn the_crc_is_rfc_4880s() {
        // The empty input is the initial value.
        assert_eq!(crc24(b""), 0x00B7_04CE);
        // Computed independently from the RFC's reference algorithm.
        assert_eq!(crc24(b"hello"), 0x0047_F58A);
    }

    #[test]
    fn text_is_hashed_with_crlf_no_trailing_space_and_no_final_newline() {
        assert_eq!(canonical_text("a  \nb\t\n"), b"a\r\nb".to_vec());
        assert_eq!(canonical_text("a\r\nb"), b"a\r\nb".to_vec());
    }
}
