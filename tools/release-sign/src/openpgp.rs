//! The subset of OpenPGP (RFC 4880, v4) needed to sign a package repository:
//! an RSA public key with one user ID, plus detached and cleartext
//! signatures, all SHA-512.
//!
//! OpenPGP libraries expect to hold the private key, and ours lives in Cloud
//! KMS. Building the packets around a KMS signature is only a few hundred
//! lines.
//!
//! KMS's `RSA_SIGN_PKCS1_4096_SHA512` uses the same PKCS#1 v1.5 `DigestInfo`
//! encoding as OpenPGP RSA signatures, so its output goes into the signature
//! MPI unchanged.

use aws_lc_rs::digest;
use base64::Engine as _;

/// Public-key algorithm 1: RSA (encrypt or sign).
const RSA: u8 = 1;
/// Hash algorithm 10: SHA-512.
const SHA512: u8 = 10;

const TAG_SIGNATURE: u8 = 2;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_USER_ID: u8 = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigType {
    Binary = 0x00,
    Text = 0x01,
    PositiveCertification = 0x13,
}

/// KMS in production, a local key in tests. `sign` takes the bytes to hash
/// and returns an `RSASSA-PKCS1-v1_5` signature over their SHA-512.
pub(crate) trait Signer {
    fn sign(&self, to_hash: &[u8]) -> anyhow::Result<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub(crate) struct PublicKey {
    /// Part of the fingerprint, so it must not change between exports.
    pub(crate) created: u32,
    pub(crate) n: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl PublicKey {
    #[must_use]
    pub(crate) fn body(&self) -> Vec<u8> {
        let mut b = vec![4];
        b.extend_from_slice(&self.created.to_be_bytes());
        b.push(RSA);
        b.extend(mpi(&self.n));
        b.extend(mpi(&self.e));
        b
    }

    #[must_use]
    pub(crate) fn fingerprint(&self) -> [u8; 20] {
        let mut ctx = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(&key_hash_prefix(&self.body()));
        let mut out = [0; 20];
        out.copy_from_slice(ctx.finish().as_ref());
        out
    }

    #[must_use]
    pub(crate) fn key_id(&self) -> [u8; 8] {
        let fpr = self.fingerprint();
        let mut id = [0; 8];
        id.copy_from_slice(&fpr[12..]);
        id
    }

    /// The armored transferable public key (key, user ID, self-certification).
    ///
    /// PKCS#1 v1.5 signatures are deterministic, so passing the key's creation
    /// time as `now` makes the export byte-for-byte reproducible.
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

    /// [`PublicKey::export`] without the armor, as a keyring for `gpgv`.
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
            // certify + sign
            subpacket(27, &[0x03]),
            // preferred hashes: SHA-512, SHA-256
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

    /// Armored detached signature, for `Release.gpg` and `repomd.xml.asc`.
    pub(crate) fn detach_sign(
        &self,
        data: &[u8],
        signer: &dyn Signer,
        now: u32,
    ) -> anyhow::Result<String> {
        let sig = signature(self, SigType::Binary, &self.hashed(now), data, signer)?;
        Ok(armor("SIGNATURE", &sig))
    }

    /// Cleartext-signed message, for `InRelease`.
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

/// For a certification, `data` must already carry the key and user ID prefix.
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

/// CRLF line endings, trailing whitespace stripped, and no newline after the
/// last line (in a cleartext message that one belongs to the armor).
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

/// Bit length, then the big-endian bytes without leading zeros.
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

/// Assumes a one-byte length; ours are all short.
fn subpacket(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::try_from(data.len() + 1).unwrap_or(u8::MAX), kind];
    out.extend_from_slice(data);
    out
}

/// New-format packet header plus body.
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
        assert_eq!(crc24(b""), 0x00B7_04CE);
        // checked against the RFC reference implementation
        assert_eq!(crc24(b"hello"), 0x0047_F58A);
    }

    #[test]
    fn text_is_hashed_with_crlf_no_trailing_space_and_no_final_newline() {
        assert_eq!(canonical_text("a  \nb\t\n"), b"a\r\nb".to_vec());
        assert_eq!(canonical_text("a\r\nb"), b"a\r\nb".to_vec());
    }
}
