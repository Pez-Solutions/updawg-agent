//! Just enough DER parsing to pull the modulus and exponent out of an RSA
//! `SubjectPublicKeyInfo` (what KMS returns) and the PKCS#1 `RSAPublicKey`
//! inside it.

use anyhow::{bail, ensure};

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
/// OID 1.2.840.113549.1.1.1 (rsaEncryption), DER-encoded.
const RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];

/// Returns `(tag, contents, rest)` for the first element in `der`.
fn element(der: &[u8]) -> anyhow::Result<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("DER ended early"))?;
    let (&first, rest) = rest
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("DER ended early"))?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7F);
        ensure!(
            (1..=4).contains(&n) && rest.len() >= n,
            "a DER length this cannot read"
        );
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    ensure!(rest.len() >= len, "DER ended early");
    Ok((tag, &rest[..len], &rest[len..]))
}

pub(crate) fn rsa_public_key(der: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (tag, seq, _) = element(der)?;
    ensure!(tag == SEQUENCE, "not an RSAPublicKey");
    let (tag, n, rest) = element(seq)?;
    ensure!(tag == INTEGER, "no modulus");
    let (tag, e, _) = element(rest)?;
    ensure!(tag == INTEGER, "no exponent");
    Ok((n.to_vec(), e.to_vec()))
}

pub(crate) fn rsa_spki(der: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let (tag, spki, _) = element(der)?;
    ensure!(tag == SEQUENCE, "not a SubjectPublicKeyInfo");
    let (tag, algorithm, rest) = element(spki)?;
    ensure!(tag == SEQUENCE, "no algorithm");
    if !algorithm.starts_with(RSA_ENCRYPTION) {
        bail!("not an RSA key");
    }
    let (tag, bits, _) = element(rest)?;
    ensure!(tag == BIT_STRING && bits.first() == Some(&0), "no key bits");
    rsa_public_key(&bits[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_rsa_spki_gives_up_its_modulus_and_exponent() {
        // A toy key: n = 0x00C5 (with its sign byte), e = 65537.
        let rsa = [
            0x30, 0x09, 0x02, 0x02, 0x00, 0xC5, 0x02, 0x03, 0x01, 0x00, 0x01,
        ];
        let mut bits = vec![0x03, 0x0C, 0x00];
        bits.extend_from_slice(&rsa);
        let mut inner = vec![
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        inner.extend(bits);
        let mut spki = vec![0x30, u8::try_from(inner.len()).unwrap()];
        spki.extend(inner);

        let (n, e) = rsa_spki(&spki).unwrap();
        assert_eq!(n, vec![0x00, 0xC5]);
        assert_eq!(e, vec![0x01, 0x00, 0x01]);
        assert!(
            rsa_spki(&rsa).is_err(),
            "a bare RSAPublicKey is not an SPKI"
        );
    }
}
