//! CRC32C (Castagnoli), for the Cloud KMS integrity fields.
//!
//! Cloud KMS checks a CRC32C of each request field it is given, and returns
//! one of each response field. This is the table-driven, reflected CRC with
//! polynomial `0x82F63B78`, initial value and final XOR `0xFFFFFFFF`
//! (RFC 3720, appendix B.4).

/// The reflected Castagnoli polynomial.
const POLYNOMIAL: u32 = 0x82F6_3B78;

const fn table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut crc = n as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[n] = crc;
        n += 1;
    }
    table
}

const TABLE: [u32; 256] = table();

/// The CRC32C of `bytes`.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc = TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        // The check value of CRC-32C, and RFC 3720 B.4's test vectors.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
        let ascending: Vec<u8> = (0u8..32).collect();
        assert_eq!(crc32c(&ascending), 0x46DD_794E);
        let descending: Vec<u8> = (0u8..32).rev().collect();
        assert_eq!(crc32c(&descending), 0x113F_DB5C);
    }
}
