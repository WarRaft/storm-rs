//! Archives written by `MpqArchiveBuilder` read back byte for byte.

use storm_rs::archive::MpqArchiveBuilder;
use storm_rs::{MPQ_FILE_COMPRESS, MPQ_FILE_ENCRYPTED, MPQ_FILE_EXISTS, MpqArchive};

#[test]
fn builder_roundtrip() {
    let dir = std::env::temp_dir().join(format!("storm-rt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("t.mpq");

    let tiny = b"library L {}\n".to_vec();
    let small = b"function main takes nothing returns nothing\nendfunction\n".to_vec();
    // Several sectors, some compressible, some not.
    let mut big: Vec<u8> = (0..20_000u32).map(|i| (i % 7) as u8 + b'a').collect();
    big.extend((0..9_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
    let secret = big.clone();

    MpqArchiveBuilder::new(&path)
        .add_file("tiny.zn", tiny.clone())
        .add_file("war3map.j", small.clone())
        .add_file("Scripts\\big.j", big.clone())
        .add_file_with_flags("secret.j", secret.clone(), MPQ_FILE_EXISTS | MPQ_FILE_COMPRESS | MPQ_FILE_ENCRYPTED)
        .add_file("empty.j", Vec::new())
        .build()
        .unwrap();

    let a = MpqArchive::open(&path).unwrap();
    assert_eq!(a.read_file("tiny.zn").unwrap(), tiny);
    assert_eq!(a.read_file("war3map.j").unwrap(), small);
    assert_eq!(a.read_file("scripts/BIG.j").unwrap(), big);
    assert_eq!(a.read_file("secret.j").unwrap(), secret);
    assert_eq!(a.read_file("empty.j").unwrap(), Vec::<u8>::new());
    let _ = std::fs::remove_dir_all(&dir);
}
