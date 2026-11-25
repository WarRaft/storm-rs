use super::*;
use crate::archive::{AddFileOptions, MpqArchiveBuilder, MpqArchiveWriter, MpqCreateOptions};

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("storm-compact-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Bytes that don't compress much, `n` of them.
fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761).max(1);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[test]
fn a_maps_copy_compacted_without_its_names() {
    let dir = temp("map");
    let mpq = dir.join("plain.mpq");
    let key_v2 = MPQ_FILE_EXISTS | MPQ_FILE_ENCRYPTED | MPQ_FILE_KEY_V2;
    // Several sectors, compressed: its key found from its sector offset table.
    let script = [b"function main takes nothing returns nothing\n".repeat(300), noise(9000, 1)].concat();
    // One unit, a WAVE's start: its key found from it.
    let mut wave = b"RIFF".to_vec();
    wave.extend((6000u32 - 8).to_le_bytes());
    wave.extend(noise(5992, 2));
    let old = noise(20000, 3);
    // Uncompressed, in sectors (a key each), past one sector.
    let mut long_wave = b"RIFF".to_vec();
    long_wave.extend((10000u32 - 8).to_le_bytes());
    long_wave.extend(noise(9992, 7));
    MpqArchiveBuilder::new(&mpq)
        .options(MpqCreateOptions::v1().create_listfile(false).create_attributes(true).max_files(64))
        .add_file("old.txt", old.clone())
        .add_file_with_flags("war3map.j", script.clone(), key_v2 | MPQ_FILE_COMPRESS)
        .add_file_with_flags("sound.wav", wave.clone(), key_v2 | MPQ_FILE_SINGLE_UNIT)
        .add_file("kept.txt", noise(3000, 4))
        .add_file_with_flags("long.wav", long_wave.clone(), key_v2)
        .build()
        .unwrap();
    // A map: its 512-byte header before the archive.
    let map = dir.join("map.w3x");
    let mut prefix = b"HM3W".to_vec();
    prefix.resize(512, 7);
    fs::write(&map, [prefix.clone(), fs::read(&mpq).unwrap()].concat()).unwrap();
    // A file replaced: its old space left behind.
    let mut w = MpqArchiveWriter::open(&map).unwrap();
    w.remove_file("old.txt").unwrap();
    w.add_file("old.txt", b"new", &AddFileOptions::default()).unwrap();
    w.finish().unwrap();
    let before = fs::metadata(&map).unwrap().len();
    let place = |name: &str| {
        let a = MpqArchive::open(&map).unwrap();
        let (i, _) = crate::archive::find_file_entry(&a.hash_table, &a.block_table, name, 0).unwrap();
        a.block_table[i as usize].file_pos
    };
    let (script_was, wave_was) = (place("war3map.j"), place("sound.wav"));

    compact_archive(&map).unwrap();
    let after = fs::read(&map).unwrap();
    assert!((after.len() as u64) < before - 15000, "{before} -> {}", after.len());
    assert_eq!(&after[..512], prefix.as_slice());
    // Every file as it was; the encrypted ones at new places, keys and all.
    assert!(place("war3map.j") < script_was && place("sound.wav") < wave_was);
    let a = MpqArchive::open(&map).unwrap();
    assert_eq!(a.read_file("war3map.j").unwrap(), script);
    assert_eq!(a.read_file("sound.wav").unwrap(), wave);
    assert_eq!(a.read_file("old.txt").unwrap(), b"new");
    assert_eq!(a.read_file("kept.txt").unwrap(), noise(3000, 4));
    assert_eq!(a.read_file("long.wav").unwrap(), long_wave);
    // And again: nothing to give back, the same files.
    compact_archive(&map).unwrap();
    assert_eq!(MpqArchive::open(&map).unwrap().read_file("war3map.j").unwrap(), script);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_key_leaves_the_archive_as_it_was() {
    let dir = temp("unknown");
    let mpq = dir.join("a.mpq");
    // One unit, encrypted, no known start: no key without its name.
    MpqArchiveBuilder::new(&mpq)
        .options(MpqCreateOptions::v1().create_listfile(false).max_files(16))
        .add_file("first.txt", noise(4000, 5))
        .add_file_with_flags("secret.bin", noise(3000, 6), MPQ_FILE_EXISTS | MPQ_FILE_ENCRYPTED | MPQ_FILE_KEY_V2 | MPQ_FILE_SINGLE_UNIT)
        .build()
        .unwrap();
    let mut w = MpqArchiveWriter::open(&mpq).unwrap();
    w.remove_file("first.txt").unwrap();
    w.finish().unwrap();
    let was = fs::read(&mpq).unwrap();
    let err = compact_archive(&mpq).unwrap_err().to_string();
    assert!(err.contains("can't be moved"), "{err}");
    assert_eq!(fs::read(&mpq).unwrap(), was);
    let _ = fs::remove_dir_all(&dir);
}

/// Real maps (`MAPS`, paths `:`-separated): each copied, compacted, and
/// every file it lists read the same.
#[test]
#[ignore]
fn real_maps_compact_to_the_same_files() {
    let maps = std::env::var("MAPS").expect("MAPS");
    let dir = temp("real");
    for (k, map) in maps.split(':').enumerate() {
        let copy = dir.join(format!("{k}.w3x"));
        fs::copy(map, &copy).unwrap();
        let was = MpqArchive::open(map).unwrap();
        println!(
            "{map}: offset {} header {} hash {} (read {}) at {}, block {} (read {}) at {}, archive {}",
            was.mpq_offset, was.header.header_size, was.header.hash_table_size, was.hash_table.len(), was.header.hash_table_pos,
            was.header.block_table_size, was.block_table.len(), was.header.block_table_pos, was.header.archive_size
        );
        let names = was.list_files();
        let before = fs::metadata(&copy).unwrap().len();
        match compact_archive(&copy) {
            Ok(()) => {
                let now = MpqArchive::open(&copy).unwrap();
                let mut same = 0;
                for n in &names {
                    match (was.read_file(n), now.read_file(n)) {
                        (Ok(a), Ok(b)) => {
                            assert!(a == b, "{map}: {n} differs");
                            same += 1;
                        }
                        (Err(_), Err(_)) => {}
                        (a, b) => panic!("{map}: {n}: before {:?}, after {:?}", a.map(|v| v.len()), b.map(|v| v.len())),
                    }
                }
                println!("{map}: {before} -> {} bytes, {same} of {} files the same", fs::metadata(&copy).unwrap().len(), names.len());
            }
            Err(e) => println!("{map}: not compacted: {e}"),
        }
    }
    let _ = fs::remove_dir_all(&dir);
}
