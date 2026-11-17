use std::env;
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { eprintln!("Usage: extract_w3i <archive.w3x>"); return; }
    let archive = storm_rs::MpqArchive::open(&args[1]).expect("open");
    let data = archive.read_file("war3map.w3i").expect("read w3i");
    // Dump raw JSON
    let json_bytes = serde_json::to_string_pretty(
        &serde_json::json!({"size": data.len(), "hex_head": format!("{:02x?}", &data[..32.min(data.len())])})
    ).unwrap();
    println!("{json_bytes}");
}

