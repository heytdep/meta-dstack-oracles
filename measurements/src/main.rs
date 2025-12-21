use std::env;
use std::fs;
use std::process;

use sha2::Digest;

fn aggregate_pods(pods: Vec<[u8; 48]>) -> Vec<u8> {
    pods.concat().to_vec()
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("Usage: measurements <pod1> <pod2> ...");
        process::exit(1);
    }

    let mut loaded_pods = Vec::new();

    for path in &args {
        if let Ok(pod_config) = fs::read(path) {
            let pod_hash: [u8; 48] = sha2::Sha384::digest(&pod_config).try_into().unwrap();
            loaded_pods.push(pod_hash);
        } else {
            println!("warn: file doesn't exist")
        }
    }

    let aggregated = aggregate_pods(loaded_pods);
    println!("Measurement: {}", hex::encode(aggregated));
}
