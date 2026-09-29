//! Run a release upgrade by hand, as a `dist_upgrade` job would, printing
//! the job log: `dist_upgrade 13`. For rehearsing on a throwaway VM
//! (DAWG-150, DAWG-151, DAWG-154); it changes the host exactly as the job
//! does. `dist_upgrade --check 24.04` changes nothing and prints what a
//! preflight's `release_upgrade` check would.

use updawg_backends::{LogSink, PackageBackend, apt::AptBackend};

struct Print;

impl LogSink for Print {
    fn line(&self, line: &str) {
        println!("{line}");
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (check, target) = match args.as_slice() {
        [flag, target] if flag == "--check" => (true, target.clone()),
        [target] => (false, target.clone()),
        _ => {
            eprintln!("usage: dist_upgrade [--check] <target release>");
            std::process::exit(2);
        }
    };
    if check {
        match AptBackend::new().release_upgrade_blockers(&target).await {
            Ok(none) if none.is_empty() => println!("nothing stands in the way"),
            Ok(found) => {
                for why in found {
                    println!("refused: {why}");
                }
                std::process::exit(1);
            }
            Err(error) => {
                println!("could not ask: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    match AptBackend::new().dist_upgrade(&target, &Print).await {
        Ok(done) => println!(
            "succeeded: {} package(s) changed, reboot required: {}",
            done.changed.len(),
            done.reboot_required
        ),
        Err(error) => {
            println!("{error}");
            std::process::exit(1);
        }
    }
}
