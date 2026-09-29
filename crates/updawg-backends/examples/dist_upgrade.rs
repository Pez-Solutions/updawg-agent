//! Run a release upgrade by hand, as a `dist_upgrade` job would, printing
//! the job log: `dist_upgrade 13`. For rehearsing on a throwaway VM
//! (DAWG-151, DAWG-154); it changes the host exactly as the job does.

use updawg_backends::{LogSink, PackageBackend, apt::AptBackend};

struct Print;

impl LogSink for Print {
    fn line(&self, line: &str) {
        println!("{line}");
    }
}

#[tokio::main]
async fn main() {
    let Some(target) = std::env::args().nth(1) else {
        eprintln!("usage: dist_upgrade <target release>");
        std::process::exit(2);
    };
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
