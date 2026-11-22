//! The allocation bound of the isolated transport, measured in a process of its own. The probe is a
//! process-wide `#[global_allocator]`, so it counts every thread's allocations while it observes;
//! beside the other transport tests it saw theirs. Alone in this binary only the server thread
//! and the peer of this test run during the window.
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    thread,
    time::Duration,
};
use vorda::link::{
    native::{self, Admission},
    server::Server,
    storage::Hub,
};

struct ObservedAllocator;
static OBSERVE: AtomicBool = AtomicBool::new(false);
static LARGEST: AtomicUsize = AtomicUsize::new(0);
unsafe impl std::alloc::GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if OBSERVE.load(Ordering::Relaxed) {
            LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        }
        std::alloc::System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        std::alloc::System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if OBSERVE.load(Ordering::Relaxed) {
            LARGEST.fetch_max(size, Ordering::Relaxed);
        }
        std::alloc::System.realloc(ptr, layout, size)
    }
}
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

const INVITE: &str = "synthetic-invite-only-0000000000000000000";
const DEVICE: &str = "synthetic-device-only-0000000000000000000";

fn status(response: &[u8]) -> u16 {
    std::str::from_utf8(response)
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn oversized_ambiguous_prefix_has_bounded_allocations() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("hub.db");
    let hub = Hub::open(&db).unwrap();
    hub.invite(INVITE, "test-org", "test-site", 60.0).unwrap();
    hub.enroll(INVITE, DEVICE).unwrap();
    native::migrate(&db).unwrap();
    let server = Server::bind(Hub::open(&db).unwrap(), "127.0.0.1", 0, None, None).unwrap();
    let addr = server.local_addr().unwrap();
    let admission = Admission::open(&db, vec![]).unwrap();
    let stop = AtomicBool::new(false);

    let mut raw = b"POST".to_vec();
    raw.resize(60000, b' ');
    raw.extend(b"/unknown x\n");
    thread::scope(|scope| {
        let server_thread = scope.spawn(|| server.serve_bounded(&admission, &stop).unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut peer = TcpStream::connect(addr).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
            LARGEST.store(0, Ordering::SeqCst);
            OBSERVE.store(true, Ordering::SeqCst);
            peer.write_all(&raw).unwrap();
            let mut response = Vec::new();
            peer.read_to_end(&mut response).unwrap();
            OBSERVE.store(false, Ordering::SeqCst);
            let largest = LARGEST.load(Ordering::SeqCst);
            assert_eq!(status(&response), 404);
            assert!(largest <= 16384, "oversized line allocation: {largest}");
        }));
        stop.store(true, Ordering::Release);
        server_thread.join().unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    });

    let counts = rusqlite::Connection::open(&db).unwrap();
    for table in [
        "v2_deliveries",
        "v2_views",
        "v2_assessments",
        "v2_observations",
    ] {
        let rows: i64 = counts
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "{table}");
    }
}
