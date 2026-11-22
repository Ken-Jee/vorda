// The XML parser hands text broken at character and entity references to Vorda in several
// pieces; an Ubuntu OVAL severity must still be read as one value.
use vorda::scanner::distro::ubuntu_records;

fn oval(severity: &str) -> String {
    format!(
        "<oval_definitions><definitions><definition><metadata>\
         <reference source=\"CVE\" ref_id=\"CVE-2024-1000\"/>\
         <advisory><severity>{severity}</severity></advisory></metadata>\
         <criteria><criterion comment=\"linux package in noble, was vulnerable but has been fixed (note: '6.8.0-41.41').\"/></criteria>\
         </definition></definitions></oval_definitions>"
    )
}

#[test]
fn a_severity_split_by_references_is_read_whole() {
    for text in ["Low", "Lo&#119;", "&#76;ow", " L&#x6F;w ", "Lo&#119;&#32;"] {
        let records = ubuntu_records(oval(text).as_bytes()).unwrap();
        assert_eq!(records[0]["severity"], "low", "{text}");
    }
    let records = ubuntu_records(oval("High &amp; urgent").as_bytes()).unwrap();
    assert_eq!(records[0]["severity"], "high & urgent");
}
