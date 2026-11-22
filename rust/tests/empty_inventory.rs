use serde_json::{json, Value};
use vorda::{
    domain::Package,
    scanner::feeds::{self, FeedSource},
    Error, Result,
};

struct UnavailableFeed(Vec<String>);
impl FeedSource for UnavailableFeed {
    fn get(&mut self, url: &str, _: Option<&Value>) -> Result<Value> {
        self.0.push(url.into());
        Err(Error::new("fixture unavailable"))
    }
}

#[test]
fn empty_inventory_makes_no_advisory_requests() {
    let mut feed = UnavailableFeed(vec![]);
    let result = feeds::scan(&[], &mut feed).unwrap();
    assert!(feed.0.is_empty());
    assert_eq!(result["errors"], json!([]));
    assert_eq!(result["covered"], json!([]));
    let package: Package = serde_json::from_value(json!({"name":"example","version":"1.2.3","ecosystem":"npm","path":"package.json","scope":"runtime"})).unwrap();
    let result = feeds::scan(&[package], &mut feed).unwrap();
    assert!(feed.0.iter().any(|url| url.ends_with("/querybatch")));
    assert!(!result["errors"].as_array().unwrap().is_empty());
}
