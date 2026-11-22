fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match vorda::cli::run(&args) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            let usage = error.is_usage();
            let command = if args.first().is_some_and(|s| s == "--state") {
                args.get(2)
            } else {
                args.first()
            };
            // `link` hides result data behind the class; a usage error holds only the command line.
            let message = if !usage && command.is_some_and(|s| s == "link") {
                error.class
            } else {
                error.message
            };
            eprintln!(
                "{}",
                serde_json::json!({"error": message, "status": if usage { "usage_error" } else { "unknown" }})
            );
            std::process::exit(if usage { 64 } else { 2 });
        }
    }
}
