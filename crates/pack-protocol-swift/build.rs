use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from("./generated");

    swift_bridge_build::parse_bridges(vec![PathBuf::from("src/lib.rs")])
        .write_all_concatenated(out_dir.clone(), env!("CARGO_PKG_NAME"));

    // swift-bridge codegen bug: when a Result-returning function takes &str params,
    // the generated toRustStr closure contains `try` but the toRustStr call itself
    // is missing `try`. Our PackBridgeExtensions.swift provides a throwing overload
    // of toRustStr, but call sites still need `try`. Fix it by replacing
    // `return <name>.toRustStr({` with `return try <name>.toRustStr({` when the
    // closure body contains `try`.
    let swift_file = out_dir
        .join(env!("CARGO_PKG_NAME"))
        .join(format!("{}.swift", env!("CARGO_PKG_NAME")));
    if let Ok(contents) = std::fs::read_to_string(&swift_file) {
        let fixed = fix_try_in_to_rust_str(&contents);
        if fixed != contents {
            std::fs::write(&swift_file, fixed).expect("failed to write patched swift bridge");
        }
    }
}

fn fix_try_in_to_rust_str(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut result = Vec::with_capacity(lines.len());

    for (i, line) in lines.iter().enumerate() {
        if line.contains(".toRustStr(") && !line.contains("try ") {
            let has_try_below = lines[i + 1..]
                .iter()
                .take(5)
                .any(|l| l.trim_start().starts_with("try ") || l.contains("try {"));
            if has_try_below {
                let patched = line.replace("return ", "return try ");
                result.push(patched);
                continue;
            }
        }
        result.push(line.to_string());
    }

    let mut out = result.join("\n");
    if input.ends_with('\n') {
        out.push('\n');
    }
    out
}
