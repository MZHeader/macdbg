// Benign file and HTTP(S) probe; only loopback and the reserved test name are accepted.
use std::{env, fs, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 4, "url scratch certificate");
    let url = reqwest::Url::parse(&args[1])?;
    assert!(matches!(url.host_str(), Some("127.0.0.1" | "connectivity.macdbg.invalid")));
    let path = format!("{}/rust-analyst-marker.txt", args[2]);
    fs::write(&path, b"benign-rust-file-content")?;
    println!("FILE:{}", fs::read_to_string(&path)?);
    let mut builder = reqwest::blocking::Client::builder()
        .no_proxy()
        .http1_only()
        .timeout(Duration::from_secs(30));
    if args[3] != "-" {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&fs::read(&args[3])?)?);
    }
    let response = builder.build()?.post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Macdbg-Fixture", "benign-rust")
        .body("language=rust&marker=benign-analyst-payload")
        .send()?;
    let status = response.status();
    let body = response.text()?;
    println!("RESULT:{status} {body}");
    assert_eq!(status, 200);
    assert_eq!(body, "fixture-online");
    Ok(())
}
