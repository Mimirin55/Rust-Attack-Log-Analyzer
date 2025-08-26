use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use colored::*;

fn main() -> std::io::Result<()> {
    let file = File::open("access.log").expect("ログファイルが見つかりません");
    let reader = BufReader::new(file);

    let mut total_ip_counter: HashMap<String, usize> = HashMap::new();
    let mut login_fail_counter: HashMap<String, usize> = HashMap::new();

    for line in reader.lines() {
        let log = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        let log = log.trim();
        if log.is_empty() { continue; }

        let ip = match log.split_whitespace().next() {
            Some(tok) => tok.to_string(),
            None => continue,
        };

        // --- 簡易ブルートフォース検知（/login への 401 を累計）---
        if log.contains("POST /login") && log.contains(" 401 ") {
            let cnt = login_fail_counter.entry(ip.clone()).or_insert(0);
            *cnt += 1;
            if *cnt >= 5 {
                println!(
                "{} {}",
                "[警告]".red().bold(),
                format!("ブルートフォースの可能性: {}", log)
            );
            }
        }

        // --- SQLインジェクションっぽいパターン（超簡易）---
        let lower = log.to_lowercase();
        if lower.contains("1=1") || lower.contains("'--") || lower.contains("' or '1'='1") || lower.contains("union select") {
            println!(
                "{} {}",
                "[警告]".yellow().bold(),
                format!("SQLインジェクション疑い: {}", log)
            );
        }

        // --- OSコマンドインジェクションっぽい記号（URLエンコード考慮を少しだけ）---
        if lower.contains(';') || lower.contains("&&") || lower.contains("%3b") || lower.contains("%26%26") {
            println!(
                "{} {}",
                "[警告]".magenta().bold(),
                format!("OSコマンドインジェクション疑い: {}", log)
            );
        }

        // --- 簡易DDoS（同一IPの総アクセス数）---
        let total = total_ip_counter.entry(ip.clone()).or_insert(0);
        *total += 1;
        if *total >= 100 {
            println!(
                "{} {}",
                "[警告]".bright_red().bold(),
                format!("簡易DDoS疑い: {}", log)
            );
        }
    }

    Ok(())
}
