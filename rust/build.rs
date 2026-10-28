use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// 递归列出目录下的文件。
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// 把前端构建产物 web/dist 嵌入二进制：生成 (路径, 内容) 表。未构建前端时嵌入一个提示页，
/// 便于只跑 Rust 测试的环境（如 CI 的 rust job）不依赖 Node.js。
fn embed_web() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dist = manifest.join("../web/dist");
    println!("cargo:rerun-if-changed={}", dist.display());
    let mut files = Vec::new();
    walk(&dist, &mut files);
    let mut code = String::from("pub static ASSETS: &[(&str, &[u8])] = &[\n");
    if dist.join("index.html").is_file() {
        for f in &files {
            let rel = f
                .strip_prefix(&dist)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let _ = writeln!(
                code,
                "    ({rel:?}, include_bytes!({:?})),",
                f.canonicalize().unwrap()
            );
        }
    } else {
        println!(
            "cargo:warning=web/dist 不存在，Web 面板将显示占位页；请先构建前端: cd web && npm ci && npm run build"
        );
        code.push_str(
            "    (\"index.html\", b\"<!doctype html><title>lport</title>\
             <p>Frontend not built: cd web &amp;&amp; npm ci &amp;&amp; npm run build\"),\n",
        );
    }
    code.push_str("];\n");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("web_assets.rs");
    std::fs::write(out, code).unwrap();
}

// 版本号：优先取 LPORT_VERSION 环境变量，其次 git describe，否则为 dev
fn main() {
    embed_web();
    println!("cargo:rerun-if-env-changed=LPORT_VERSION");
    if let Some(dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        let dir = Path::new(&dir);
        // HEAD 切换分支、当前分支有新提交、打 tag 或 gc 打包 ref 时重新计算
        let mut watch = vec![
            dir.join("HEAD"),
            dir.join("packed-refs"),
            dir.join("refs/tags"),
            dir.join("index"),
        ];
        if let Some(r) = git(&["symbolic-ref", "-q", "HEAD"]) {
            watch.push(dir.join(r));
        }
        // 不存在的路径会让 cargo 每次都重跑构建脚本，只监听已存在的
        for p in watch.iter().filter(|p| p.exists()) {
            println!("cargo:rerun-if-changed={}", p.display());
        }
        // 源码改动会改变 --dirty 标记
        println!("cargo:rerun-if-changed=src");
    }
    let version = std::env::var("LPORT_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| git(&["describe", "--tags", "--always", "--dirty"]))
        .unwrap_or_else(|| "dev".into());
    println!("cargo:rustc-env=LPORT_VERSION={version}");
}
