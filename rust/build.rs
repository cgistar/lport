use std::path::Path;
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

// 版本号：优先取 LPORT_VERSION 环境变量，其次 git describe，否则为 dev
fn main() {
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
