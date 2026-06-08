use std::process::Command;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let dashboard_dir = std::path::Path::new(&manifest_dir).join("dashboard");
    let dist_dir = dashboard_dir.join("dist");
    let skip = std::env::var("LAYERHOUSE_SKIP_DASHBOARD")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);

    println!("cargo::rerun-if-changed=dashboard/src");
    println!("cargo::rerun-if-changed=dashboard/public");
    println!("cargo::rerun-if-changed=dashboard/static");
    println!("cargo::rerun-if-changed=dashboard/vite.config.ts");
    println!("cargo::rerun-if-changed=dashboard/package.json");
    println!("cargo::rerun-if-env-changed=LAYERHOUSE_SKIP_DASHBOARD");

    if skip {
        std::fs::create_dir_all(&dist_dir).ok();
        std::fs::write(
            dist_dir.join("index.html"),
            "<!DOCTYPE html><html><head><title>layerhouse</title></head>\
             <body><h1>layerhouse</h1><p>Dashboard not built. \
             <code>LAYERHOUSE_SKIP_DASHBOARD=1</code> was set.</p></body></html>",
        )
        .expect("failed to write stub index.html");
        return;
    }

    // Check for vp (vite-plus) in PATH
    if Command::new("vp").arg("--version").output().is_err() {
        // In debug builds, this is a warning. In release, it's fatal.
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!(
                "vp (vite-plus) not found. Install it to build the dashboard, \
                 or set LAYERHOUSE_SKIP_DASHBOARD=1 for a headless build. \
                 See README#dashboard-setup."
            );
        } else {
            println!(
                "cargo::warning=vp (vite-plus) not found — dashboard won't be built. \
                 Set LAYERHOUSE_SKIP_DASHBOARD=1 to suppress this warning."
            );
            std::fs::create_dir_all(&dist_dir).ok();
            std::fs::write(
                dist_dir.join("index.html"),
                "<!DOCTYPE html><html><head><title>layerhouse</title></head>\
                 <body><h1>layerhouse</h1><p>Dashboard not built — vp not found.</p></body></html>",
            )
            .expect("failed to write stub index.html");
            return;
        }
    }

    // Run vp install if node_modules is missing
    if !dashboard_dir.join("node_modules").exists() {
        let status = Command::new("vp")
            .arg("install")
            .current_dir(&dashboard_dir)
            .status()
            .expect("failed to run vp install");
        if !status.success() {
            panic!("vp install failed in dashboard/");
        }
    }

    // Run vp build
    let status = Command::new("vp")
        .arg("build")
        .current_dir(&dashboard_dir)
        .status()
        .expect("failed to run vp build");

    if !status.success() {
        panic!("vp build failed in dashboard/");
    }

    // Verify dist/ was produced
    if !dist_dir.join("index.html").exists() {
        panic!("vp build succeeded but dashboard/dist/index.html was not produced");
    }
}
