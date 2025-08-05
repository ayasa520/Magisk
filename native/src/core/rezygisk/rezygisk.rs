use base::{FsPathBuilder, ResultExt, Utf8CStr, cstr, info};
use std::fs::{self, File, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

static REZYGISK_ZIP: &[u8] = include_bytes!("rezygisk.zip");
const UTIL_F: &str = include_str!("util_functions.sh");
const MODULE_I: &str = include_str!("module_installer.sh");

pub fn extract_rezygisk_to(path: &PathBuf) -> std::io::Result<()> {
    remove_check(path)?;
    let mut file = File::create(path)?;
    file.write_all(REZYGISK_ZIP)?;
    Ok(())
}

pub fn install_rezygisk(rezygisk_path: &Path, secure_dir: &Utf8CStr) -> std::io::Result<()> {
    let moduleroot = crate::consts::MODULEROOT;
    let zygisk_module = PathBuf::from(moduleroot).join("rezygisk");
    remove_check(&zygisk_module)?;
    let module_installer = PathBuf::from(secure_dir).join("magisk/module_installer.sh");
    let util_functions = PathBuf::from(secure_dir).join("magisk/util_functions.sh");
    if (rezygisk_path.exists() && rezygisk_path.is_file())
        && (util_functions.exists() && util_functions.is_file())
    {
        if !module_installer.exists() || !module_installer.is_file() {
            remove_check(&module_installer)?;

            fs::write(&module_installer, MODULE_I)?;
            fs::set_permissions(&module_installer, Permissions::from_mode(0o755))?;
        }
        info!("* Injecting ReZygisk");
        let util_functions_str = fs::read_to_string(&util_functions)?;
        fs::write(&util_functions, UTIL_F)?;

        Command::new("sh")
            .args([
                &module_installer.to_string_lossy(),
                "/dev/null",
                "1",
                &rezygisk_path.to_string_lossy(),
            ])
            .output()?;

        fs::write(&util_functions, util_functions_str)?;

        remove_check(&rezygisk_path.to_path_buf())?;

        let installed = PathBuf::from("/data/local/tmp/rezygisk");
        remove_check(&installed)?;
        File::create(installed)?;
    }
    Ok(())
}

pub fn hide_rezygisk() -> std::io::Result<()> {
    while !std::path::Path::new("/proc").read_dir()?.any(|p| {
        if let Ok(entry) = p {
            if let Ok(cmdline) =
                std::fs::read_to_string(format!("{}/cmdline", entry.path().display()))
            {
                return cmdline.contains("com.android.shell");
            }
        }
        false
    }) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    let moduleroot = crate::consts::MODULEROOT;
    let rezygisk_dir = PathBuf::from(moduleroot).join("rezygisk");
    let module_prop = cstr::buf::default()
        .join_path(moduleroot)
        .join_path("rezygisk/module.prop");
    if module_prop.exists() {
        let mut millis = 0;
        while !module_prop.unmount().is_ok() {
            millis += 100;
            if millis >= 20000 {
                info!("rezygisk: failed to unmount \'{}\'\n", module_prop);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        //module_prop.unmount().log_ok();
    }
    remove_check(&rezygisk_dir)?;
    Ok(())
}

pub fn is_rezygisk() -> bool {
    let rezygisk = PathBuf::from(crate::consts::MODULEROOT).join("rezygisk");
    let installed = PathBuf::from("/data/local/tmp/rezygisk");
    let exists = rezygisk.exists() && (installed.exists() && installed.is_file());
    remove_check(&installed).log_ok();
    exists
}

pub fn remove_check(file: &PathBuf) -> std::io::Result<()> {
    if file.exists() {
        if file.is_dir() {
            fs::remove_dir_all(file.clone())?;
        } else {
            fs::remove_file(file.clone())?;
        }
    }
    Ok(())
}
