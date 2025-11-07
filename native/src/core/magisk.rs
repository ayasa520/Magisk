use crate::consts::{APPLET_NAMES, DEVICEDIR, INTERNAL_DIR, MAGISK_PROC_CON, MAGISK_VER_CODE, MAGISK_VERSION, POST_FS_DATA_WAIT_TIME};
use crate::daemon::connect_daemon;
use crate::ffi::{RequestCode, denylist_cli, get_magisk_tmp, install_module, mount_sbin, tmpfs_mount, unlock_blocks};
use crate::mount::find_preinit_device;
use crate::selinux::restorecon;
use crate::socket::{Decodable, Encodable};
use argh::FromArgs;
use base::{CmdArgs, EarlyExitExt, LoggedResult, Utf8CString, argh, clone_attr, cstr};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use std::ffi::c_char;
use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::exit;

/// 在指定路径创建 applet 符号链接
fn install_applet(path: &str) -> LoggedResult<()> {
    let path_obj = std::path::Path::new(path);
    
    // 为每个 applet 创建符号链接
    for name in APPLET_NAMES {
        let link_path = path_obj.join(name);
        let _ = fs::remove_file(&link_path); // 删除可能存在的旧链接
        symlink("./magisk", &link_path)?;
    }
    
    // 创建 supolicy 符号链接
    let supolicy_path = path_obj.join("supolicy");
    let _ = fs::remove_file(&supolicy_path);
    symlink("./magiskpolicy", &supolicy_path)?;
    
    Ok(())
}

fn print_usage() {
    eprintln!(
        r#"Magisk - Multi-purpose Utility

Usage: magisk [applet [arguments]...]
   or: magisk [options]...

Options:
   -c                        print current binary version
   -v                        print running daemon version
   -V                        print running daemon version code
   --list                    list all available applets
   --remove-modules [-n]     remove all modules, reboot if -n is not provided
   --install-module ZIP      install a module zip file

Advanced Options (Internal APIs):
   --daemon                  manually start magisk daemon
   --stop                    remove all magisk changes and stop daemon
   --[init trigger]          callback on init triggers. Valid triggers:
                             post-fs-data, service, boot-complete, zygote-restart
   --unlock-blocks           set BLKROSET flag to OFF for all block devices
   --restorecon              restore selinux context on Magisk files
   --clone-attr SRC DEST     clone permission, owner, and selinux context
   --clone SRC DEST          clone SRC to DEST
   --sqlite SQL              exec SQL commands to Magisk database
   --path                    print Magisk tmpfs mount path
   --denylist ARGS           denylist config CLI
   --preinit-device          resolve a device to store preinit files

Available applets:
     {}
"#,
        APPLET_NAMES.join(", ")
    );
}

#[derive(FromArgs)]
struct Cli {
    #[argh(subcommand)]
    action: MagiskAction,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum MagiskAction {
    LocalVersion(LocalVersion),
    Version(Version),
    VersionCode(VersionCode),
    List(ListApplets),
    RemoveModules(RemoveModules),
    InstallModule(InstallModule),
    Daemon(StartDaemon),
    Stop(StopDaemon),
    PostFsData(PostFsData),
    Service(ServiceCmd),
    BootComplete(BootComplete),
    ZygoteRestart(ZygoteRestart),
    UnlockBlocks(UnlockBlocks),
    RestoreCon(RestoreCon),
    CloneAttr(CloneAttr),
    CloneFile(CloneFile),
    Sqlite(Sqlite),
    Path(PathCmd),
    DenyList(DenyList),
    PreInitDevice(PreInitDevice),
    MountSbin(MountSbin),
    SetupSbin(SetupSbin),
    Install(InstallApplets),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "-c")]
struct LocalVersion {}

#[derive(FromArgs)]
#[argh(subcommand, name = "-v")]
struct Version {}

#[derive(FromArgs)]
#[argh(subcommand, name = "-V")]
struct VersionCode {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--list")]
struct ListApplets {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--remove-modules")]
struct RemoveModules {
    #[argh(switch, short = 'n')]
    no_reboot: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "--install-module")]
struct InstallModule {
    #[argh(positional)]
    zip: Utf8CString,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "--daemon")]
struct StartDaemon {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--stop")]
struct StopDaemon {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--post-fs-data")]
struct PostFsData {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--service")]
struct ServiceCmd {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--boot-complete")]
struct BootComplete {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--zygote-restart")]
struct ZygoteRestart {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--unlock-blocks")]
struct UnlockBlocks {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--restorecon")]
struct RestoreCon {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--clone-attr")]
struct CloneAttr {
    #[argh(positional)]
    from: Utf8CString,
    #[argh(positional)]
    to: Utf8CString,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "--clone")]
struct CloneFile {
    #[argh(positional)]
    from: Utf8CString,
    #[argh(positional)]
    to: Utf8CString,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "--sqlite")]
struct Sqlite {
    #[argh(positional)]
    sql: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "--path")]
struct PathCmd {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--denylist")]
struct DenyList {
    #[argh(positional, greedy)]
    args: Vec<String>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "--preinit-device")]
struct PreInitDevice {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--mount-sbin")]
struct MountSbin {}

#[derive(FromArgs)]
#[argh(subcommand, name = "--setup-sbin")]
struct SetupSbin {
    #[argh(positional)]
    source_dir: Utf8CString,
    #[argh(positional)]
    target_dir: Option<Utf8CString>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "--install")]
struct InstallApplets {
    #[argh(positional)]
    path: Option<Utf8CString>,
}

impl MagiskAction {
    fn exec(self) -> LoggedResult<i32> {
        use MagiskAction::*;
        match self {
            LocalVersion(_) => {
                #[cfg(debug_assertions)]
                println!("{MAGISK_VERSION}:MAGISK:D ({MAGISK_VER_CODE})");
                #[cfg(not(debug_assertions))]
                println!("{MAGISK_VERSION}:MAGISK:R ({MAGISK_VER_CODE})");
            }
            Version(_) => {
                let mut fd = connect_daemon(RequestCode::CHECK_VERSION, false)?;
                let ver = String::decode(&mut fd)?;
                println!("{ver}");
            }
            VersionCode(_) => {
                let mut fd = connect_daemon(RequestCode::CHECK_VERSION_CODE, false)?;
                let ver = i32::decode(&mut fd)?;
                println!("{ver}");
            }
            List(_) => {
                for name in APPLET_NAMES {
                    println!("{name}");
                }
            }
            RemoveModules(self::RemoveModules { no_reboot }) => {
                let mut fd = connect_daemon(RequestCode::REMOVE_MODULES, false)?;
                let do_reboot = !no_reboot;
                do_reboot.encode(&mut fd)?;
                return Ok(i32::decode(&mut fd)?);
            }
            InstallModule(self::InstallModule { zip }) => {
                install_module(&zip);
            }
            Daemon(_) => {
                let _ = connect_daemon(RequestCode::START_DAEMON, true)?;
            }
            Stop(_) => {
                let mut fd = connect_daemon(RequestCode::STOP_DAEMON, false)?;
                return Ok(i32::decode(&mut fd)?);
            }
            PostFsData(_) => {
                let fd = connect_daemon(RequestCode::POST_FS_DATA, true)?;
                let mut pfd = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
                nix::poll::poll(
                    &mut pfd,
                    PollTimeout::try_from(POST_FS_DATA_WAIT_TIME * 1000)?,
                )?;
            }
            Service(_) => {
                let _ = connect_daemon(RequestCode::LATE_START, true)?;
            }
            BootComplete(_) => {
                let _ = connect_daemon(RequestCode::BOOT_COMPLETE, false)?;
            }
            ZygoteRestart(_) => {
                let _ = connect_daemon(RequestCode::ZYGOTE_RESTART, false)?;
            }
            UnlockBlocks(_) => {
                unlock_blocks();
            }
            RestoreCon(_) => {
                restorecon();
            }
            CloneAttr(self::CloneAttr { from, to }) => {
                clone_attr(&from, &to)?;
            }
            CloneFile(self::CloneFile { from, to }) => {
                from.copy_to(&to)?;
            }
            Sqlite(self::Sqlite { sql }) => {
                let mut fd = connect_daemon(RequestCode::SQLITE_CMD, false)?;
                sql.encode(&mut fd)?;
                loop {
                    let line = String::decode(&mut fd)?;
                    if line.is_empty() {
                        return Ok(0);
                    }
                    println!("{line}");
                }
            }
            Path(_) => {
                let tmp = get_magisk_tmp();
                if tmp.is_empty() {
                    return Ok(1);
                } else {
                    println!("{tmp}");
                }
            }
            DenyList(self::DenyList { mut args }) => {
                return Ok(denylist_cli(&mut args));
            }
            PreInitDevice(_) => {
                let name = find_preinit_device();
                if name.is_empty() {
                    return Ok(1);
                } else {
                    println!("{name}");
                }
            }
            MountSbin(_) => {
                return Ok(mount_sbin());
            }
            SetupSbin(self::SetupSbin { source_dir, target_dir }) => {
                let magisk_tmp_cstr;
                let magisk_tmp = if let Some(ref dir) = target_dir {
                    magisk_tmp_cstr = dir;
                    magisk_tmp_cstr.as_str()
                } else {
                    "/sbin"
                };
                
                if magisk_tmp == "/sbin" {
                    if mount_sbin() != 0 {
                        return Ok(-1);
                    }
                } else {
                    let magisk_tmp_ref = target_dir.as_ref().unwrap();
                    if tmpfs_mount(cstr!("magisk"), magisk_tmp_ref) != 0 {
                        return Ok(-1);
                    }
                }
                
                let bins = ["magisk", "magisk32", "magiskpolicy", "stub.apk"];
                for bin in &bins {
                    let src = Utf8CString::from(format!("{}/{}", source_dir, bin));
                    let dest = Utf8CString::from(format!("{}/{}", magisk_tmp, bin));
                    
                    if std::path::Path::new(src.as_str()).exists() {
                        src.copy_to(&dest)?;
                        let _ = fs::set_permissions(dest.as_str(), fs::Permissions::from_mode(0o755));
                    }
                }
                
                std::env::set_current_dir(magisk_tmp)?;
                
                cstr!(INTERNAL_DIR).mkdir(0o755)?;
                cstr!(DEVICEDIR).mkdir(0o711)?;

                install_applet(magisk_tmp)?;
            }
            Install(self::InstallApplets { path }) => {
                let install_path = path
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("/sbin");
                install_applet(install_path)?;
            }
        };
        Ok(0)
    }
}

pub fn magisk_main(argc: i32, argv: *mut *mut c_char) -> i32 {
    if argc < 2 {
        print_usage();
        exit(1);
    }
    
    let mut cmds = CmdArgs::new(argc, argv.cast()).0;
    
    if cmds.len() >= 2 && cmds[1] == "--auto-selinux" {
        use std::fs::OpenOptions;
        use std::io::{Read, Write, Seek, SeekFrom};
        
        if let Ok(mut file) = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/proc/self/attr/current")
        {
            if file.write_all(MAGISK_PROC_CON.as_bytes()).is_ok() {
                let _ = file.seek(SeekFrom::Start(0));
                let mut current_con = [0u8; 128];
                if let Ok(n) = file.read(&mut current_con) {
                    if let Ok(con_str) = std::str::from_utf8(&current_con[..n]) {
                        eprintln!("SeLinux context: {}", con_str.trim_end_matches('\0'));
                    }
                }
            } else {
                let _ = file.seek(SeekFrom::Start(0));
                if file.write_all(b"u:r:su:s0").is_ok() {
                    let _ = file.seek(SeekFrom::Start(0));
                    let mut current_con = [0u8; 128];
                    if let Ok(n) = file.read(&mut current_con) {
                        if let Ok(con_str) = std::str::from_utf8(&current_con[..n]) {
                            eprintln!("SeLinux context: {}", con_str.trim_end_matches('\0'));
                        }
                    }
                }
            }
        }
        
        cmds.remove(1);
    }
    
    if cmds.len() < 2 {
        print_usage();
        exit(1);
    }
    
    // We need to manually inject "--" so that all actions can be treated as subcommands
    cmds.insert(1, "--");
    let cli = Cli::from_args(&cmds[..1], &cmds[1..]).on_early_exit(print_usage);
    cli.action.exec().unwrap_or(1)
}
