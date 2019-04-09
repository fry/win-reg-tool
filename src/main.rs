extern crate winreg;
#[macro_use]
extern crate log;
extern crate env_logger;

use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;

use std::ffi::OsStr;

use clap::{clap_app, crate_authors, crate_version, AppSettings};

static LOAD_KEY: &str = "_LoadedProfile";

fn reg_create_all_users(subkey: &OsStr, name: &OsStr, value: &OsStr) -> io::Result<()> {
    let hive_path = format!(r"HKU\{}", LOAD_KEY);

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hku = RegKey::predef(HKEY_USERS);

    info!("Loading profiles");
    let profiles =
        hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\")?;

    for profile_key in profiles.enum_keys().filter_map(|m| m.ok()) {
        info!("Attempting to load {}", &profile_key);
        let image_path: io::Result<String> = profiles
            .open_subkey(&profile_key)
            .and_then(|f| f.get_value("ProfileImagePath"));
        if let Ok(image_path) = image_path {
            let ntuser_path = Path::new(&image_path).join("NTUSER.DAT");
            let loaded_hive;
            // Ensure all the registry keys are closed before we unload the hive
            {
                // Check if the hive is already loaded for this user
                let existing_key = hku.open_subkey(&profile_key).ok();
                loaded_hive = existing_key.is_none();
                let load_key = match existing_key {
                    Some(load_key) => {
                        info!("Hive already loaded");
                        load_key
                    }
                    None => {
                        // Registry hive is not loaded yet, load it
                        info!(
                            "Loading registry hive {:?} for profile {} to {}",
                            ntuser_path, profile_key, hive_path
                        );
                        let output = Command::new("reg")
                            .arg("load")
                            .arg(&hive_path)
                            .arg(&ntuser_path)
                            .output()
                            .expect("failed to load registry hive");

                        if !output.status.success() {
                            error!("Failed to load");
                            io::stdout().write_all(&output.stdout).unwrap();
                            io::stdout().write_all(&output.stderr).unwrap();
                            continue;
                        }

                        hku.open_subkey(LOAD_KEY).expect("hive key to be loaded")
                    }
                };

                info!(
                    "Writing value {}\\{}",
                    subkey.to_string_lossy(),
                    name.to_string_lossy()
                );
                let (proofing_key, _) = load_key.create_subkey(subkey)?;

                proofing_key
                    .set_value(&name, &value)
                    .expect("setting value to succeed");
            }

            // Unload registry hive if we loaded it
            if loaded_hive {
                info!("Unloading hive");

                let output = Command::new("reg")
                    .arg("unload")
                    .arg(&hive_path)
                    .output()
                    .expect("failed to unload registry hive");

                if !output.status.success() {
                    error!("Failed to unload");
                    io::stdout().write_all(&output.stdout).unwrap();
                    io::stdout().write_all(&output.stderr).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                }
            }
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    env_logger::init();

    let matches = clap_app!(app =>
        (version: crate_version!())
		(author: crate_authors!())
        (about: "Helps dealing with the Windows registry")
        (setting: AppSettings::SubcommandRequiredElseHelp)
        (@subcommand all_users =>
            (about: "Set a registry value for all users on the system by loading their corresponding registry hive")
            (@arg SUB_KEY: -k --key +required +takes_value "The subkey to set a value in")
            (@arg NAME: -n --name +required +takes_value "Name of the value to set")
            (@arg VALUE: -v --value +required +takes_value "Value to set")
        )
    ).get_matches();

    match matches.subcommand() {
        ("all_users", Some(matches)) => {
            let subkey = matches.value_of_os("SUB_KEY").expect("sub key to be set");
            let name = matches.value_of_os("NAME").expect("name to be set");
            let value = matches.value_of_os("VALUE").expect("value to bet set");

            return reg_create_all_users(subkey, name, value);
        }
        _ => eprintln!("Invalid subcommand"),
    }

    Ok(())
}
