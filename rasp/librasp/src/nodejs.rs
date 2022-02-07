use std::{
    collections::HashMap, ffi::OsString, process::Command, thread::sleep,
    time::Duration,
};

use crate::process::ProcessInfo;
use crate::settings;

use anyhow::{anyhow, Result};
use log::*;
// use npm_package_json::Package;
use regex::Regex;
// use version_compare::{CompOp, VersionCompare};


pub fn nodejs_attach(
    pid: i32,
    _environ: &HashMap<OsString, OsString>,
    node_path: &str,
) -> Result<bool> {
    debug!("node attach: {}", pid);
    let smith_module_path = settings::RASP_NODE_MODULE;
    nodejs_run(pid, node_path, smith_module_path)
}

pub fn nodejs_run(pid: i32, node_path: &str, smith_module_path: &'static str) -> Result<bool> {
    let pid_string = pid.to_string();
    let nsenter = settings::RASP_NS_ENTER_BIN.to_string();
    let inject_script_path = settings::RASP_NODE_INJECTOR;
    let nspid = match ProcessInfo::read_ns_pid(pid) {
        Ok(nspid_option) => {
            if let Some(nspid) = nspid_option {
                nspid
            } else {
                pid
            }
        }
        Err(e) => {
            return Err(anyhow!(e));
        }
    };
    let nspid_string = nspid.clone().to_string();
    let require_module = format!("require('{}')", smith_module_path);
    let args = [
        "-m",
        "-n",
        "-p",
        "-t",
        pid_string.as_str(),
        node_path,
        inject_script_path,
        nspid_string.as_str(),
        require_module.as_str(),
    ];
    return match Command::new(nsenter).args(&args).status() {
        Ok(st) => {
            // wait inejct code done, then close debug
            sleep(Duration::from_secs(1));
            Ok(st.success())
        }
        Err(e) => Err(anyhow!(e.to_string())),
    };
}

pub fn nodejs_version(pid: i32, nodejs_bin_path: &String) -> Result<(u32, u32, String)> {
    // exec nodejs
    let nsenter = settings::RASP_NS_ENTER_BIN.to_string();
    let pid_string = pid.to_string();
    let args = [
	"-m",
	"-n",
	"-p",
	"-t",
	pid_string.as_str(),
	nodejs_bin_path,
	"-v"
    ];
    let output = match Command::new(nsenter).args(&args).output() {
        Ok(s) => s,
        Err(e) => return Err(anyhow!(e.to_string())),
    };
    let output_string = String::from_utf8(output.stdout).unwrap_or(String::new());
    if output_string.is_empty() {
        return Err(anyhow!("empty stdout"));
    }
    // parse nodejs version
    let re = Regex::new(r"v((\d+)\.(\d+)\.\d+)").unwrap();
    let (major, minor, version) = match re.captures(&output_string) {
        Some(c) => {
            let major = c.get(2).map_or("", |m| m.as_str());
            let minor = c.get(3).map_or("", |m| m.as_str());
            let version = c.get(1).map_or("", |m| m.as_str());
            (major, minor, version)
        }
        None => return Err(anyhow!(String::from("can not find version"))),
    };
    let major_number = match major.parse::<u32>() {
        Ok(n) => n,
        Err(e) => return Err(anyhow!(e.to_string())),
    };
    let minor_number = match minor.parse::<u32>() {
        Ok(n) => n,
        Err(e) => return Err(anyhow!(e.to_string())),
    };
    Ok((major_number, minor_number, String::from(version)))
}
