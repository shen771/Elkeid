use std::sync::{Arc, Mutex};
use std::fmt;
use std::collections::HashMap;

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json;
use log::*;

use super::utils::generate_timestamp_f64;

lazy_static! {
    pub static ref PROBE_CONFIG: Arc<Mutex<ProbeConfig>> =
        Arc::new(Mutex::new(ProbeConfig::default()));
    pub static ref PROBE_CONFIG_FLAG: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProbeData {
    args: Option<Vec<String>>,
    method_id: Option<u32>,
    class_id: Option<u32>,
    stack_trace: Option<Vec<String>>,
    pub action: Option<u32>,
    pub config: Option<String>,
    pub jars: Option<Vec<JarData>>,
    pub golang: Option<GolangDepData>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GolangDepData {
    pub deps: Option<Vec<GolangDep>>,
    pub main: Option<Vec<GolangDep>>,
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GolangDep {
    pub path: Option<String>,
    pub sum: Option<String>,
    pub version: Option<String>,
    pub replace: Option<GolangReplace>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GolangReplace {
    pub path: Option<String>,
    pub sum: Option<String>,
    pub version: Option<String>,
}


impl ProbeData {
    pub fn new_config(config_string: String) -> Self {
        let mut pd = ProbeData::default();
        pd.config = Some(config_string);
        pd
    }

    pub fn new_action(action: u32) -> Self {
        let mut pd = ProbeData::default();
        pd.action = Some(action);
        pd
    }
    pub fn to_hashmap(self) -> HashMap::<&'static str, String> {
        let mut pdhm = HashMap::<&'static str, String>::new();
        if let Some(args) = self.args {
            pdhm.insert("args", serde_json::json!(args).to_string());
        }
        if let Some(method_id) = self.method_id {
            pdhm.insert("method_id", method_id.to_string());
        }
        if let Some(class_id) = self.class_id {
            pdhm.insert("class_id", class_id.to_string());
        }
        if let Some(stack_trace) = self.stack_trace {
            pdhm.insert("stack_trace", serde_json::json!(stack_trace).to_string());
        }
        if let Some(jars) = self.jars {
            pdhm.insert("jars", serde_json::json!(jars).to_string());
        }
        pdhm
    }

}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JarData {
    path: String,
    implementation_title: Option<String>,
    implementation_version: Option<String>,
    specification_tittle: Option<String>,
    specification_version: Option<String>,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProbeConfig {
    pub config: Option<String>,
    pub action: Option<u32>,
}

impl ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            config: None,
            action: None,
        }
    }
}

pub fn message_handle(message: &String) -> Result<String, String> {
    // parse message
    let message = match Message::from(message) {
        Ok(m) => m,
        Err(e) => {
            return Err(e.to_string());
        }
    };
    debug!("Message: {}", message);
    let response = match message.message_type {
        1 => match heartbeat_handle(&message.clone()) {
            Ok(resp) => resp,
            Err(e) => {
                return Err(e);
            }
        },
        2 => match probe_report(&message.clone()) {
            Some(e) => {
                return Err(e);
            }
            None => String::new(),
        },
        5 =>  match jar_report(&message.clone()) {
            Ok(_) => String::new(),
            Err(e) => {
                return Err(e)
            }
        }
        _ => return Err(String::from("bad message type")),
    };
    Ok(response)
}
pub fn jar_report(message: &Message) -> Result<String, String> {
    let msg = message.clone();
    let response = serde_json::json!(msg).to_string();
    println!("jar:{}", response);
    Ok(String::new())
}

pub fn heartbeat_handle(message: &Message) -> Result<String, String> {
    let msg = message.clone();
    let response = serde_json::json!(msg).to_string();
    println!("heart_beat:{}", response);
    Ok(response)
}

pub fn probe_report(message: &Message) -> Option<String> {
    let msg = message.clone();
    let response = serde_json::json!(msg).to_string();
    println!("probe_report:{}", response);
    None
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    pid: i32,
    runtime: String,
    runtime_version: String,
    probe_version: String,
    message_type: u32,
    time: f64,
    data: Option<ProbeData>,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, {}, {}, {}, {}, ProbeData: {:?})",
            self.pid,
            self.message_type,
            self.runtime,
            self.runtime_version,
            self.probe_version,
            self.data,
        )
    }
}

impl fmt::Display for ProbeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({:?})", self.args)
    }
}

impl Message {
    pub fn from(message_string: &String) -> Result<Self, String> {
        info!("new mesage from: {}", message_string);
        let message_struct = match serde_json::from_str(message_string.as_str()) {
            Ok(m) => m,
            Err(e) => {
                return Err(e.to_string());
            }
        };
        Ok(message_struct)
    }
    pub fn default() -> Self {
        Message {
            pid: 0,
            runtime: String::new(),
            runtime_version: String::new(),
            probe_version: String::new(),
            message_type: 0,
            time: generate_timestamp_f64(),
            data: None,
        }
    }
    pub fn new_config(config_string: &String) -> Self {
        let probe_data = ProbeData::new_config(config_string.clone());
        let mut new_message = Message::default();
        new_message.data = Some(probe_data);
        new_message.message_type = 3;
        new_message
    }

    pub fn new_action(action: u32) -> Self {
        let probe_data = ProbeData::new_action(action);
        let mut new_message = Message::default();
        new_message.data = Some(probe_data);
        new_message.message_type = 4;
        new_message
    }
    pub fn to_json(&self) -> String {
        serde_json::json!(&self).to_string()
    }
    pub fn to_hashmap(self) -> HashMap::<&'static str, String> {
        let mut mhm = HashMap::<&'static str, String>::new();
        mhm.insert("pid", self.pid.to_string());
        mhm.insert("runtime", self.runtime);
        mhm.insert("runtime_version", self.runtime_version);
        mhm.insert("message_type", self.message_type.to_string());
        mhm.insert("rasp_timestamp", self.time.to_string());
        if let Some(data) = self.data {
            let probe_data_map = data.to_hashmap();
            mhm.extend(probe_data_map);
        }
        mhm
    }

}
