use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::Path,
};

use anyhow::Result;
use clap::{arg, command, Parser, Subcommand};
use log::{error, info};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand, Debug)]
enum Action {
    Enable,
    Disable,
    #[command(subcommand)]
    Add(ActionCommand),
    #[command(subcommand)]
    Remove(ActionCommand),
    #[command(subcommand)]
    Change(ActionCommand),
}

#[derive(Debug, Subcommand)]
enum ActionCommand {
    #[command(name = "user-role", about = "set the user and corresponding role")]
    UserRole {
        #[arg(short, long)]
        user: String,
        #[arg(short, long)]
        role: String,
    },
    #[command(
        name = "role-permission",
        about = "set the role and corresponding permission"
    )]
    RolePermission {
        #[arg(short, long)]
        role: String,
        #[arg(short, long)]
        permission: String,
    },
}

static USER_ROLE_FILE: &'static str = "/tmp/mylsm/user_role";
static ROLE_PERMISSION_FILE: &'static str = "/tmp/mylsm/role_permission";
static ABILITY_FILE: &'static str = "/tmp/mylsm/ability";

fn change_ability(is_able: bool) -> Result<()> {
    let mut file = File::create(ABILITY_FILE)?;
    if is_able {
        file.write_all("y".as_bytes())?;
    } else {
        file.write_all("n".as_bytes())?;
    }
    Ok(())
}
fn read_key_value(file: &mut File) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let mut iter = line.split_whitespace();
        let key = iter.next().unwrap();
        let value = iter.next().unwrap();
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}

fn write_key_value(file: &mut File, map: &HashMap<String, String>) -> Result<()> {
    file.set_len(0)?;
    for (key, value) in map.iter() {
        // let num = i32::from_str_radix(key, 10);
        file.write_all(format!("{} {}\n", key, value).as_bytes())?;

        // if num.is_ok() {
        //     file.write_all(&num.unwrap().to_le_bytes())?;
        //     file.write_all(format!(" {}\n", value).as_bytes())?;
        // } else {
        // }
    }

    Ok(())
}
#[derive(Debug, PartialEq)]
enum ModifyType {
    Add,
    Remove,
    Change,
}
fn modify_key_value(
    file_path: &str,
    modify_type: ModifyType,
    key: &str,
    value: &str,
) -> Result<()> {
    let path = Path::new(file_path);
    // 文件不存在的时候可以添加用户，但是不能删除或改变
    if !path.is_file() && (modify_type == ModifyType::Remove || modify_type == ModifyType::Change) {
        return Err(anyhow::Error::msg("user-role file not create"));
    }
    let mut file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;
    // read the key-value
    let mut key_value = read_key_value(&mut file)?;
    // modify the key-value
    match modify_type {
        ModifyType::Add => {
            if key_value.contains_key(key) {
                return Err(anyhow::Error::msg(format!("user {} already exist", key)));
            } else {
                key_value.insert(key.to_string(), value.to_string());
            }
        }
        ModifyType::Remove => {
            if !key_value.contains_key(key) {
                return Err(anyhow::Error::msg(format!("user {} not exist ", key)));
            } else {
                key_value.remove(key);
            }
        }
        ModifyType::Change => {
            if !key_value.contains_key(key) {
                return Err(anyhow::Error::msg(format!("user {} not exist", key)));
            } else {
                *key_value.get_mut(key).unwrap() = value.to_string();
            }
        }
    }

    // write the key-value
    write_key_value(&mut file, &key_value)?;
    Ok(())
}
fn main() {
    let args = Cli::parse();
    match args.action {
        Action::Enable => match change_ability(true) {
            Ok(_) => {
                info!("enable ability success.");
            }
            Err(e) => {
                error!("enable ability error: {}", e);
            }
        },
        Action::Disable => match change_ability(false) {
            Ok(_) => {
                info!("disable ability success.");
            }
            Err(e) => {
                error!("disable ability error: {}.", e);
            }
        },

        Action::Add(command) => match command {
            ActionCommand::UserRole { user, role } => {
                match modify_key_value(USER_ROLE_FILE, ModifyType::Add, &user, &role) {
                    Ok(_) => info!("add user-role success."),
                    Err(e) => error!("add user-role error: {}", e),
                }
            }
            ActionCommand::RolePermission { role, permission } => {
                match modify_key_value(ROLE_PERMISSION_FILE, ModifyType::Add, &role, &permission) {
                    Ok(_) => info!("add role-permission success."),
                    Err(e) => error!("add role-permission error: {}", e),
                }
            }
        },
        Action::Remove(command) => match command {
            ActionCommand::UserRole { user, role } => {
                match modify_key_value(USER_ROLE_FILE, ModifyType::Remove, &user, &role) {
                    Ok(_) => info!("remove user-role success."),
                    Err(e) => error!("remove user-role error: {}", e),
                }
            }
            ActionCommand::RolePermission { role, permission } => {
                match modify_key_value(ROLE_PERMISSION_FILE, ModifyType::Remove, &role, &permission)
                {
                    Ok(_) => info!("remove role-permission success."),
                    Err(e) => error!("remove role-permission error: {}", e),
                }
            }
        },
        Action::Change(command) => match command {
            ActionCommand::UserRole { user, role } => {
                match modify_key_value(USER_ROLE_FILE, ModifyType::Change, &user, &role) {
                    Ok(_) => info!("change user-role success."),
                    Err(e) => error!("change user-role error: {}", e),
                }
            }
            ActionCommand::RolePermission { role, permission } => {
                match modify_key_value(ROLE_PERMISSION_FILE, ModifyType::Change, &role, &permission)
                {
                    Ok(_) => info!("change role-permission success."),
                    Err(e) => error!("change role-permission error: {}", e),
                }
            }
        },
    }
}
