#![feature(if_let_guard)]

#[macro_use]
extern crate prettytable;

mod components;
use components::cryptography::encryption::Cipher;
use components::logindata::LoginData;
use components::{console, cryptography::*, database, error, export, metadata::Metadata};

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process;

use aes_kw::KekAes256;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::time::{self, Duration};

/// Lazily handles unrecoverable errors.
/// Receives an `Result` where `E`  `std::fmt::Display`.
/// Print and return exit code 1 when `Err`, unwrap and return content when `Ok`.
macro_rules! unrecoverable {
    ($result:expr) => {
        match $result {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        }
    };
}

/// Wrapper of `run`. Makes sure that things are propperly configured.
#[tokio::main]
async fn main() {
    // Prepare: Define variables
    let folder_path = PathBuf::from("./data/");

    let mut database_path = folder_path.clone();
    database_path.push("data.db");

    let mut metadata_path = folder_path.clone();
    metadata_path.push("encryption.json");

    if !database_path.exists() && !metadata_path.exists() {
        initialize(&metadata_path, &database_path);
    }
    let exit_code = run(&metadata_path, &database_path).await;
    process::exit(exit_code);
}

/// The main logic.
/// Ask for master password and enters read-eval-print loop.
async fn run(metadata_path: &Path, database_path: &Path) -> i32 {
    // Connect to database and read metadata file;
    let context = unrecoverable!(Metadata::from_file(metadata_path));
    let conn = unrecoverable!(database::database_connection(database_path));

    // Check master password.
    let mut incorrect_counter = 0;
    let cipher = loop {
        let password = rpassword::prompt_password("Master Password: ").unwrap();
        let kek = kdf::derive_kek(&password, &unrecoverable!(context.kek_salt()));
        match encryption::Cipher::from_unwrap(kek, unrecoverable!(context.wrap())) {
            Ok(c) => break c,
            Err(_) => {
                incorrect_counter += 1;
                if incorrect_counter == 3 {
                    eprintln!("\nPassword Manager: 3 incorrect password attempts.");
                    return 1;
                }
                println!("Sorry, try again.\n");
            }
        };
    };

    repl(&cipher, &conn).await
}

// REPL: Handle operations queries
async fn repl(cipher: &Cipher, conn: &rusqlite::Connection) -> i32 {
    let stdin = io::stdin();
    let handle = BufReader::new(stdin);
    let timeout_duration = Duration::from_secs(120);

    let mut lines = handle.lines();

    let mut selection: Option<LoginData> = None;
    print!("\x1B[2J\x1B[1;1H");

    let data = unrecoverable!(database::retrieve_all(conn));
    loop {
        println!();

        // If user has already chosen an item
        if let Some(item) = selection.take() {
            console::print_table([&item].into_iter());
            console::item_operation_prompt(item.id, &item.name);

            // Read input
            // Terminate if reached timeout before next user input
            let line = tokio::select! {
                line = lines.next_line() => line.unwrap().unwrap_or(String::new()),
                _ = time::sleep(timeout_duration) => {
                    eprintln!("\nPassword Manager: Timeout reached, aborting.");
                    return 1;
                }
            };
            match line.trim() {
                "remove" => {
                    unrecoverable!(database::delete_login(conn, item.id));
                    println!("Item removed successfully")
                }
                "update" => {
                    todo!()
                }
                "password" => {
                    let password =
                        String::from_utf8(cipher.decrypt(&item.password).unwrap()).unwrap();
                    println!("The password is as follow:\n{}", password);
                }
                _ => println!("Back to main menu.\n"),
            }
        // Main menu if use has not selected item to operate
        } else {
            console::main_menu_text();
            console::main_menu_selection_prompt();

            // Read input
            // Terminate if reached timeout before next user input
            let line = tokio::select! {
                line = lines.next_line() => line.unwrap().unwrap_or(String::new()),
                _ = time::sleep(timeout_duration) => {
                    eprintln!("\nPassword Manager: Timeout reached, aborting.");
                    return 1;
                }
            };

            match line.trim() {
                // Insert login
                "insert" => {
                    println!();
                    let handler = tokio::spawn(async {
                        time::sleep(Duration::from_secs(60)).await;
                        eprintln!("\nPassword Manager: Timeout reached, aborting.");
                        process::exit(1)
                    });
                    let name = console::input("Login name: ", false);
                    let username = console::input("Email: ", false);
                    let password = loop {
                        let password = rpassword::prompt_password("Password: ").unwrap();
                        if rpassword::prompt_password("Retype password: ").unwrap() != password {
                            println!("Password not match. Please try again.\n");
                        } else {
                            break password;
                        }
                    };
                    let encrypted_password = cipher.encrypt(password.as_bytes());
                    handler.abort();
                    database::insert_login(conn, LoginData::new(name, username, encrypted_password));
                },
                "display" => {
                    console::print_table(data.iter());
                },
                "export" => {
                    match export::decrypt_and_export(data.iter(), cipher) {
                        Ok(_) => println!("Passwords successfully exported to `password.csv`"),
                        Err(e) => println!("ERROR: Unable to export due to {e}")
                    }
                }
                "search" => {
                    todo!()
                },
                "quit" => {
                    println!("Exit.");
                    break 0
                },

                // If user selects an item
                x if let Ok(index) = x.parse::<usize>() => {
                    if index <= data.len() {
                        selection = Some(data[index - 1].clone());
                    } else {
                        eprintln!("Invalid index");
                    }
                },
                _ => println!("Invalid option"),
            }
        }
    }
}

pub fn initialize(metadata_path: &Path, database_path: &Path) {
    File::create(metadata_path).unwrap();
    File::create(database_path).unwrap();

    let conn = database::database_connection(database_path).unwrap();
    database::create_table(&conn).unwrap();

    let master_password = console::init_master_password();
    let mut enc_key = encryption::Cipher::generate_key();
    let salt = generate_salt();
    let kek = KekAes256::new(&kdf::derive_kek(&master_password, &salt).into());

    let mut wrap = [0u8; 40];
    kek.wrap(
        &base64_url::decode(base64_url::escape_in_place(&mut enc_key)).unwrap(),
        &mut wrap,
    )
    .unwrap();

    let md = Metadata::new(base64_url::encode(&wrap), [base64_url::encode(&salt)]);

    md.write_metadata(metadata_path).unwrap();
}
