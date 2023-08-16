use prettytable::{
    format::{FormatBuilder, LinePosition, LineSeparator},
    Table,
};
use std::io::{self, Write};

use super::database;

pub fn input(message: &str, allow_empty: bool) -> String {
    print!("{message}");
    io::stdout().flush().unwrap();
    let mut value = String::new();
    loop {
        if io::stdin().read_line(&mut value).is_ok() && (!value.is_empty() || allow_empty) {
            return value.trim().to_owned();
        }
    }
}

pub fn init_master_password() -> String {
    loop {
        println!("Welcome! Let's create your master password first.");
        let password = rpassword::prompt_password("Create a master password: ").unwrap();
        if rpassword::prompt_password("Retype password: ").unwrap() == password {
            println!("Thank you! Now you can continue. Have a nice day!\n");
            return password;
        } else {
            println!("Password not match. Please try again\n");
        }
    }
}

pub fn main_menu_text() {
    println!("Hi there! Select an operation:");
    println!("  ▶ insert\tInsert new item to the database");
    println!("  ▶ display\tDisplay all accounts");
    println!("  ▶ search\tSearch for an item");
    println!("  ▶ (number)\tSelect the item with ID (number) to apply actions");
    println!("  ▶ quit\tQuit the program");
}

pub fn main_menu_selection_prompt() {
    print!("Select an operation [insert/display/search/(number)/quit]: ");
    io::stdout().flush().unwrap();
}

pub fn item_operation_prompt(id: usize, name: &str) {
    println!("Select an operation on item no.{} ({}) :", id, name);
    println!("  ▶ remove\tRemove this item");
    println!("  ▶ update\tUpdate information of this item");
    println!("  ▶ password\tPrint the decrypted password");
    println!("Any other keys to get back.");
    print!("Select operation [remove/update/password]: ");
    io::stdout().flush().unwrap();
}

pub fn print_table<'a, I>(data: I)
where
    I: Iterator<Item = &'a database::LoginData>,
{
    let mut table = Table::new();
    let format = FormatBuilder::new()
        .column_separator('│')
        .borders('│')
        .separators(&[LinePosition::Top], LineSeparator::new('─', '┬', '┌', '┐'))
        .separators(
            &[LinePosition::Title],
            LineSeparator::new('═', '╪', '╞', '╡'),
        )
        .separators(
            &[LinePosition::Intern],
            LineSeparator::new('─', '┼', '├', '┤'),
        )
        .separators(
            &[LinePosition::Bottom],
            LineSeparator::new('─', '┴', '└', '┘'),
        )
        .padding(1, 1)
        .build();
    table.set_format(format);
    table.set_titles(row!["ID", "LOGIN", "USERNAME", "DATE MODIFIED"]);
    for item in data {
        table.add_row(row![
            &item.id,
            &item.name,
            &item.username,
            &item.date_modified
        ]);
    }
    table.printstd();
}
