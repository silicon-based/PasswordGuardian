use std::path::Path;

use rusqlite::Connection;

use super::logindata::LoginData;
use super::error::DataStorageError;


pub fn database_connection(path: &Path) -> Result<Connection, DataStorageError> {
    if !path.exists() {
        return Err(DataStorageError::FileNotFound {
            path: path.to_path_buf(),
        });
    }
    Ok(Connection::open(path)?)
}

pub fn create_table(connection: &Connection) -> Result<(), DataStorageError> {
    _ = 'a';
    connection
        .execute(
            "CREATE TABLE IF NOT EXISTS Accounts (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            date_modified TEXT NOT NULL,
            password TEXT NOT NULL
        )",
            (),
        )
        .map_err(|e| DataStorageError::DatabaseError { cause: e })?;
    Ok(())
}

pub fn insert_login(connection: &Connection, login: LoginData) {
    connection.execute(
        "INSERT INTO Accounts (name, username, date_modified, password) VALUES (?1, ?2, ?3, ?4)",
        [&login.name, &login.username, &login.date_modified, &login.password]
    ).unwrap();
}

pub fn delete_login(connection: &Connection, id: usize) -> Result<(), DataStorageError> {
    connection.execute("DELETE FROM Accounts WHERE ID = ?1", [id])?;
    connection.execute("UPDATE Accounts SET Id = Id - 1 WHERE Id > ?1", [id])?;
    Ok(())
}

pub fn retrieve_all(connection: &Connection) -> Result<Vec<LoginData>, DataStorageError> {
    let mut sql = connection.prepare("SELECT * FROM Accounts").unwrap();
    let logins_iter = sql
        .query_map([], |row| {
            Ok(LoginData {
                id: row.get(0)?,
                name: row.get(1)?,
                username: row.get(2)?,
                date_modified: row.get(3)?,
                password: row.get(4)?,
            })
        })
        .unwrap();
    let mut logins = Vec::new();
    for name_result in logins_iter {
        logins.push(name_result?);
    }

    Ok(logins)
}
