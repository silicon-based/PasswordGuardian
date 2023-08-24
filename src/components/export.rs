use super::logindata;
use super::cryptography::encryption;
use std::error::Error;
use csv::Writer;

pub fn decrypt_and_export<'a, I>(data: I, cipher: &encryption::Cipher) -> Result<(), Box<dyn Error>>
where
    I: Iterator<Item = &'a logindata::LoginData>,
{
    let mut wtr = Writer::from_path("passwords.csv")?;

    wtr.write_record(["name", "username", "password", "date"])?;

    for item in data {        
        let password =
            String::from_utf8(cipher.decrypt(&item.password)?)?;
        wtr.write_record([&item.name, &item.username, &password, &item.date_modified])?;
    };
    
    wtr.flush()?;
    Ok(())
}
