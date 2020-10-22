extern crate base64;
extern crate clap;
extern crate crypto;
extern crate ini;
extern crate rand_core;
extern crate ctrlc;

use self::base64::{decode, encode};
use clap::{App, Arg};
use crypto::aes::{self, KeySize};
use crypto::buffer::{self, BufferResult, ReadBuffer, WriteBuffer};
use crypto::symmetriccipher::{Decryptor, SynchronousStreamCipher};
use ini::Ini;
use rand_core::{OsRng, RngCore};
use std::env;
use std::iter::repeat;
use std::process::{Command, Stdio};
use std::path::Path;
use std::io;

const FILEPATH: &str = "C:\\DataSources\\conf.ini";

fn verify_safe_write() -> bool {
    if Path::new(FILEPATH).exists() {
        println!("Configuration file already exist, do you want to overwrite? (y/n)");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Could not read user input");
        match input.chars().next().expect("Could not read user input") {
            'y' | 'Y' => true,
            'n' | 'N' => false,
            _ => {
                eprintln!("ParseError: Could not make sense of the input");
                std::process::exit(10);
            }
        }
    } else {
        true
    }
}

fn main() {
    ctrlc::set_handler(move || {
        println!("Received termination request\nTerminating...");
        std::process::exit(11)
    }).expect("Error setting Ctrl+C handler");
    let matches = App::new("Configuration Management")
        .version("0.1")
        .about("Configuration management for automated workflows")
        .subcommand(
            App::new("init")
                .about("Initialize a configuration file")
        )
        .subcommand(
            App::new("add")
                .about("Add new configuration section")
                .arg(
                    Arg::with_name("domain")
                        .short("d")
                        .help("Name for the configuration domain to add")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("username")
                        .short("u")
                        .help("Username for the technology")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("p")
                        .help("Password for the technology")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            App::new("edit")
                .about("Modify password of a configuration section")
                .arg(
                    Arg::with_name("domain")
                        .short("d")
                        .help("Name for the configuration domain to be modified")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("username")
                        .short("u")
                        .help("Username for the technology")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("p")
                        .help("Updated Password for the technology")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            App::new("delete")
                .about("Delete a configuration section")
                .arg(
                    Arg::with_name("domain")
                        .short("d")
                        .help("Name for the configuration domain to be modified")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            App::new("retrieve")
                .about("Retrive a configuration section")
                .arg(
                    Arg::with_name("domain")
                        .short("d")
                        .help("Name for the configuration domain to be modified")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .get_matches();

    
    match matches.subcommand() {
        ("init", _) => {
            if verify_safe_write() {
                // Generate a secret key and a nounce value with
                // a secure random generator
                let mut key: Vec<u8> = repeat(0u8).take(16).collect();
                OsRng.fill_bytes(&mut key[..]);
                let mut nounce: Vec<u8> = repeat(0u8).take(16).collect();
                OsRng.fill_bytes(&mut nounce[..]);
    
                Command::new("SETX")
                    .args(&["C_KEY", encode(&key).as_str()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("Unable to setup user env variables");
    
                Command::new("SETX")
                    .args(&["C_NOUNCE", encode(&nounce).as_str()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("Unable to setup user env variables");
    
                Command::new("cmd")
                    .arg("/C")
                    .arg(format!("SET C_KEY={}", encode(&key).as_str()))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("Unable to setup env variables");
    
                Command::new("cmd")
                    .arg("/C")
                    .arg(format!("SET C_NOUNCE={}", encode(&nounce).as_str()))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("Unable to setup env variables");
    
                // Initialize a template for `conf.ini`
                let conf = Ini::new();
                conf.write_to_file(FILEPATH).unwrap();
                println!("Configuration file initialized at: {}", FILEPATH);
                println!("Use `configstore.exe add <domain> <username> <password>` \
                    to add configurations")
            } else {
                println!("Configuration file located at: {}", FILEPATH);
                std::process::exit(10)
            }
        }
        ("add", Some(add_matches)) => {
            let mut conf = Ini::load_from_file(FILEPATH).unwrap();
            let _key = match env::var("C_KEY") {
                Ok(k) => k,
                Err(e) => {
                    println!(
                        "Essential ENV variables could not be read\n \
                    Try running the shell with elevated priviliges or \
                    restarting the shell."
                    );
                    eprintln!("Error: C_KEY {:?}", e);
                    std::process::exit(1)
                }
            };
            let _nounce = match env::var("C_NOUNCE") {
                Ok(k) => k,
                Err(e) => {
                    println!(
                        "Essential ENV variables could not be read\n \
                    Try running the shell with elevated priviliges or \
                    restarting the shell."
                    );
                    eprintln!("Error: C_NOUNCE {:?}", e);
                    std::process::exit(1)
                }
            };
            let key = decode(_key).unwrap();
            let nounce = decode(_nounce).unwrap();

            let mut cipher = aes::ctr(KeySize::KeySize128, &key, &nounce);
            let mut password: Vec<u8> = repeat(0u8)
                .take(add_matches.value_of("password").unwrap().len())
                .collect();
            cipher.process(
                add_matches.value_of("password").unwrap().as_bytes(),
                &mut password[..],
            );

            match conf.section(add_matches.value_of("domain")) {
                None => {
                    conf.with_section(add_matches.value_of("domain"))
                        .set("username", add_matches.value_of("username").unwrap())
                        .set("password", encode(&password).as_str());
                    conf.write_to_file(FILEPATH).unwrap();
                    println!(
                        "Configuration for {} has been added",
                        add_matches.value_of("domain").unwrap()
                    );
                }
                Some(d) => {
                    println!(
                        "Configuration already exists for {} with username {} \
                        \nRun 'confini.exe edit --help' for edit instructions",
                        add_matches.value_of("domain").unwrap(),
                        d.get("username").unwrap()
                    );
                }
            }
        }
        ("edit", Some(edit_matches)) => {
            let mut conf = Ini::load_from_file(FILEPATH).unwrap();

            let _key = "C_KEY";
            let _nounce = "C_NOUNCE";
            let key = decode(env::var(_key).unwrap()).unwrap();
            let nounce = decode(env::var(_nounce).unwrap()).unwrap();

            let mut cipher = aes::ctr(KeySize::KeySize128, &key, &nounce);
            let mut password: Vec<u8> = repeat(0u8)
                .take(edit_matches.value_of("password").unwrap().len())
                .collect();
            cipher.process(
                edit_matches.value_of("password").unwrap().as_bytes(),
                &mut password[..],
            );

            let domain_config = match conf.section_mut(edit_matches.value_of("domain")) {
                Some(s) => s,
                None => {
                    eprintln!(
                        "Configuration not found for domain: {}",
                        edit_matches.value_of("domain").unwrap()
                    );
                    std::process::exit(2)
                }
            };

            if edit_matches.is_present("username") {
                domain_config.insert(
                    "username", 
                    edit_matches.value_of("username").unwrap());
                domain_config.insert("password", encode(&password).as_str());
            } else {
                domain_config.insert("password", encode(&password).as_str());
            }
            conf.write_to_file(FILEPATH).unwrap();
            println!(
                "Configuration for {} has been updated",
                edit_matches.value_of("domain").unwrap()
            );
        }
        ("delete", Some(delete_matches)) => {
            let mut conf = Ini::load_from_file(FILEPATH).unwrap();
            conf.delete(delete_matches.value_of("domain"));
            conf.write_to_file(FILEPATH).unwrap();
            println!(
                "Configuration for {} has been deleted",
                delete_matches.value_of("domain").unwrap()
            );
        }
        ("retrieve", Some(retrieve_matches)) => {
            let conf = Ini::load_from_file(FILEPATH).unwrap();
            let _key = match env::var("C_KEY") {
                Ok(k) => k,
                Err(e) => {
                    println!("Essential ENV variables could not be read\n \
                    Try running the shell with elevated priviliges or \
                    restarting the shell.");
                    eprintln!("Error: C_KEY {:?}", e);
                    std::process::exit(1)
                }
            };
            let _nounce = match env::var("C_NOUNCE") {
                Ok(k) => k,
                Err(e) => {
                    println!("Essential ENV variables could not be read\n \
                    Try running the shell with elevated priviliges or \
                    restarting the shell.");
                    eprintln!("Error: C_NOUNCE {:?}", e);
                    std::process::exit(1)
                }
            };
            let key = decode(_key).unwrap();
            let nounce = decode(_nounce).unwrap();
            let mut decryptor = aes::ctr(KeySize::KeySize128, &key, &nounce);
            let mut final_result = Vec::<u8>::new();

            let domain_config = match conf.section(retrieve_matches.value_of("domain")) {
                Some(s) => s,
                None => {
                    eprintln!(
                        "Configuration not found for domain: {}",
                        retrieve_matches.value_of("domain").unwrap()
                    );
                    std::process::exit(2)
                }
            };
            let encrypted_data = decode(domain_config.get("password").unwrap()).unwrap();
            let mut read_buffer = buffer::RefReadBuffer::new(&encrypted_data);
            let mut buffer = [0; 4096];
            let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

            loop {
                let result = decryptor
                    .decrypt(&mut read_buffer, &mut write_buffer, true)
                    .unwrap();
                final_result.extend(
                    write_buffer
                        .take_read_buffer()
                        .take_remaining()
                        .iter()
                        .map(|&i| i),
                );
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }
            println!(
                "Configuration for {}:\nUsername: {}\nPassword: {}",
                retrieve_matches.value_of("domain").unwrap(),
                domain_config.get("username").unwrap(),
                std::str::from_utf8(&final_result).unwrap()
            );
        }
        ("", None) => println!("No subcommand was used"),
        _ => println!("Usage Error: Run 'confini.exe --help' for usage \
            instructions."),
    }
}
