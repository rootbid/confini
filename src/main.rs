extern crate base64;
extern crate clap;
extern crate crypto;
extern crate ini;
extern crate rand_core;

use self::base64::{decode, encode};
use clap::{App, Arg};
use crypto::aes::{self, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;
use ini::Ini;
use rand_core::{OsRng, RngCore};
use std::env;
use std::iter::repeat;
use std::process::{Command, Stdio};

fn main() {
    let matches = App::new("Configuration Management")
        .version("0.1")
        .about("Configuration management for automated workflows")
        .arg(Arg::with_name("init").help("Initialize the configuration store"))
        .subcommand(
            App::new("add")
                .about("Add new configuration section")
                .arg(
                    Arg::with_name("domain")
                        .short("d")
                        .help("'Technology-Vendor' name for the domain to add")
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
                        .help("'Technology-Vendor' name for the domain to be modified")
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
                        .help("'Technology-Vendor' name for the domain to be modified")
                        .takes_value(true)
                        .required(true),
                )
        )
        .get_matches();

    if matches.is_present("init") {
        // Generate a secret key and a nounce value with a secure random generator
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
        let mut conf = Ini::new();
        conf.with_general_section().set("encoding", "utf-8");
        conf.write_to_file("conf.ini").unwrap();
        println!("Configuration file 'conf.ini' initiated");
        println!("Use `configstore.exe add <domain> <username> <password>` to add configurations")
    } else {
        match matches.subcommand() {
            ("add", Some(add_matches)) => {
                let mut conf = Ini::load_from_file("conf.ini").unwrap();
                let _key = "C_KEY";
                let _nounce = "C_NOUNCE";
                let key = decode(env::var(_key).unwrap()).unwrap();
                let nounce = decode(env::var(_nounce).unwrap()).unwrap();

                let mut cipher = aes::ctr(KeySize::KeySize128, &key, &nounce);
                let mut password: Vec<u8> = repeat(0u8)
                    .take(add_matches.value_of("password").unwrap().len())
                    .collect();
                cipher.process(
                    add_matches.value_of("password").unwrap().as_bytes(),
                    &mut password[..],
                );

                conf.with_section(add_matches.value_of("domain"))
                    .set("username", add_matches.value_of("username").unwrap())
                    .set("password", encode(&password).as_str());
                conf.write_to_file("conf.ini").unwrap();
                println!(
                    "Configuration for {} has been added",
                    add_matches.value_of("domain").unwrap()
                );
            }
            ("edit", Some(edit_matches)) => {
                let mut conf = Ini::load_from_file("conf.ini").unwrap();

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

                if edit_matches.is_present("username") {
                    conf.with_section(edit_matches.value_of("domain"))
                        .set("username", edit_matches.value_of("username").unwrap())
                        .set("password", encode(&password).as_str());
                } else {
                    conf.with_section(edit_matches.value_of("domain"))
                        .set("password", encode(&password).as_str());
                }
                conf.write_to_file("conf.ini").unwrap();
                println!(
                    "Password configuration for {} has been updated",
                    edit_matches.value_of("domain").unwrap()
                );
            }
            ("delete", Some(delete_matches)) => {
                let mut conf = Ini::load_from_file("conf.ini").unwrap();
                conf.delete(delete_matches.value_of("domain"));
                conf.write_to_file("conf.ini").unwrap();
                println!(
                    "Password configuration for {} has been deleted",
                    delete_matches.value_of("domain").unwrap()
                );
            }
            ("", None) => println!("No subcommand was used"), // If no subcommand was usd it'll match the tuple ("", None)
            _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
        }
    }
}
