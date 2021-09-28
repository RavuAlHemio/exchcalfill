mod model;
mod ntlm;
mod xml;


use std::fs::File;
use std::io::{Read, stdin};

use base64;
use chrono::{DateTime, Local, LocalResult, NaiveDate, NaiveTime, TimeZone, Utc};
use reqwest::Client;
use rpassword::read_password_from_tty;

use crate::model::{Config, FolderId, NewEvent};
use crate::ntlm::{
    NtlmCredentials, NtlmFlags, NtlmMessage, NtlmNegotiateMessage, get_ntlm_time,
    respond_challenge_ntlm_v2,
};
use crate::xml::{create_event, extract_found_calendars, extract_success, search_for_calendars};


const USER_AGENT: &str = "exchcalfill";


async fn initial_auth(config: &Config) -> Client {
    let password = read_password_from_tty(Some("PASSWORD? "))
        .expect("failed to read password");

    // negotiate NTLM
    let nego_flags
        = NtlmFlags::NEGOTIATE_UNICODE
        | NtlmFlags::REQUEST_TARGET
        | NtlmFlags::NEGOTIATE_NTLM
        | NtlmFlags::NEGOTIATE_WORKSTATION_SUPPLIED
        ;
    let nego_msg = NtlmMessage::Negotiate(NtlmNegotiateMessage {
        flags: nego_flags,
        supplied_domain: String::new(),
        supplied_workstation: config.local_hostname.clone(),
        os_version: Default::default(),
    });
    let nego_msg_bytes = nego_msg.to_bytes()
        .expect("failed to encode NTLM negotiation message");
    let nego_b64 = base64::encode(&nego_msg_bytes);

    // attempt to connect to the server, offering the negotiation header
    let client = Client::builder()
        .cookie_store(true)
        .user_agent(USER_AGENT)
        .build()
        .expect("failed to build client");
    let resp = client.get(&config.ews_url)
        .header("Authorization", format!("NTLM {}", nego_b64))
        .send().await
        .expect("failed to send challenge request to Exchange");
    let challenge_header = resp.headers().get("www-authenticate")
        .expect("response missing challenge header");

    let challenge_b64 = challenge_header.to_str()
        .expect("challenge header not a string")
        .split(" ")
        .nth(1).expect("second chunk of challenge header missing");
    let challenge_bytes = base64::decode(&challenge_b64)
        .expect("base64 decoding challenge message failed");
    let challenge = NtlmMessage::try_from(challenge_bytes.as_slice())
        .expect("decoding challenge message failed");
    let challenge_content = match challenge {
        NtlmMessage::Challenge(c) => c,
        other => panic!("wrong challenge message: {:?}", other),
    };

    let target_info_bytes: Vec<u8> = challenge_content.target_information
        .iter()
        .flat_map(|ie| ie.to_bytes())
        .collect();

    // calculate the response
    let creds = NtlmCredentials {
        username: config.username.clone(),
        password,
        domain: config.domain.clone(),
    };
    let challenge_response = respond_challenge_ntlm_v2(
        challenge_content.challenge,
        &target_info_bytes,
        get_ntlm_time(),
        &creds,
    );
 
    // assemble the packet
    let auth_flags
        = NtlmFlags::NEGOTIATE_UNICODE
        | NtlmFlags::NEGOTIATE_NTLM
        ;
    let auth_msg = challenge_response.to_message(
        &creds,
        &config.local_hostname,
        auth_flags,
    );
    let auth_msg_bytes = auth_msg.to_bytes()
        .expect("failed to encode NTLM authentication message");
    let auth_b64 = base64::encode(&auth_msg_bytes);

    client.get(&config.ews_url)
        .header("Authorization", format!("NTLM {}", auth_b64))
        .send().await
        .expect("failed to send authentication request to Exchange")
        .error_for_status()
        .expect("error response to authentication message");

    // try calling again, without the auth stuff (thanks to cookies)
    client.get(&config.ews_url)
        .send().await
        .expect("failed to send refresher request to Exchange")
        .error_for_status()
        .expect("error response to refresher message");

    client
}

fn read_stdin_line() -> String {
    let stdin = stdin();
    let mut buf = String::new();
    stdin.read_line(&mut buf)
        .expect("failed to read line");
    buf
}

fn read_stdin_line_trimmed() -> String {
    let line = read_stdin_line();
    line.trim().to_owned()
}

fn get_time(date: &NaiveDate, time_kind: &str) -> Option<DateTime<Local>> {
    loop {
        println!("> {}? [hhmm] (or \"nvm\" to give up)", time_kind);
        let time_line = read_stdin_line_trimmed();
        if time_line == "nvm" {
            return None;
        }
        let t = match NaiveTime::parse_from_str(&time_line, "%H%M") {
            Ok(v) => v,
            Err(e) => {
                println!("> failed to parse: {}", e);
                continue;
            }
        };
        let dt = match Local.from_local_datetime(&date.and_time(t)) {
            LocalResult::None => {
                println!("> no such time; try again");
                continue;
            },
            LocalResult::Ambiguous(first_time, second_time) => {
                loop {
                    println!("> this time happens twice; 1st or 2nd occurrence? [12] (or \"nvm\" to give up)");
                    let pick_line = read_stdin_line_trimmed();
                    if pick_line == "nvm" {
                        return None;
                    } else if pick_line == "1" {
                        break first_time;
                    } else if pick_line == "2" {
                        break second_time;
                    }
                    // otherwise, ask again
                }
            },
            LocalResult::Single(dt) => dt,
        };
        return Some(dt);
    }
}

async fn add_event_loop(client: &mut Client, config: &Config, calendar_folder: &FolderId, date: &NaiveDate) -> bool {
    loop {
        println!("> Add an event on {}? [yn]", date.format("%Y-%m-%d"));
        let add_line = read_stdin_line_trimmed();

        if add_line == "y" {
            // break out of this obstinate loop
            break;
        } else if add_line == "n" {
            // exit the app
            return false;
        }

        // otherwise, ask again
    }

    println!("> Event name?");
    let name = read_stdin_line_trimmed();

    println!("> Location?");
    let location_line = read_stdin_line_trimmed();
    let location = if location_line.len() > 0 {
        Some(location_line)
    } else {
        None
    };

    let start_local = match get_time(&date, "Start time") {
        None => return true,
        Some(dt) => dt,
    };
    let end_local = match get_time(&date, "End time") {
        None => return true,
        Some(dt) => dt,
    };

    let start = start_local.with_timezone(&Utc);
    let end = end_local.with_timezone(&Utc);

    let new_event = NewEvent::new(
        start,
        end,
        name,
        location,
    );

    // add this event
    let add_body = create_event(&new_event, &calendar_folder);
    let add_response = client.post(&config.ews_url)
        .header("Content-Type", "text/xml")
        .body(add_body)
        .send().await.expect("failed to request addition");
    let add_bytes = add_response
        .bytes().await.expect("failed to obtain addition response bytes")
        .to_vec();
    extract_success(add_bytes);

    true
}

async fn interaction_loop(mut client: Client, config: &Config, calendar_folder: &FolderId) {
    loop {
        let date = loop {
            println!("> Date? [yyyymmdd] (or \"nvm\" to end)");
            let date_line = read_stdin_line_trimmed();
            if date_line == "nvm" {
                return;
            }
            let d = match NaiveDate::parse_from_str(&date_line, "%Y%m%d") {
                Ok(v) => v,
                Err(e) => {
                    println!("> failed to parse: {}", e);
                    continue;
                }
            };
            break d;
        };

        loop {
            let keep_looping = add_event_loop(&mut client, config, calendar_folder, &date).await;
            if !keep_looping {
                break;
            }
        }
    }
}


#[tokio::main]
async fn main() {
    // load config
    let config: Config = {
        let mut f = File::open("config.toml")
            .expect("failed to open config.toml");
        let mut config_bytes = Vec::new();
        f.read_to_end(&mut config_bytes)
            .expect("failed to read config.toml");
        toml::from_slice(&config_bytes)
            .expect("failed to parse config.toml")
    };

    let client = initial_auth(&config).await;

    let sfc_body = search_for_calendars();
    let sfc_response = client.post(&config.ews_url)
        .header("Content-Type", "text/xml")
        .body(sfc_body)
        .send().await.expect("failed to request calendar folders");
    let sfc_bytes = sfc_response
        .bytes().await.expect("failed to obtain calendar folders response bytes")
        .to_vec();
    let calendars = extract_found_calendars(sfc_bytes);

    let calendar_index = {
        loop {
            println!("> Pick a calendar:");
            for (i, calendar) in calendars.iter().enumerate() {
                println!("> {}. {}", i, calendar.display_name);
            }

            let buf = read_stdin_line_trimmed();

            // try to parse
            let calendar_index: usize = match buf.parse() {
                Ok(u) => u,
                Err(e) => {
                    println!("failed to parse {:?}: {}", buf, e);
                    continue;
                },
            };
            if calendar_index >= calendars.len() {
                println!("index {} is out of bounds, try again", calendar_index);
                continue;
            }

            break calendar_index;
        }
    };

    interaction_loop(client, &config, &calendars[calendar_index].folder_id).await;
}
