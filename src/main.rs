mod model;
mod xml;


use std::io::stdin;
use std::sync::Arc;

use base64::prelude::{BASE64_STANDARD, Engine};
use chrono::{DateTime, Days, Local, LocalResult, NaiveDate, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use ntlmclient;
use reqwest::Client;
use rpassword::prompt_password;

use crate::model::{Config, FolderId, NewEvent};
use crate::xml::{create_event, extract_found_calendars, extract_success, search_for_calendars};


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum TimeResult {
    Time(DateTime<Utc>),
    InputAgain,
    GiveUp,
}


const USER_AGENT: &str = "exchcalfill";


async fn initial_auth(config: &Config) -> Client {
    let password = prompt_password("PASSWORD? ")
        .expect("failed to read password");

    // negotiate NTLM
    let nego_flags
        = ntlmclient::Flags::NEGOTIATE_UNICODE
        | ntlmclient::Flags::REQUEST_TARGET
        | ntlmclient::Flags::NEGOTIATE_NTLM
        | ntlmclient::Flags::NEGOTIATE_WORKSTATION_SUPPLIED
        ;
    let nego_msg = ntlmclient::Message::Negotiate(ntlmclient::NegotiateMessage {
        flags: nego_flags,
        supplied_domain: String::new(),
        supplied_workstation: config.local_hostname.clone(),
        os_version: Default::default(),
    });
    let nego_msg_bytes = nego_msg.to_bytes()
        .expect("failed to encode NTLM negotiation message");
    let nego_b64 = BASE64_STANDARD.encode(&nego_msg_bytes);

    // prepare TLS config with key logging
    let mut roots = rustls::RootCertStore::empty();
    roots.add_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS.iter()
            .map(|ta| rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject, ta.spki, ta.name_constraints,
            ))
    );
    let mut tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    // attempt to connect to the server, offering the negotiation header
    let client = Client::builder()
        .use_preconfigured_tls(tls_config)
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
    let challenge_bytes = BASE64_STANDARD.decode(challenge_b64)
        .expect("base64 decoding challenge message failed");
    let challenge = ntlmclient::Message::try_from(challenge_bytes.as_slice())
        .expect("decoding challenge message failed");
    let challenge_content = match challenge {
        ntlmclient::Message::Challenge(c) => c,
        other => panic!("wrong challenge message: {:?}", other),
    };

    let target_info_bytes: Vec<u8> = challenge_content.target_information
        .iter()
        .flat_map(|ie| ie.to_bytes())
        .collect();

    // calculate the response
    let creds = ntlmclient::Credentials {
        username: config.username.clone(),
        password,
        domain: config.domain.clone(),
    };
    let challenge_response = ntlmclient::respond_challenge_ntlm_v2(
        challenge_content.challenge,
        &target_info_bytes,
        ntlmclient::get_ntlm_time(),
        &creds,
    );
 
    // assemble the packet
    let auth_flags
        = ntlmclient::Flags::NEGOTIATE_UNICODE
        | ntlmclient::Flags::NEGOTIATE_NTLM
        ;
    let auth_msg = challenge_response.to_message(
        &creds,
        &config.local_hostname,
        auth_flags,
    );
    let auth_msg_bytes = auth_msg.to_bytes()
        .expect("failed to encode NTLM authentication message");
    let auth_b64 = BASE64_STANDARD.encode(&auth_msg_bytes);

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

fn get_time_assuming_timezone<T: TimeZone>(date: &NaiveDate, time: &NaiveTime, tz: &T) -> TimeResult {
    let local_time = match tz.from_local_datetime(&date.and_time(*time)) {
        LocalResult::None => {
            println!("> no such time; try again");
            return TimeResult::InputAgain;
        },
        LocalResult::Ambiguous(first_time, second_time) => {
            loop {
                println!("> this time happens twice; 1st or 2nd occurrence? [12] (or \"nvm\" to give up)");
                let pick_line = read_stdin_line_trimmed();
                if pick_line == "nvm" {
                    return TimeResult::GiveUp;
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
    TimeResult::Time(local_time.with_timezone(&Utc))
}

fn get_time(date: &NaiveDate, time_kind: &str) -> Option<DateTime<Utc>> {
    let mut timezone: Option<Tz> = None;
    loop {
        let timezone_name = timezone.map(|tz| tz.name()).unwrap_or("local time");
        println!("> {} in {}? [hhmm] (or \"tz\" to set timezone or \"nvm\" to give up)", time_kind, timezone_name);
        let time_line = read_stdin_line_trimmed();
        if time_line == "nvm" {
            return None;
        } else if time_line == "tz" {
            loop {
                println!("> IANA timezone (or empty for local time)?");
                let timezone_line = read_stdin_line_trimmed();
                if timezone_line.len() == 0 {
                    timezone = None;
                    break;
                }
                let mut tz_found = false;
                for tz in chrono_tz::TZ_VARIANTS {
                    if tz.name() == &timezone_line {
                        timezone = Some(tz);
                        tz_found = true;
                        break;
                    }
                }
                if tz_found {
                    break;
                } else {
                    println!("unknown timezone");
                }
            }
            continue;
        }
        let t = match NaiveTime::parse_from_str(&time_line, "%H%M") {
            Ok(v) => v,
            Err(e) => {
                println!("> failed to parse: {}", e);
                continue;
            },
        };
        let dt_result = if let Some(tz) = timezone {
            get_time_assuming_timezone(date, &t, &tz)
        } else {
            get_time_assuming_timezone(date, &t, &Local)
        };
        match dt_result {
            TimeResult::Time(dt) => return Some(dt),
            TimeResult::GiveUp => return None,
            TimeResult::InputAgain => {}, // loop again
        }
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

    let start = match get_time(&date, "Start time") {
        None => return true,
        Some(dt) => dt,
    };
    let mut end = match get_time(&date, "End time") {
        None => return true,
        Some(dt) => dt,
    };
    if end < start {
        println!("Warning: end time before start time; increasing end date");
        end = end.checked_add_days(Days::new(1)).unwrap();
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
    env_logger::init();

    // load config
    let config: Config = {
        let config_string = std::fs::read_to_string("config.toml")
            .expect("failed to read config.toml");
        toml::from_str(&config_string)
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
