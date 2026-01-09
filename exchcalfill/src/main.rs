mod model;
mod xml;


use std::io::stdin;

use chrono::{DateTime, Days, Local, LocalResult, NaiveDate, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use msswap::ExchangeConfig;
use reqwest::Client;

use crate::model::{FolderId, FreeBusyStatus, NewEvent};
use crate::xml::{create_event, extract_found_calendars, extract_success, search_for_calendars};


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum TimeResult {
    Time(DateTime<Utc>),
    InputAgain,
    GiveUp,
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

async fn add_event_loop(client: &mut Client, config: &ExchangeConfig, calendar_folder: &FolderId, date: &NaiveDate) -> bool {
    let mut ask_free_busy_state = false;
    loop {
        println!("> Add an event on {}? [ynf]", date.format("%Y-%m-%d"));
        let add_line = read_stdin_line_trimmed();

        if add_line == "y" {
            // break out of this obstinate loop
            break;
        } else if add_line == "n" {
            // exit the app
            return false;
        } else if add_line == "f" {
            // user wants to add a special free-busy state
            ask_free_busy_state = true;
            break;
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

    let free_busy_state = if ask_free_busy_state {
        loop {
            println!("> Free/busy state? [f=free, b=busy, t=tentative, o=out-of-office, e=elsewhere, n=no-data, q=quit]");
            let fbs_line = read_stdin_line_trimmed();
            match fbs_line.as_str() {
                "f" => break FreeBusyStatus::Free,
                "b" => break FreeBusyStatus::Busy,
                "t" => break FreeBusyStatus::Tentative,
                "o" => break FreeBusyStatus::OutOfOffice,
                "e" => break FreeBusyStatus::WorkingElsewhere,
                "n" => break FreeBusyStatus::NoData,
                "q" => return true,
                _ => {},
            }
        }
    } else {
        FreeBusyStatus::Busy
    };

    let new_event = NewEvent::new(
        start,
        end,
        name,
        location,
        Some(free_busy_state),
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

async fn interaction_loop(mut client: Client, config: &ExchangeConfig, calendar_folder: &FolderId) {
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
    let config: ExchangeConfig = {
        let config_string = std::fs::read_to_string("config.toml")
            .expect("failed to read config.toml");
        toml::from_str(&config_string)
            .expect("failed to parse config.toml")
    };

    let client = msswap::initial_auth(&config).await;

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
