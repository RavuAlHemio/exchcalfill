mod exch;


use std::collections::{BTreeMap, BTreeSet};

use chrono::{Datelike, Utc};
use msswap::{ExchangeConfig, IdAndChangeKey};
use reqwest::{Client, Method, StatusCode};
use reqwest::header::HeaderMap;
use xot::output::xml::{Declaration, Parameters};
use xot::{Node, Xot};

use crate::exch::SentItem;


#[derive(Debug)]
pub struct CommunicateResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub xot: Xot,
    pub doc: Node,
}


async fn communicate(client: &Client, exchange_post_url: &str, xot: &Xot, doc: Node) -> CommunicateResponse {
    let mut params = Parameters::default();
    params.declaration = Some(Declaration::default());
    let mut request_bytes = Vec::new();
    xot.serialize_xml_write(params, doc, &mut request_bytes)
        .expect("failed to serialize request");
    eprintln!("sending: {:?}", std::str::from_utf8(&request_bytes));
    let response = client.request(Method::POST, exchange_post_url)
        .header("Content-Type", "text/xml")
        .body(request_bytes)
        .send().await.expect("failed to send Exchange request");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes_vec = response
        .bytes().await.expect("failed to obtain response bytes")
        .to_vec();
    let bytes_str = std::str::from_utf8(&bytes_vec)
        .expect("failed to decode response bytes");
    eprintln!("received >{}< {}", status, bytes_str);
    let mut new_xot = Xot::new();
    let new_doc = new_xot.parse_bytes(&bytes_vec)
        .expect("failed to parse response as XML");
    CommunicateResponse {
        status,
        headers,
        xot: new_xot,
        doc: new_doc,
    }
}


async fn get_known_folder(client: &Client, exchange_post_url: &str, known_folder_id: &str) -> Option<IdAndChangeKey> {
    let (xot, doc) = crate::exch::create_request_get_known_folder(known_folder_id);
    let mut response = communicate(client, exchange_post_url, &xot, doc).await;
    if response.status != StatusCode::OK {
        panic!("get-known-folder operation failed: {}", response.status);
    }
    crate::exch::extract_response_get_folder(&mut response.xot, response.doc)
}


async fn get_sent_folder_items(client: &Client, exchange_post_url: &str, offset: usize) -> (bool, Vec<SentItem>) {
    let (xot, doc) = crate::exch::create_request_enumerate_sent_folder(offset);
    let mut response = communicate(client, exchange_post_url, &xot, doc).await;
    if response.status != StatusCode::OK {
        panic!("get-sent-folder-items operation failed: {}", response.status);
    }
    let sent_items = crate::exch::extract_response_enumerate_sent_folder(&mut response.xot, response.doc);
    sent_items
}


async fn find_folder(client: &Client, exchange_post_url: &str, base_folder_id: &IdAndChangeKey, name: &str) -> Option<IdAndChangeKey> {
    let (xot, doc) = crate::exch::create_request_find_folder(base_folder_id, name);
    let mut response = communicate(client, exchange_post_url, &xot, doc).await;
    if response.status != StatusCode::OK {
        panic!("find-folder operation failed: {}", response.status);
    }
    crate::exch::extract_response_find_folder(&mut response.xot, response.doc)
}


async fn move_items_to_folder(client: &Client, exchange_post_url: &str, items_ids: &[IdAndChangeKey], dest_folder_id: &IdAndChangeKey) {
    let (xot, doc) = crate::exch::create_request_move_item(items_ids, dest_folder_id);
    let response = communicate(client, exchange_post_url, &xot, doc).await;
    if response.status != StatusCode::OK {
        panic!("move-items operation failed: {}", response.status);
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

    let sent_folder_id = get_known_folder(&client, &config.ews_url, "sentitems")
        .await.expect("sent folder not found");

    let mut year_to_target_folder_id: BTreeMap<i32, IdAndChangeKey> = BTreeMap::new();
    let mut offset = 0;
    loop {
        let (last_items, items) = get_sent_folder_items(&client, &config.ews_url, offset).await;
        eprintln!("batch at {}", offset);

        let mut target_folder_id_to_source_items = BTreeMap::new();
        for item in &items {
            // determine target folder ID
            let sent_year = item.sent.year();

            let current_year = Utc::now().year();
            if sent_year >= current_year {
                // leave this in the regular folder
                continue;
            }

            let target_folder_id = if let Some(tfid) = year_to_target_folder_id.get(&sent_year) {
                tfid.clone()
            } else {
                // sigh, find the folder
                let sent_year_folder_name = format!("sent {}", sent_year);
                let Some(sent_year_folder_id) = find_folder(&client, &config.ews_url, &sent_folder_id, &sent_year_folder_name).await
                    else { panic!("failed to find sent folder for year {}", sent_year) };
                year_to_target_folder_id.insert(sent_year, sent_year_folder_id.clone());
                sent_year_folder_id
            };

            target_folder_id_to_source_items
                .entry(target_folder_id)
                .or_insert_with(|| BTreeSet::new())
                .insert(item.id.clone());
        }

        if target_folder_id_to_source_items.len() == 0 {
            // none of these items are eligible for move; get the next batch
            if last_items {
                break;
            } else {
                offset += items.len();
            }
        } else {
            // check it all from the beginning
            offset = 0;
        }

        for (target_folder_id, source_items) in &target_folder_id_to_source_items {
            let source_item_list: Vec<IdAndChangeKey> = source_items
                .iter()
                .cloned()
                .collect();
            if source_item_list.len() == 0 {
                continue;
            }
            let year = year_to_target_folder_id
                .iter()
                .filter(|(_year, tfid)| *tfid == target_folder_id)
                .map(|(year, _tfid)| *year)
                .nth(0).expect("year not found for folder ID");
            eprintln!("year {}", year);

            // batch-move source items to target folder ID
            move_items_to_folder(&client, &config.ews_url, &source_item_list, target_folder_id)
                .await;
        }
    }
}
