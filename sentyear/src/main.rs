mod exch;


use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use msswap::ExchangeConfig;
use reqwest::Client;


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum TimeResult {
    Time(DateTime<Utc>),
    InputAgain,
    GiveUp,
}


struct FolderItem {
    // TODO
}


async fn get_sent_folder_items(client: &Client, offset: usize) -> Vec<FolderItem> {
    todo!();
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

    let mut offset = 0;
    loop {
        let items = get_sent_folder_items(&client, offset).await;
        if items.len() == 0 {
            break;
        }
        offset += items.len();

        let mut target_folder_id_to_source_items = BTreeMap::new();
        for item in &items {
            // determine target folder ID
            let target_folder_id = todo!();

            target_folder_id_to_source_items
                .entry(target_folder_id)
                .or_insert_with(|| Vec::new())
                .push(item.id);
        }

        for (target_folder_id, source_items) in &target_folder_id_to_source_items {
            // batch-move source items to target folder ID
            todo!();
        }
    }
}
