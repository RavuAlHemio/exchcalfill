use std::sync::Arc;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use reqwest::Client;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};


const USER_AGENT: &str = "msswap (github.com/RavuAlHemio/exchcalfill)";


#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ExchangeConfig {
    pub ews_url: String,
    pub username: String,
    pub domain: String,
    pub local_hostname: String,
}


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdAndChangeKey {
    pub id: String,
    pub change_key: Option<String>,
}
impl IdAndChangeKey {
    pub fn new<I: Into<String>>(id: I) -> Self {
        Self {
            id: id.into(),
            change_key: None,
        }
    }

    pub fn new_with_change_key<I: Into<String>, C: Into<String>>(
        id: I,
        change_key: C,
    ) -> Self {
        Self {
            id: id.into(),
            change_key: Some(change_key.into()),
        }
    }

    pub fn set_on_xml_element(&self, element: &sxd_document::dom::Element<'_>) {
        element.set_attribute_value("Id", &self.id);
        if let Some(change_key) = self.change_key.as_ref() {
            element.set_attribute_value("ChangeKey", change_key);
        }
    }
}


pub async fn initial_auth(config: &ExchangeConfig) -> Client {
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
    let roots = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter()
            .cloned()
    );
    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("failed to prepare TLS client config")
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
