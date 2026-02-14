use mailparse::{self, MailHeaderMap};
use serde::{Deserialize, Serialize};
use toml;

use async_imap::extensions::idle::IdleResponse;
use async_imap::{Authenticator, Client, Session};
use chrono::{DateTime, Utc};
use dotenvy::dotenv;
use futures::TryStreamExt;
use native_tls::TlsConnector as NativeTlsConnector;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector, TlsStream};

fn log_func(args: std::fmt::Arguments) {
    let offset = chrono::FixedOffset::east_opt(3600 * 2).unwrap();
    let current_time = Utc::now().with_timezone(&offset);
    println!("{} {}", current_time, args);
}

// Then use this macro to bridge the gap:
macro_rules! log {
    ($($arg:tt)*) => {
        log_func(format_args!($($arg)*))
    };
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    filters: Vec<Filter>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Filter {
    name: String,
    enabled: bool,
    priority: u32,
    condition: Condition,
    action: Action,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Condition {
    #[serde(rename = "type")]
    condition_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conditions: Option<Vec<Condition>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Action {
    #[serde(rename = "type")]
    action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,
}

struct Email {
    uid: u32,
    subject: String,
    sender: String,
    recipient: String,
    date: DateTime<Utc>,
    body: String,
}

struct GmailOAuth2 {
    user: String,
    access_token: String,
}

type ImapSession = Session<TlsStream<TcpStream>>;

impl Authenticator for GmailOAuth2 {
    type Response = String;
    fn process(&mut self, _: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.user, self.access_token
        )
    }
}

async fn connect_and_authenticate(
    auth: GmailOAuth2,
) -> Result<ImapSession, Box<dyn std::error::Error + Send + Sync>> {
    let domain = "imap.gmail.com";
    let port = 993;

    let native_tls_connector = NativeTlsConnector::builder().build()?;
    let tls_connector = TlsConnector::from(native_tls_connector);

    let tcp_stream = TcpStream::connect((domain, port)).await?;
    let tls_stream = tls_connector.connect(domain, tcp_stream).await?;

    let mut client = Client::new(tls_stream);
    let greeting = client.read_response().await?;
    if greeting.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Expected IMAP greeting",
        )
        .into());
    }

    let session = client
        .authenticate("LOGIN", auth)
        .await
        .map_err(|(err, _client)| err)?;

    Ok(session)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    load_dotenv()?;

    let config_path = std::path::PathBuf::from("config.toml");

    let args: Vec<String> = std::env::args().collect();

    // Check if an argument exists to avoid a panic if the user runs it without args
    if args.len() < 2 {
        eprintln!("Usage: <program> [monitor|filter] (requires GMAIL_USER and GMAIL_ACCESS_TOKEN)");
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Incorrect arguments").into(),
        );
    }

    let gmail_auth = GmailOAuth2 {
        user: std::env::var("GMAIL_USER")?,
        access_token: std::env::var("GMAIL_ACCESS_TOKEN")?,
    };

    println!("Using user {}", gmail_auth.user);
    println!("Using access token {}", gmail_auth.access_token);

    let mut session = connect_and_authenticate(gmail_auth).await?;

    // Load config
    let email_config: Config = toml::from_str(&std::fs::read_to_string(config_path)?)?;
    log!("Loaded {} filters from config", email_config.filters.len());

    // Select INBOX (read-write mode required for moving/deleting)
    let mailbox = session.select("INBOX").await?;
    log!("Connected to INBOX with {} messages", mailbox.exists);

    match args[1].as_str() {
        "monitor" => {
            log!("Running in monitor mode.");
            let err = monitor_inbox(session, &email_config).await;
            if let Err(e) = err {
                eprint!("Error in monitor mode: {}", e);
            }
        }
        "filter" => {
            log!("Running in filter mode.");
            // Fetch emails
            let emails = fetch_emails_by_uid_batches(&mut session, "INBOX", 50).await?;

            // Process with filters
            if !emails.is_empty() {
                process_emails_with_filters(&mut session, &emails, &email_config).await?;
            }
            // Clean logout
            println!("\nMailbox filtered successfully");
            session.logout().await?;
        }
        _ => eprint!("Unknown argument {}", args[1]),
    }

    Ok(())
}

fn load_dotenv() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if dotenv().is_ok() {
        return Ok(());
    }

    let mut search_bases: Vec<std::path::PathBuf> = Vec::new();

    if let Ok(current_dir) = std::env::current_dir() {
        search_bases.push(current_dir);
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            search_bases.push(exe_dir.to_path_buf());
        }
    }

    for base in search_bases {
        let mut cursor = base.as_path();
        loop {
            let candidate = cursor.join(".env");
            if candidate.is_file() {
                match dotenvy::from_path(&candidate) {
                    Ok(_) => return Ok(()),
                    Err(err) => {
                        return Err(format!(
                            "Failed to load .env file at {}: {}",
                            candidate.display(),
                            err
                        )
                        .into());
                    }
                }
            }

            match cursor.parent() {
                Some(parent) => cursor = parent,
                None => break,
            }
        }
    }

    Err("Failed to load .env file".into())
}

async fn fetch_latest_email(
    session: &mut ImapSession,
    mailbox_name: &str,
) -> Result<Email, Box<dyn std::error::Error + Send + Sync>> {
    session.select(mailbox_name).await?;

    // Get the highest UID (most recent email)
    let uids = session.uid_search("ALL").await?;
    let latest_uid = uids.iter().max().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "No messages in mailbox")
    })?;

    // Fetch that specific email
    let fetch_result = session
        .uid_fetch(format!("{}", latest_uid), "RFC822")
        .await?;
    let fetch_result: Vec<_> = fetch_result.try_collect().await?;

    // -- MOST OPTIMAL
    // Get highest sequence number (not UID) to fetch latest in one command
    // let mailbox = session.select(mailbox_name)?;
    // let latest_seq = mailbox.exists; // Highest = most recent

    // Fetch only that one message
    // let fetch_result = session.fetch(format!("{}", latest_seq), "RFC822")?;
    // --

    // Fetch the latest email
    let message = fetch_result.first().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "No messages in mailbox")
    })?;

    let body_bytes = match message.body() {
        Some(b) => b,
        None => {
            eprintln!(
                "Skipping UID {}: No body content found",
                message.uid.unwrap_or(0)
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No body content found",
            )
            .into());
        }
    };

    let parsed = match mailparse::parse_mail(body_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to parse email: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to parse email",
            )
            .into());
        }
    };

    // Extract Message-ID
    // let id = parsed
    //     .headers
    //     .get_first_value("Message-ID")
    //     .unwrap_or_else(|| format!("no-id-{}", message.uid.unwrap_or(0)));

    // Extract UID
    let uid = message.uid.expect("message did not have a UID!");

    // Extract Subject
    let subject = parsed
        .headers
        .get_first_value("Subject")
        .unwrap_or_else(|| String::from("(no subject)"));

    // Extract Sender (From)
    let sender = parsed
        .headers
        .get_first_value("From")
        .unwrap_or_else(|| String::from("(unknown sender)"));

    // Extract Recipient (To)
    let recipient = parsed
        .headers
        .get_first_value("To")
        .unwrap_or_else(|| String::from("(unknown recipient)"));

    // Extract Date
    let date_str = parsed
        .headers
        .get_first_value("Date")
        .unwrap_or_else(|| "(no date)".into());

    // Use parse_from_rfc2822 instead of the default .parse()
    let date = DateTime::parse_from_rfc2822(&date_str)
        .map(|dt| dt.with_timezone(&Utc)) // Convert FixedOffset to Utc
        .unwrap_or_else(|e| {
            eprintln!("Warning: Failed to parse date '{}': {}", date_str, e);
            Utc::now()
        });

    // Extract body text
    let body_text = parsed.get_body()?.trim().to_string();

    let email = Email {
        uid,
        subject,
        sender,
        recipient,
        date,
        body: body_text,
    };

    Ok(email)
}

/// Monitors inbox for new messages using IMAP IDLE
async fn monitor_inbox(
    mut session: ImapSession,
    email_config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log!("Using IDLE to monitor incoming emails in realtime.");
    let mailbox = session.select("INBOX").await?;

    // Track the highest UID we've already processed
    let mut last_processed_uid = session
        .uid_search("ALL")
        .await?
        .iter()
        .max()
        .cloned()
        .unwrap_or(0);

    loop {
        let mut idle = session.idle();
        idle.init().await?;
        let (wait, _stop) = idle.wait_with_timeout(Duration::from_secs(60 * 10));
        let response = wait.await?;
        session = idle.done().await?;

        match response {
            IdleResponse::NewData(_) | IdleResponse::Timeout | IdleResponse::ManualInterrupt => {
                log!("{} New emails received.", mailbox.exists);
                // Get current max UID
                let current_uids = session.uid_search("ALL").await?;
                let current_max_uid = current_uids.iter().max().cloned().unwrap_or(0);

                // If there are new messages
                if current_max_uid > last_processed_uid {
                    // Fetch ALL new emails (not just latest)
                    log!(
                        "Fetching new emails by UIDs: {}:{}",
                        last_processed_uid + 1,
                        current_max_uid
                    );

                    let new_emails = fetch_emails_by_uid_range(
                        &mut session,
                        "INBOX",
                        last_processed_uid + 1,
                        current_max_uid,
                    )
                    .await?;

                    // Process all new emails
                    process_emails_with_filters(&mut session, &new_emails, email_config).await?;

                    // Update last processed UID
                    last_processed_uid = current_max_uid;
                }
            }
        }
    }
}

async fn fetch_emails_by_uid_range(
    session: &mut ImapSession,
    mailbox: &str,
    start_uid: u32,
    end_uid: u32,
) -> Result<Vec<Email>, Box<dyn std::error::Error + Send + Sync>> {
    session.select(mailbox).await?;

    // Validate range
    if start_uid > end_uid {
        return Ok(Vec::new());
    }

    // Construct UID range string (e.g., "100:200" or "50" for single)
    let uid_range = if start_uid == end_uid {
        start_uid.to_string()
    } else {
        format!("{}:{}", start_uid, end_uid)
    };

    // Fetch only the specified range
    let messages = session.uid_fetch(uid_range, "BODY.PEEK[]").await?;
    let messages: Vec<_> = messages.try_collect().await?;

    let mut emails = Vec::new();

    for message in messages.iter() {
        let uid = message.uid.expect("Message missing UID");

        // Get body once and handle the None case immediately
        let body_bytes = match message.body() {
            Some(body) => body,
            None => {
                eprintln!("Warning: No body for UID {}, skipping", uid);
                continue; // Skip this message and move to the next
            }
        };

        let parsed = mailparse::parse_mail(body_bytes).expect("The email has no body.");

        // Extract email fields with safe defaults
        // let id = parsed
        //     .headers
        //     .get_first_value("Message-ID")
        //     .unwrap_or_else(|| format!("no-id-{}", uid));

        let subject = parsed
            .headers
            .get_first_value("Subject")
            .unwrap_or_else(|| "(no subject)".into());

        let sender = parsed
            .headers
            .get_first_value("From")
            .unwrap_or_else(|| "(unknown sender)".into());

        let recipient = parsed
            .headers
            .get_first_value("To")
            .unwrap_or_else(|| "(unknown recipient)".into());

        let date_str = parsed
            .headers
            .get_first_value("Date")
            .unwrap_or_else(|| "(no date)".into());

        // Use parse_from_rfc2822 instead of the default .parse()
        let date = DateTime::parse_from_rfc2822(&date_str)
            .map(|dt| dt.with_timezone(&Utc)) // Convert FixedOffset to Utc
            .unwrap_or_else(|e| {
                eprintln!("Warning: Failed to parse date '{}': {}", date_str, e);
                Utc::now()
            });

        let body_text = parsed.get_body()?.trim().to_string();

        let email = Email {
            uid,
            subject,
            sender,
            recipient,
            date,
            body: body_text,
        };

        emails.push(email);
    }

    Ok(emails)
}

// Example using UIDs instead of sequence numbers (more reliable)
async fn fetch_emails_by_uid_batches(
    session: &mut ImapSession,
    mailbox: &str,
    batch_size: u32,
) -> Result<Vec<Email>, Box<dyn std::error::Error + Send + Sync>> {
    session.select(mailbox).await?;

    // Search for all UIDs
    let uids = session.uid_search("ALL").await?;

    // println!("Total messages: {}", uids.len());
    log!("Total messages: {}", uids.len());

    // Convert HashSet to Vec and sort for consistent ordering
    let mut uid_vec: Vec<u32> = uids.into_iter().collect();
    uid_vec.sort();

    let mut all_emails = Vec::new();

    // Process UIDs in batches
    for chunk in uid_vec.chunks(batch_size as usize) {
        if chunk.is_empty() {
            continue;
        }

        let uid_range = if chunk.len() == 1 {
            format!("{}", chunk[0])
        } else {
            format!("{}:{}", chunk[0], chunk[chunk.len() - 1])
        };

        // println!("\nFetching UIDs: {}", uid_range);
        log!("Fetching UIDs: {}", uid_range);

        // Fetch full message body (RFC822) to parse with mailparse
        let messages = session.uid_fetch(uid_range, "RFC822").await?;
        let messages: Vec<_> = messages.try_collect().await?;

        for message in messages.iter() {
            // Get the email body
            let body_bytes = match message.body() {
                Some(b) => b,
                None => {
                    eprintln!(
                        "Skipping UID {}: No body content found",
                        message.uid.unwrap_or(0)
                    );
                    continue;
                }
            };

            let parsed = match mailparse::parse_mail(body_bytes) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Failed to parse email: {}", e);
                    continue;
                }
            };

            // Extract Message-ID
            // let id = parsed
            //     .headers
            //     .get_first_value("Message-ID")
            //     .unwrap_or_else(|| format!("no-id-{}", message.uid.unwrap_or(0)));

            // Extract UID
            let uid = message.uid.expect("message did not have a UID!");

            // Extract Subject
            let subject = parsed
                .headers
                .get_first_value("Subject")
                .unwrap_or_else(|| String::from("(no subject)"));

            // Extract Sender (From)
            let sender = parsed
                .headers
                .get_first_value("From")
                .unwrap_or_else(|| String::from("(unknown sender)"));

            // Extract Recipient (To)
            let recipient = parsed
                .headers
                .get_first_value("To")
                .unwrap_or_else(|| String::from("(unknown recipient)"));

            // Extract Date
            let date_str = parsed
                .headers
                .get_first_value("Date")
                .unwrap_or_else(|| "(no date)".into());

            // Use parse_from_rfc2822 instead of the default .parse()
            let date = DateTime::parse_from_rfc2822(&date_str)
                .map(|dt| dt.with_timezone(&Utc)) // Convert FixedOffset to Utc
                .unwrap_or_else(|e| {
                    eprintln!("Warning: Failed to parse date '{}': {}", date_str, e);
                    Utc::now()
                });

            // Extract body text
            let body_text = parsed.get_body()?.trim().to_string();

            let email = Email {
                uid,
                subject,
                sender,
                recipient,
                date,
                body: body_text,
            };

            all_emails.push(email);
        }
    }

    Ok(all_emails)
}

/// Recursively evaluate a condition against an email
fn evaluate_condition(email: &Email, condition: &Condition) -> bool {
    match condition.condition_type.as_str() {
        "subject_contains" => condition.value.as_ref().map_or(false, |v| {
            email.subject.to_lowercase().contains(&v.to_lowercase())
        }),
        "subject_is" => condition
            .value
            .as_ref()
            .map_or(false, |v| email.subject.to_lowercase() == v.to_lowercase()),
        "from_contains" => condition.value.as_ref().map_or(false, |v| {
            email.sender.to_lowercase().contains(&v.to_lowercase())
        }),
        "from_is" => condition
            .value
            .as_ref()
            .map_or(false, |v| email.sender.to_lowercase() == v.to_lowercase()),
        "to_contains" => condition.value.as_ref().map_or(false, |v| {
            email.recipient.to_lowercase().contains(&v.to_lowercase())
        }),
        "to_is" => condition.value.as_ref().map_or(false, |v| {
            email.recipient.to_lowercase() == v.to_lowercase()
        }),
        "body_contains" => condition.value.as_ref().map_or(false, |v| {
            email.body.to_lowercase().contains(&v.to_lowercase())
        }),
        "body_is" => condition
            .value
            .as_ref()
            .map_or(false, |v| email.body.to_lowercase() == v.to_lowercase()),
        // the example date value should be in the format "YYYY-MM-DDTHH:MM:SSZ"
        "before" => condition.value.as_ref().map_or(false, |v| {
            let target_date = v.parse::<DateTime<Utc>>().expect("Invalid condition date");

            let email_date = email.date;

            email_date < target_date
        }),
        "after" => condition.value.as_ref().map_or(false, |v| {
            let target_date = v.parse::<DateTime<Utc>>().expect("Invalid condition date");

            let email_date = email.date;

            email_date > target_date
        }),
        "and" => condition.conditions.as_ref().map_or(false, |conds| {
            conds.iter().all(|c| evaluate_condition(email, c))
        }),
        "or" => condition.conditions.as_ref().map_or(false, |conds| {
            conds.iter().any(|c| evaluate_condition(email, c))
        }),
        _ => {
            eprintln!("Unknown condition type: {}", condition.condition_type);
            false
        }
    }
}

/// Execute an action on a specific email
async fn execute_action(
    session: &mut ImapSession,
    email: &Email,
    action: &Action,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match action.action_type.as_str() {
        "move_to_folder" => {
            if let Some(folder) = &action.folder {
                // Fix: Wrap the folder name in double quotes for IMAP safety
                let quoted_folder = format!("\"{}\"", folder);

                session
                    .uid_copy(email.uid.to_string(), &quoted_folder)
                    .await?;
                let _updates: Vec<_> = session
                    .uid_store(email.uid.to_string(), "+FLAGS (\\Deleted)")
                    .await?
                    .try_collect()
                    .await?;
                println!("Moved '{}' to folder '{}'", email.subject, folder);
            } else {
                eprintln!("Move action missing folder");
            }
        }
        "mark_as_read" => {
            // Fix: Use +FLAGS to add the \Seen flag (marking it as read)
            let _updates: Vec<_> = session
                .uid_store(email.uid.to_string(), "+FLAGS (\\Seen)")
                .await?
                .try_collect()
                .await?;
            println!("Marked '{}' as read", email.subject);
        }
        "delete" => {
            let _updates: Vec<_> = session
                .uid_store(email.uid.to_string(), "+FLAGS (\\Deleted)")
                .await?
                .try_collect()
                .await?;
            println!("Deleted '{}'", email.subject);
        }
        "flag" => {
            let _updates: Vec<_> = session
                .uid_store(email.uid.to_string(), "+FLAGS (\\Flagged)")
                .await?
                .try_collect()
                .await?;
            println!("Flagged '{}'", email.subject);
        }
        _ => eprintln!("Unknown action type: {}", action.action_type),
    }
    Ok(())
}

/// Process emails through filters and execute actions
async fn process_emails_with_filters(
    session: &mut ImapSession,
    emails: &[Email],
    email_config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Sort filters by priority (highest first)
    let mut sorted_filters = email_config.filters.clone();
    sorted_filters.sort_by(|a, b| b.priority.cmp(&a.priority));

    for email in emails {
        log!("Processing email: {}", email.subject);

        // Find first matching filter (highest priority)
        for filter in &sorted_filters {
            if !filter.enabled {
                continue;
            }

            if evaluate_condition(email, &filter.condition) {
                execute_action(session, email, &filter.action).await?;
                break; // Only execute highest priority matching filter
            }
        }
    }

    // Expunge deleted emails
    let _expunged: Vec<_> = session.expunge().await?.try_collect().await?;

    Ok(())
}
