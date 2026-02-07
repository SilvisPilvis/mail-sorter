use mailparse::{self, MailHeaderMap};
use native_tls;
use serde::{Deserialize, Serialize};
use toml;

use chrono::{DateTime, Utc};
use imap::Session;
use native_tls::TlsStream;
use std::net::TcpStream;

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

impl imap::Authenticator for GmailOAuth2 {
    type Response = String;
    #[allow(unused_variables)]
    fn process(&self, data: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.user, self.access_token
        )
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = "imap.gmail.com";
    let config_path = std::path::PathBuf::from("config.toml");

    let args: Vec<String> = std::env::args().collect();

    // Check if an argument exists to avoid a panic if the user runs it without args
    if args.len() < 2 {
        eprintln!("Usage: <program> [monitor|filter]");
        return Err("Incorrect arguments".into());
    }

    // Load config
    let config: Config = toml::from_str(&std::fs::read_to_string(config_path)?)?;
    log!("Loaded {} filters from config", config.filters.len());

    // Connect to IMAP
    let gmail_auth = GmailOAuth2 {
        user: String::from("silvestrsl47@gmail.com"),
        access_token: String::from("yste jmmi nmga xxwg"),
    };

    let tls = native_tls::TlsConnector::builder().build()?;
    let client = imap::connect((domain, 993), domain, &tls)?;
    let mut session = client
        .login(gmail_auth.user, gmail_auth.access_token)
        .unwrap();

    // Select INBOX (read-write mode required for moving/deleting)
    let mailbox = session.select("INBOX")?;
    log!("Connected to INBOX with {} messages", mailbox.exists);

    match args[1].as_str() {
        "monitor" => {
            log!("Running in monitor mode.");
            let err = monitor_inbox(&mut session, &config);
            match err {
                Ok(_) => {}
                Err(e) => {
                    eprint!("Error in monitor mode: {}", e);
                }
            }
            let _ = &session.logout()?;
        }
        "filter" => {
            log!("Running in filter mode.");
            // Fetch emails
            let emails = fetch_emails_by_uid_batches(&mut session, "INBOX", 50)?;

            // Process with filters
            if !emails.is_empty() {
                process_emails_with_filters(&mut session, &emails, &config)?;
            }
            // Clean logout
            println!("\nMailbox filtered successfully");
            session.logout()?;
        }
        _ => eprint!("Unknown argument {}", args[1]),
    }

    Ok(())
}

fn fetch_latest_email(
    session: &mut Session<TlsStream<TcpStream>>,
    mailbox_name: &str,
) -> Result<Email, Box<dyn std::error::Error>> {
    session.select(mailbox_name)?;

    // Get the highest UID (most recent email)
    let uids = session.uid_search("ALL")?;
    let latest_uid = uids.iter().max().ok_or("No messages in mailbox")?;

    // Fetch that specific email
    let fetch_result = session.uid_fetch(format!("{}", latest_uid), "RFC822")?;

    // -- MOST OPTIMAL
    // Get highest sequence number (not UID) to fetch latest in one command
    // let mailbox = session.select(mailbox_name)?;
    // let latest_seq = mailbox.exists; // Highest = most recent

    // Fetch only that one message
    // let fetch_result = session.fetch(format!("{}", latest_seq), "RFC822")?;
    // --

    // Fetch the latest email
    let message = fetch_result.first().ok_or("No messages in mailbox")?;

    let body_bytes = match message.body() {
        Some(b) => b,
        None => {
            eprintln!(
                "Skipping UID {}: No body content found",
                message.uid.unwrap_or(0)
            );
            return Err("No body content found".into());
        }
    };

    let parsed = match mailparse::parse_mail(body_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to parse email: {}", e);
            return Err("Failed to parse email".into());
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
fn monitor_inbox(
    session: &mut Session<TlsStream<TcpStream>>, // Change to &mut
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    log!("Using IDLE to monitor incoming emails in realtime.");
    let mailbox = session.select("INBOX")?;

    // Track the highest UID we've already processed
    let mut last_processed_uid = session
        .uid_search("ALL")?
        .iter()
        .max()
        .cloned()
        .unwrap_or(0);

    loop {
        let mut idle = session.idle()?;
        idle.set_keepalive(std::time::Duration::from_secs(60 * 10));

        match idle.wait_keepalive() {
            Ok(_) => {
                log!("{} New emails recived.", mailbox.exists);
                // Get current max UID
                let current_uids = session.uid_search("ALL")?;
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
                        session,
                        "INBOX",
                        last_processed_uid + 1,
                        current_max_uid,
                    )?;

                    // Process all new emails
                    process_emails_with_filters(session, &new_emails, config)?;

                    // Update last processed UID
                    last_processed_uid = current_max_uid;
                }
            }
            Err(e) => {
                // println!("Error waiting for IDLE: {}", e);
                // log!("Error waiting for IDLE: {}", e);
                // session.logout()?;
                return Err(format!("Failed waiting for IDLE: {}", e).into());
            }
        }
    }
}

fn fetch_emails_by_uid_range(
    session: &mut Session<TlsStream<TcpStream>>,
    mailbox: &str,
    start_uid: u32,
    end_uid: u32,
) -> Result<Vec<Email>, Box<dyn std::error::Error>> {
    session.select(mailbox)?;

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
    let messages = session.uid_fetch(uid_range, "BODY.PEEK[]")?;

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
fn fetch_emails_by_uid_batches(
    session: &mut Session<TlsStream<TcpStream>>,
    mailbox: &str,
    batch_size: u32,
) -> Result<Vec<Email>, Box<dyn std::error::Error>> {
    session.select(mailbox)?;

    // Search for all UIDs
    let uids = session.uid_search("ALL")?;

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
        let messages = session.uid_fetch(uid_range, "RFC822")?;

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
fn execute_action(
    session: &mut Session<TlsStream<TcpStream>>,
    email: &Email,
    action: &Action,
) -> Result<(), imap::Error> {
    match action.action_type.as_str() {
        "move_to_folder" => {
            if let Some(folder) = &action.folder {
                // Fix: Wrap the folder name in double quotes for IMAP safety
                let quoted_folder = format!("\"{}\"", folder);

                session.uid_copy(email.uid.to_string(), &quoted_folder)?;
                session.uid_store(email.uid.to_string(), "+FLAGS (\\Deleted)")?;
                println!("Moved '{}' to folder '{}'", email.subject, folder);
            } else {
                eprintln!("Move action missing folder");
            }
        }
        "mark_as_read" => {
            // Fix: Use +FLAGS to add the \Seen flag (marking it as read)
            session.uid_store(email.uid.to_string(), "+FLAGS (\\Seen)")?;
            println!("Marked '{}' as read", email.subject);
        }
        "delete" => {
            session.uid_store(email.uid.to_string(), "+FLAGS (\\Deleted)")?;
            println!("Deleted '{}'", email.subject);
        }
        "flag" => {
            session.uid_store(email.uid.to_string(), "+FLAGS (\\Flagged)")?;
            println!("Flagged '{}'", email.subject);
        }
        _ => eprintln!("Unknown action type: {}", action.action_type),
    }
    Ok(())
}

/// Process emails through filters and execute actions
fn process_emails_with_filters(
    session: &mut Session<TlsStream<TcpStream>>,
    emails: &[Email],
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // Sort filters by priority (highest first)
    let mut sorted_filters = config.filters.clone();
    sorted_filters.sort_by(|a, b| b.priority.cmp(&a.priority));

    for email in emails {
        log!("Processing email: {}", email.subject);

        // Find first matching filter (highest priority)
        for filter in &sorted_filters {
            if !filter.enabled {
                continue;
            }

            if evaluate_condition(email, &filter.condition) {
                execute_action(session, email, &filter.action)?;
                break; // Only execute highest priority matching filter
            }
        }
    }

    // Expunge deleted emails
    session.expunge()?;

    Ok(())
}
