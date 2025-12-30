use crate::{extract_tables_from_sql, SqlEvent};
use chrono::Utc;
use log::info;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// SQL Event Logger
/// Logs SQL events to files and console.
/// Creates two log files:
/// 1. sql_capture_*.log - SQL text only
/// 2. sql_capture_raw_*.log - SQL text + raw data (Hex)
pub struct SqlLogger {
    log_file: Option<Arc<Mutex<std::fs::File>>>, // SQL text only
    log_file_path: Option<String>,
    raw_log_file: Option<Arc<Mutex<std::fs::File>>>, // SQL text + raw data
    raw_log_file_path: Option<String>,
}

impl SqlLogger {
    /// Create a new logger
    pub fn new() -> Self {
        Self {
            log_file: None,
            log_file_path: None,
            raw_log_file: None,
            raw_log_file_path: None,
        }
    }

    /// Start capture - Create log files and write headers
    pub fn start_capture(&mut self, interface: Option<&String>) -> Result<String, String> {
        // Create log directories
        std::fs::create_dir_all("log/basic")
            .map_err(|e| format!("Failed to create log/basic directory: {}", e))?;
        std::fs::create_dir_all("log/raw")
            .map_err(|e| format!("Failed to create log/raw directory: {}", e))?;

        let now = Utc::now();
        let timestamp_str = now.format("%Y%m%d_%H%M%S").to_string();

        // Log file with SQL text only (in log/basic/)
        let log_filename = format!("sql_capture_{}.log", timestamp_str);
        let log_path = Path::new("log/basic").join(&log_filename);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| format!("Failed to create log file: {}", e))?;

        // Log file with raw data included (in log/raw/)
        let raw_log_filename = format!("sql_capture_{}.log", timestamp_str);
        let raw_log_path = Path::new("log/raw").join(&raw_log_filename);

        let raw_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&raw_log_path)
            .map_err(|e| format!("Failed to create raw data log file: {}", e))?;

        // Write header
        let header = format!(
            "\n{}\nCapture Started: {}\nInterface: {}\n{}\n\n",
            "=".repeat(80),
            now.format("%Y-%m-%d %H:%M:%S%.3f"),
            interface.unwrap_or(&"N/A".to_string()),
            "=".repeat(80)
        );

        // Write header to SQL text log file
        if let Ok(mut f) = file.try_clone() {
            let _ = f.write_all(header.as_bytes());
            let _ = f.flush();
        }

        // Write header to raw data log file
        if let Ok(mut f) = raw_file.try_clone() {
            let _ = f.write_all(header.as_bytes());
            let _ = f.flush();
        }

        self.log_file = Some(Arc::new(Mutex::new(file)));
        let log_file_path_str = format!("log/basic/{}", log_filename);
        self.log_file_path = Some(log_file_path_str.clone());

        self.raw_log_file = Some(Arc::new(Mutex::new(raw_file)));
        let raw_log_file_path_str = format!("log/raw/{}", raw_log_filename);
        self.raw_log_file_path = Some(raw_log_file_path_str);

        Ok(log_file_path_str)
    }

    /// Log SQL event
    pub fn log_event(&self, event: &SqlEvent) {
        let timestamp = event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f");

        // Extract table information
        let tables = if event.tables.is_empty() {
            extract_tables_from_sql(&event.sql_text)
        } else {
            event.tables.clone()
        };

        let tables_str = if tables.is_empty() {
            "N/A".to_string()
        } else {
            tables.join(", ")
        };

        // Log message with SQL text only
        let log_message = format!(
            "\n{}\nTimestamp: {}\nFlow: {}\nTables: {}\nSQL:\n{}\n{}\n",
            "=".repeat(80),
            timestamp,
            event.flow_id,
            tables_str,
            event.sql_text,
            "=".repeat(80)
        );

        // Log message with raw data included
        let raw_log_message = if let Some(ref raw_data) = event.raw_data {
            // Generate hex string (16 bytes per line)
            let hex_string: String = raw_data
                .chunks(16)
                .enumerate()
                .map(|(i, chunk)| {
                    let hex: String = chunk
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let offset = i * 16;
                    format!("{:08x}:  {}", offset, hex)
                })
                .collect::<Vec<_>>()
                .join("\n");

            format!(
                "\n{}\nTimestamp: {}\nFlow: {}\nTables: {}\nSQL:\n{}\n\nRaw Data (Hex):\n{}\n{}\n",
                "=".repeat(80),
                timestamp,
                event.flow_id,
                tables_str,
                event.sql_text,
                hex_string,
                "=".repeat(80)
            )
        } else {
            // If raw_data is not available, include SQL text only
            log_message.clone()
        };

        // Output to console
        info!("{}", log_message);

        // Output to SQL text only file
        if let Some(ref log_file) = self.log_file {
            if let Ok(mut file) = log_file.lock() {
                let _ = file.write_all(log_message.as_bytes());
                let _ = file.flush();
            }
        }

        // Output to raw data file
        if let Some(ref raw_log_file) = self.raw_log_file {
            if let Ok(mut file) = raw_log_file.lock() {
                let _ = file.write_all(raw_log_message.as_bytes());
                let _ = file.flush();
            }
        }
    }

    /// Stop capture - Write footer
    pub fn stop_capture(&mut self, event_count: usize) {
        let now = Utc::now();
        let footer = format!(
            "\n{}\nCapture Stopped: {}\nTotal Events: {}\n{}\n",
            "=".repeat(80),
            now.format("%Y-%m-%d %H:%M:%S%.3f"),
            event_count,
            "=".repeat(80)
        );

        // Write footer to SQL text log file
        if let Some(ref log_file) = self.log_file {
            if let Ok(mut file) = log_file.lock() {
                let _ = file.write_all(footer.as_bytes());
                let _ = file.flush();
            }
        }

        // Write footer to raw data log file
        if let Some(ref raw_log_file) = self.raw_log_file {
            if let Ok(mut file) = raw_log_file.lock() {
                let _ = file.write_all(footer.as_bytes());
                let _ = file.flush();
            }
        }
    }

    /// Get log file path
    pub fn get_file_path(&self) -> Option<&String> {
        self.log_file_path.as_ref()
    }
}

impl Default for SqlLogger {
    fn default() -> Self {
        Self::new()
    }
}
