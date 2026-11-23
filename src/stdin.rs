use std::io::Read;
use tokio::sync::mpsc;

/// Centralized Stdin handle passed around the application
pub struct StdinStream {
    rx: mpsc::Receiver<Vec<u8>>,
    buffer: Vec<u8>, // Remainder buffer for CLI line parsing
}

impl StdinStream {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(32);

        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            loop {
                let mut buf = [0u8; 128];
                let result = stdin.read(&mut buf);
                match result {
                    Ok(n) => {
                        if tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break; // App exiting
                        }
                    }
                    _ => break,
                }
            }
        });

        Self {
            rx,
            buffer: Vec::new(),
        }
    }

    pub async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        // Drain any leftover buffered bytes first
        if !self.buffer.is_empty() {
            return Some(std::mem::take(&mut self.buffer));
        }

        self.rx.recv().await
    }

    pub async fn read_line(&mut self) -> std::io::Result<String> {
        loop {
            // Check if we already have a full line in our remainder buffer
            if let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
                let line_bytes = self.buffer.drain(..=pos).collect::<Vec<u8>>();
                let line_str = String::from_utf8(line_bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                return Ok(line_str);
            }

            // Wait for next byte chunk from the single stdin task
            match self.rx.recv().await {
                Some(chunk) => self.buffer.extend_from_slice(&chunk),
                None => {
                    let e = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF");
                    return Err(e);
                }
            }
        }
    }
}
