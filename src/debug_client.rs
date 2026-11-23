use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use sha2::Sha256;
use tokio::io::BufReader;
use tokio_util::sync::CancellationToken;

use montclair_api::id::AccountId;
use montclair_api::id::DebugSessionId;
use montclair_api::id::UserId;
use montclair_git::GitClient;
use montclair_git::GitRemote;
use montclair_plan::config::ImageConfig;
use montclair_plan::config::JobConfig;
use montclair_protocol::channel::ChannelReceiver;
use montclair_protocol::channel::ChannelSender;
use montclair_protocol::channel::ChannelType;
use montclair_protocol::message::DebugClientMessage;
use montclair_protocol::message::Message;
use montclair_protocol::mux::MuxHandle;
use montclair_tracing::TError;

use crate::debug_client_mux::debug_client_mux_handle;
use crate::ssh_tunnel::DebugClientSshTunnel;
use crate::stdin::StdinStream;

pub enum DebugClientInteractiveCommand {
    /// Execute the step at the given index in the job.
    Exec { step_idx: usize },

    /// Execute the step at the given index in the job and continue executing until a step returns a non-zero exit code.
    ExecContinue { step_idx: usize },

    /// Start an interactive shell in the job.
    Shell,

    /// Move the interactive debug session cursor to a specific step in the job.
    Move { step_idx: usize },

    /// Quit the interactive debug session.
    Quit,
}

#[derive(Debug, thiserror::Error)]
#[error("DebugClientError: {0}")]
struct DebugClientError(String);

pub struct DebugClient {
    channel_tx: ChannelSender,
    channel_rx: ChannelReceiver,
    channel_closed: CancellationToken,
    mux_handle: MuxHandle,
    user_id: UserId,
    account_id: AccountId,
    debug_session_id: DebugSessionId,
}

impl DebugClient {
    #[tracing::instrument(skip_all)]
    pub async fn connect(
        client_shutdown: CancellationToken,
        server_domain: &str,
        user_id: &UserId,
        secret: &str,
        account_id: &AccountId,
        debug_session_id: &DebugSessionId,
    ) -> Result<Self, TError> {
        let mux_handle = debug_client_mux_handle(
            client_shutdown,
            server_domain,
            user_id,
            secret,
            account_id,
            debug_session_id,
        )
        .await?;

        let (channel_tx, mut channel_rx, channel_closed) =
            mux_handle.open_channel(ChannelType::DebugClient).await?;

        channel_tx
            .send(Message::DebugClient(
                DebugClientMessage::ConnectDebugClientRequest {
                    debug_session_id: debug_session_id.clone(),
                },
            ))
            .await?;

        channel_rx
            .recv()
            .await
            .ok_or_else(|| DebugClientError("Channel closed".to_string()))
            .and_then(|response| match response {
                Message::DebugClient(DebugClientMessage::ConnectDebugClientResponse { result }) => {
                    result.map_err(|e| DebugClientError(e.to_string()))
                }
                _ => Err(DebugClientError("Unexpected message type".to_string())),
            })?;

        Ok(Self {
            channel_tx,
            channel_rx,
            channel_closed,
            mux_handle,
            user_id: user_id.clone(),
            account_id: account_id.clone(),
            debug_session_id: debug_session_id.clone(),
        })
    }

    #[tracing::instrument(skip_all)]
    pub async fn prepare_sandbox(
        &mut self,
        image: ImageConfig,
        git_remote: GitRemote,
    ) -> Result<(), TError> {
        //
        // Create sandbox
        //
        self.channel_tx
            .send(Message::DebugClient(
                DebugClientMessage::CreateSandboxRequest { image },
            ))
            .await?;

        self.channel_rx
            .recv()
            .await
            .ok_or_else(|| DebugClientError("Channel closed".to_string()))
            .and_then(|response| match response {
                Message::DebugClient(DebugClientMessage::CreateSandboxResponse { result }) => {
                    result.map_err(|e| DebugClientError(e.to_string()))
                }
                _ => Err(DebugClientError("Unexpected message type".to_string())),
            })?;

        //
        // Checkout git remote branch into sandbox
        //
        self.channel_tx
            .send(Message::DebugClient(
                DebugClientMessage::CheckoutBranchRequest {
                    url: git_remote.url,
                    branch: git_remote.branch.clone(),
                },
            ))
            .await?;

        self.channel_rx
            .recv()
            .await
            .ok_or_else(|| TError::new("Channel closed"))
            .and_then(|response| match response {
                Message::DebugClient(DebugClientMessage::CheckoutBranchResponse { result }) => {
                    result.map_err(|e| TError::new(&e.to_string()))
                }
                _ => Err(TError::new("Unexpected message type")),
            })?;

        //
        // Send local diff to sandbox
        //
        let diff_file = {
            let mut diff_file = tempfile::NamedTempFile::new()?;
            let git_client = GitClient::try_default()?;
            let target_dir = PathBuf::from("./.git");
            git_client.create_diff(&target_dir, git_remote.branch, &mut diff_file)?;
            diff_file
        };

        self.channel_tx
            .send(Message::DebugClient(
                DebugClientMessage::StartDiffUploadRequest,
            ))
            .await?;

        self.channel_rx
            .recv()
            .await
            .ok_or_else(|| TError::new("Channel closed"))
            .and_then(|response| match response {
                Message::DebugClient(DebugClientMessage::StartDiffUploadResponse { result }) => {
                    result.map_err(|e| TError::new(&e.to_string()))
                }
                _ => Err(TError::new("Unexpected message type")),
            })?;

        let diff_file = tokio::fs::File::from_std(diff_file.reopen()?);

        use sha2::Digest;
        use tokio::io::AsyncBufReadExt;

        const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB
        let mut reader = BufReader::with_capacity(CHUNK_SIZE, diff_file);
        let mut diff_hasher = Sha256::new();

        loop {
            let buffer = reader.fill_buf().await?;
            let n = buffer.len();
            if n == 0 {
                break;
            }

            diff_hasher.update(buffer);

            let chunk = buffer.to_vec();
            self.channel_tx
                .send(Message::DebugClient(
                    DebugClientMessage::UploadDiffChunkRequest { chunk },
                ))
                .await?;

            self.channel_rx
                .recv()
                .await
                .ok_or_else(|| TError::new("Channel closed"))
                .and_then(|response| match response {
                    Message::DebugClient(DebugClientMessage::UploadDiffChunkResponse {
                        result,
                    }) => result.map_err(|e| TError::new(&e.to_string())),
                    _ => Err(TError::new("Unexpected message type")),
                })?;

            reader.consume(n);
        }

        let checksum = hex::encode(diff_hasher.finalize_reset());

        self.channel_tx
            .send(Message::DebugClient(
                DebugClientMessage::CompleteDiffUploadRequest { checksum },
            ))
            .await?;

        self.channel_rx
            .recv()
            .await
            .ok_or_else(|| TError::new("Channel closed"))
            .and_then(|response| match response {
                Message::DebugClient(DebugClientMessage::CompleteDiffUploadResponse { result }) => {
                    result.map_err(|e| TError::new(&e.to_string()))
                }
                _ => Err(TError::new("Unexpected message type")),
            })?;

        //
        // Apply local diff to sandbox
        //
        self.channel_tx
            .send(Message::DebugClient(DebugClientMessage::ApplyDiffRequest))
            .await?;

        self.channel_rx
            .recv()
            .await
            .ok_or_else(|| TError::new("Channel closed"))
            .and_then(|response| match response {
                Message::DebugClient(DebugClientMessage::ApplyDiffResponse { result }) => {
                    result.map_err(|e| TError::new(&e.to_string()))
                }
                _ => Err(TError::new("Unexpected message type")),
            })?;

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn start_interactive_session(
        &mut self,
        signal_receiver_enabled: Arc<AtomicBool>,
        job_opt: Option<JobConfig>,
    ) -> Result<(), TError> {
        let mut stdin = StdinStream::new();

        match job_opt {
            Some(job) => {
                let mut current_step: usize = 0;
                let mut step_success: Vec<Option<bool>> = vec![None; job.steps.len()];

                loop {
                    // print current state
                    println!("Job: {}", job.name);
                    println!("Steps:");
                    for (i, step) in job.steps.iter().enumerate() {
                        let status = if let Some(success) = step_success[i] {
                            if success { "✔" } else { "✘" }
                        } else {
                            "?"
                        };
                        let cursor = if i == current_step { ">" } else { " " };
                        println!(
                            "{} {} ({}) {}\n\t\"{}\"\n",
                            cursor,
                            status,
                            i + 1,
                            step.name,
                            step.command
                        );
                    }

                    println!("You can open a (s)hell, (m)ove, (n)ext, (c)ontinue, or (q)uit.");

                    print!("> ");
                    use std::io::Write;
                    std::io::stdout().flush()?;

                    // read user input line
                    let line = stdin.read_line().await?;

                    // parse into command
                    let mut parts = line.split_whitespace();
                    let command = parts.next();
                    let command = match command {
                        Some(command) => match command {
                            "s" | "shell" => DebugClientInteractiveCommand::Shell,
                            "m" | "move" => {
                                if let Some(i) = parts.next().and_then(|s| s.parse::<usize>().ok())
                                {
                                    DebugClientInteractiveCommand::Move { step_idx: i - 1 }
                                } else {
                                    DebugClientInteractiveCommand::Move {
                                        step_idx: current_step,
                                    }
                                }
                            }
                            "c" | "continue" => {
                                if let Some(i) = parts.next().and_then(|s| s.parse::<usize>().ok())
                                {
                                    DebugClientInteractiveCommand::ExecContinue { step_idx: i - 1 }
                                } else {
                                    DebugClientInteractiveCommand::ExecContinue {
                                        step_idx: current_step,
                                    }
                                }
                            }
                            "n" | "next" => DebugClientInteractiveCommand::Exec {
                                step_idx: current_step,
                            },
                            "q" | "quit" => DebugClientInteractiveCommand::Quit,
                            _ => {
                                println!("Unknown command: {}", line.trim());
                                continue;
                            }
                        },
                        None => continue,
                    };

                    // execute command
                    match command {
                        DebugClientInteractiveCommand::Quit => break,
                        DebugClientInteractiveCommand::Exec { step_idx } => {
                            println!("Executing next.");
                            // Execute the step pointed by current_step.
                            let step = job.steps.get(step_idx).unwrap().clone();
                            let exit_code = self
                                .exec(signal_receiver_enabled.clone(), &step.command)
                                .await?;
                            if exit_code == 0 {
                                step_success[step_idx] = Some(true);
                                if step_idx + 1 < job.steps.len() {
                                    current_step = step_idx + 1;
                                }
                            } else {
                                step_success[current_step] = Some(false);
                                current_step = step_idx;
                            }
                        }
                        DebugClientInteractiveCommand::ExecContinue { step_idx } => {
                            println!("Executing continue on {}", step_idx);
                            // Starting with step_idx, execute each step until the end or a failure.
                            current_step = step_idx;
                            loop {
                                if current_step >= job.steps.len() {
                                    break;
                                }

                                let step = job.steps.get(current_step).unwrap().clone();
                                let exit_code = self
                                    .exec(signal_receiver_enabled.clone(), &step.command)
                                    .await?;
                                if exit_code == 0 {
                                    step_success[current_step] = Some(true);
                                    if current_step + 1 < job.steps.len() {
                                        current_step += 1;
                                    } else if current_step + 1 == job.steps.len() {
                                        break;
                                    }
                                } else {
                                    step_success[current_step] = Some(false);
                                    // If a failure occurs, do not advance the current_step.
                                    break;
                                }
                            }
                        }
                        DebugClientInteractiveCommand::Shell => {
                            // Open an interactive shell for the step pointed by step_idx.
                            let _exit_code = self
                                .shell(signal_receiver_enabled.clone(), &mut stdin)
                                .await?;
                        }
                        DebugClientInteractiveCommand::Move { step_idx } => {
                            println!("Executing move on {}", step_idx);
                            // Move current_step to step_idx.
                            if step_idx < job.steps.len() {
                                current_step = step_idx;
                            } else {
                                println!("Step {} is out of bounds.", step_idx);
                            }
                        }
                    }

                    // update state
                }
            }
            None => {
                let _exit_code = self
                    .shell(signal_receiver_enabled.clone(), &mut stdin)
                    .await?;
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn exec(
        &mut self,
        signal_receiver_enabled: Arc<AtomicBool>,
        cmd: &str,
    ) -> Result<u32, TError> {
        self.channel_tx
            .send(Message::DebugClient(DebugClientMessage::StartShellRequest))
            .await?;

        self.channel_rx
            .recv()
            .await
            .ok_or_else(|| TError::new("Channel closed"))
            .and_then(|response| match response {
                Message::DebugClient(DebugClientMessage::StartShellResponse { result }) => {
                    result.map_err(|e| TError::new(&e.to_string()))
                }
                _ => Err(TError::new("Unexpected message type")),
            })?;

        let tunnel = DebugClientSshTunnel::connect(
            signal_receiver_enabled,
            self.mux_handle.clone(),
            &self.user_id,
            &self.account_id,
            &self.debug_session_id,
        )
        .await?;

        tunnel.exec(cmd).await
    }

    #[tracing::instrument(skip_all)]
    pub async fn shell(
        &mut self,
        signal_receiver_enabled: Arc<AtomicBool>,
        stdin: &mut StdinStream,
    ) -> Result<u32, TError> {
        self.channel_tx
            .send(Message::DebugClient(DebugClientMessage::StartShellRequest))
            .await?;

        self.channel_rx
            .recv()
            .await
            .ok_or_else(|| TError::new("Channel closed"))
            .and_then(|response| match response {
                Message::DebugClient(DebugClientMessage::StartShellResponse { result }) => {
                    result.map_err(|e| TError::new(&e.to_string()))
                }
                _ => Err(TError::new("Unexpected message type")),
            })?;

        let tunnel = DebugClientSshTunnel::connect(
            signal_receiver_enabled,
            self.mux_handle.clone(),
            &self.user_id,
            &self.account_id,
            &self.debug_session_id,
        )
        .await?;

        tunnel.shell(stdin).await
    }
}
