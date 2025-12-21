use std::{path::PathBuf, sync::Arc};

use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufWriter},
    process::Command,
    sync::mpsc,
    task::JoinSet,
};
use tokio_util::io::ReaderStream;
use warp::{reject::Rejection, reply::Reply};

pub struct LogsManager {
    busy: bool,
    rx: mpsc::Receiver<LogManagerInstruction>,
}

pub enum LogManagerInstruction {
    RequestLogs,
    JobComplete,
}

impl LogsManager {
    pub fn new(rx: mpsc::Receiver<LogManagerInstruction>) -> Self {
        Self { rx, busy: false }
    }

    pub async fn worker(&mut self, internal_tx: mpsc::Sender<LogManagerInstruction>) {
        while let Some(task) = self.rx.recv().await {
            match task {
                LogManagerInstruction::RequestLogs => self.collect_logs(internal_tx.clone()).await,
                LogManagerInstruction::JobComplete => self.set_free(),
            }
        }
    }

    async fn collect_logs(&mut self, internal_tx: mpsc::Sender<LogManagerInstruction>) {
        if !self.is_busy() {
            self.set_busy();
            tokio::spawn(async move {
                let _ = collect_podman_logs().await;
                let _ = internal_tx.send(LogManagerInstruction::JobComplete).await;
            });
        }
    }

    fn is_busy(&mut self) -> bool {
        self.busy
    }

    fn set_busy(&mut self) {
        self.busy = true
    }

    fn set_free(&mut self) {
        tracing::info!("job completed");
        self.busy = false;
    }
}

async fn collect_podman_logs() -> Result<(), std::io::Error> {
    let path: PathBuf = std::env::temp_dir().join("podman_dump.log");

    let id_output = Command::new("podman").args(["ps", "-q"]).output().await?;
    let ids: Vec<String> = String::from_utf8_lossy(&id_output.stdout)
        .lines()
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
        .collect();

    tracing::info!("got ids {:?}", ids);

    let file = File::create(&path).await?;
    let mut writer = BufWriter::new(file);

    let mut set = JoinSet::new();
    for id in ids {
        set.spawn(async move {
            let out = Command::new("podman").args(["logs", &id]).output().await?;
            let mut buf = String::with_capacity(out.stdout.len() + 128);
            buf.push_str(&format!("{id}\n"));
            buf.push_str(&String::from_utf8_lossy(&out.stdout));
            buf.push_str("\n\n");
            Ok::<_, std::io::Error>(buf)
        });
    }

    while let Some(res) = set.join_next().await {
        let chunk = res??;
        writer.write_all(chunk.as_bytes()).await?;
    }
    writer.flush().await?;

    Ok(())
}

pub async fn download_handler() -> Result<impl Reply, Rejection> {
    let path: PathBuf = std::env::temp_dir().join("podman_dump.log");

    println!("{:?}", path);

    let file = File::open(&path).await.map_err(|_| warp::reject())?;
    let stream = ReaderStream::new(file);
    Ok(warp::reply::Response::new(warp::hyper::Body::wrap_stream(
        stream,
    )))
}

pub async fn handle_logs_request(
    sender: Arc<mpsc::Sender<LogManagerInstruction>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let _ = sender.send(LogManagerInstruction::RequestLogs).await;

    Ok(warp::reply::with_status(
        "forwared to internal log manager worker",
        warp::http::StatusCode::OK,
    ))
}
