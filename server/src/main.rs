use std::sync::Arc;

use debug::{LogsManager, download_handler, handle_logs_request};
use podman::{handle_pod_yml, handle_request_pods};

use tdx::{PodManager, handle_quote_request, handle_info_request, handle_signer_secret_request, handle_finalize_deployment};
use tokio::sync::mpsc;
use tracing::{Level, info};
use warp::{Filter, reject::Reject};

mod debug;
mod podman;
mod tdx;
mod signer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    let (tx, rx) = mpsc::channel(10);

    let sender = Arc::new(tx.clone());
    let sender = warp::any().map(move || Arc::clone(&sender));

    let (logs_tx, logs_rx) = mpsc::channel(10);

    let logs_sender = Arc::new(logs_tx.clone());
    let logs_sender = warp::any().map(move || Arc::clone(&logs_sender));

    tokio::spawn(async {
        let mut manager = PodManager::new(rx);
        manager.worker().await;
    });

    tokio::spawn(async {
        let mut manager = LogsManager::new(logs_rx);
        manager.worker(logs_tx).await;
    });

    let pods = warp::post()
        .and(warp::path!("pods" / "deploy"))
        .and(sender.clone())
        .and(warp::body::bytes())
        .and_then(handle_pod_yml);

    let list_pods = warp::get()
        .and(warp::path("pods"))
        .and(sender.clone())
        .and_then(handle_request_pods);

    let get_quote = warp::get()
        .and(warp::path!("quote" / String))
        .and(sender.clone())
        .and_then(handle_quote_request);

    let status = warp::get()
        .and(warp::path("status"))
        .map(|| warp::reply::json(&serde_json::json!({"status": "ok"})));

    let download_logs = warp::path!("logs")
        .and(warp::get())
        .and_then(download_handler);

    let get_logs = warp::post()
        .and(warp::path!("logs" / "dump"))
        .and(logs_sender)
        .and_then(handle_logs_request);

    let get_info = warp::get()
        .and(warp::path("info"))
        .and(sender.clone())
        .and_then(handle_info_request);

    let get_signer_secret = warp::get()
        .and(warp::path!("signer" / "secret"))
        .and(sender.clone())
        .and(warp::addr::remote())
        .and_then(handle_signer_secret_request);

    let finalize = warp::post()
        .and(warp::path!("pods" / "finalize"))
        .and(sender)
        .and_then(handle_finalize_deployment);

    info!("Server running at http://0.0.0.0:3030");
    let routes = pods
        .or(status)
        .or(get_quote)
        .or(list_pods)
        .or(download_logs)
        .or(get_logs)
        .or(get_info)
        .or(get_signer_secret)
        .or(finalize);
    warp::serve(routes).run(([0, 0, 0, 0], 3030)).await;
}

#[derive(Debug)]
pub struct Wrapper(pub String);

impl Reject for Wrapper {}
