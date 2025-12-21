use crate::{Wrapper, signer::AttestedSigner};
use bytes::Bytes;
use std::sync::Arc;
use tokio::{
    process::Command,
    sync::{mpsc, oneshot},
};

mod quote;

pub struct PodManager {
    rx: mpsc::Receiver<PodManagerInstruction>,
    pub(crate) loaded_pods: Vec<[u8; 48]>,
    pub(crate) signer: Option<AttestedSigner>,
    pub(crate) initialized: bool,
}

pub enum PodManagerInstruction {
    CreatePod(Bytes),
    RequestQuote((String, oneshot::Sender<Result<String, warp::Rejection>>)),
    RequestPods(oneshot::Sender<Vec<[u8; 48]>>),
    RequestInfo(oneshot::Sender<Result<InfoResponse, warp::Rejection>>),
    RequestSignerSecret(oneshot::Sender<Result<String, warp::Rejection>>),
    FinalizeDeployment(oneshot::Sender<Result<String, warp::Rejection>>),
}

#[derive(serde::Serialize)]
pub struct InfoResponse {
    pub pubkey: String,
    pub quote: String,
    pub container_hashes: Vec<String>,
    pub container_signatures: Vec<String>,
}

impl PodManager {
    pub fn new(rx: mpsc::Receiver<PodManagerInstruction>) -> Self {
        Self {
            rx,
            loaded_pods: Vec::new(),
            signer: None,
            initialized: false,
        }
    }

    fn aggregate_digest(&self) -> Vec<u8> {
        self.loaded_pods.concat().to_vec()
    }

    pub async fn worker(&mut self) {
        let _ = Command::new("podman")
            .args(&["pull", "k8s.gcr.io/pause:3.8"])
            .status()
            .await;

        let _ = Command::new("sed")
            .args(&[
                "-i",
                "/^\\[engine\\]/a infra_image = \"k8s.gcr.io/pause:3.8\"",
                "/etc/containers/containers.conf",
            ])
            .status()
            .await;

        self.initialize_signer().await;

        while let Some(task) = self.rx.recv().await {
            match task {
                PodManagerInstruction::CreatePod(pod_config) => {
                    let _ = self.handle_pod_yml(pod_config).await;
                }

                PodManagerInstruction::RequestQuote((report_data, sender)) => {
                    let resp = self.get_quote(report_data).await;
                    let _ = sender.send(resp);
                }

                PodManagerInstruction::RequestPods(sender) => {
                    let pods = self.loaded_pods.clone();
                    let _ = sender.send(pods);
                }

                PodManagerInstruction::RequestInfo(sender) => {
                    let resp = self.get_info().await;
                    let _ = sender.send(resp);
                }

                PodManagerInstruction::RequestSignerSecret(sender) => {
                    let resp = self.get_signer_secret();
                    let _ = sender.send(resp);
                }

                PodManagerInstruction::FinalizeDeployment(sender) => {
                    let resp = self.finalize_deployment();
                    let _ = sender.send(resp);
                }
            }
        }
    }

    async fn initialize_signer(&mut self) {
        tracing::info!("initializing attested signer");
        let mut signer = AttestedSigner::new();

        let pubkey_bytes = signer.public_key_bytes();
        let quote = quote::get_quote(&pubkey_bytes).await;

        match quote {
            Ok(q) => {
                signer.set_pubkey_quote(q);
                tracing::info!("attested signer initialized with pubkey: {}", signer.public_key_hex());
                self.signer = Some(signer);
            }
            Err(e) => {
                tracing::error!("failed to get quote for signer pubkey: {:?}", e);
            }
        }
    }

    fn finalize_deployment(&mut self) -> Result<String, warp::Rejection> {
        if self.initialized {
            return Err(warp::reject::custom(Wrapper(
                "deployment already finalized".into(),
            )));
        }

        if self.loaded_pods.is_empty() {
            return Err(warp::reject::custom(Wrapper(
                "no pods loaded, cannot finalize".into(),
            )));
        }

        match &mut self.signer {
            Some(signer) => {
                let pods_ref: Vec<[u8; 48]> = self.loaded_pods.clone();
                signer
                    .sign_container_hashes(&pods_ref)
                    .map_err(|e| warp::reject::custom(Wrapper(format!("signing failed: {}", e))))?;

                self.initialized = true;
                tracing::info!("deployment finalized with {} pods", self.loaded_pods.len());

                Ok(format!(
                    "deployment finalized with {} container(s)",
                    self.loaded_pods.len()
                ))
            }
            None => Err(warp::reject::custom(Wrapper(
                "signer not initialized".into(),
            ))),
        }
    }

    fn get_signer_secret(&self) -> Result<String, warp::Rejection> {
        match &self.signer {
            Some(signer) => {
                let secret_bytes = signer.get_signing_key_bytes();
                Ok(hex::encode(secret_bytes))
            }
            None => Err(warp::reject::custom(Wrapper(
                "signer not initialized".into(),
            ))),
        }
    }

    async fn get_info(&self) -> Result<InfoResponse, warp::Rejection> {
        match &self.signer {
            Some(signer) => {
                let pubkey = signer.public_key_hex();
                let quote = signer
                    .get_pubkey_quote()
                    .ok_or_else(|| warp::reject::custom(Wrapper("quote not available".into())))?
                    .to_string();

                let container_hashes: Vec<String> =
                    self.loaded_pods.iter().map(hex::encode).collect();

                let container_signatures: Vec<String> =
                    signer.get_container_signatures().to_vec();

                Ok(InfoResponse {
                    pubkey,
                    quote,
                    container_hashes,
                    container_signatures,
                })
            }
            None => Err(warp::reject::custom(Wrapper(
                "signer not initialized".into(),
            ))),
        }
    }

    async fn get_quote(&self, report_data: String) -> Result<String, warp::Rejection> {
        let report_data = [
            self.aggregate_digest(),
            hex::decode(report_data).map_err(|_| Wrapper("invalid hex".into()))?,
        ]
        .concat();

        let quote = quote::get_quote(&report_data).await;

        match quote {
            Ok(quote) => {
                tracing::info!("successfully obtained quote");
                Ok(quote)
            }

            Err(e) => {
                tracing::error!("failed to obtain quote: {:?}", e);
                Ok("failed to get quote".into())
            }
        }
    }
}

pub async fn handle_quote_request(
    report_data: String,
    sender: Arc<mpsc::Sender<PodManagerInstruction>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let (one_sender, quote) = oneshot::channel();
    let _ = sender
        .send(PodManagerInstruction::RequestQuote((
            report_data,
            one_sender,
        )))
        .await;

    let quote = quote
        .await
        .map_err(|_| Wrapper("oneshot sender dropped unexpectedly".into()))??;
    Ok(warp::reply::with_status(quote, warp::http::StatusCode::OK))
}

pub async fn handle_info_request(
    sender: Arc<mpsc::Sender<PodManagerInstruction>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let (one_sender, info) = oneshot::channel();
    let _ = sender.send(PodManagerInstruction::RequestInfo(one_sender)).await;

    let info = info
        .await
        .map_err(|_| Wrapper("oneshot sender dropped unexpectedly".into()))??;
    Ok(warp::reply::json(&info))
}

pub async fn handle_signer_secret_request(
    sender: Arc<mpsc::Sender<PodManagerInstruction>>,
    remote_addr: Option<std::net::SocketAddr>,
) -> Result<impl warp::Reply, warp::Rejection> {
    if let Some(addr) = remote_addr {
        if !addr.ip().is_loopback() {
            return Err(warp::reject::custom(Wrapper(
                "signer secret only accessible from localhost".into(),
            )));
        }
    } else {
        return Err(warp::reject::custom(Wrapper(
            "unable to determine remote address".into(),
        )));
    }

    let (one_sender, secret) = oneshot::channel();
    let _ = sender
        .send(PodManagerInstruction::RequestSignerSecret(one_sender))
        .await;

    let secret = secret
        .await
        .map_err(|_| Wrapper("oneshot sender dropped unexpectedly".into()))??;
    Ok(warp::reply::with_status(secret, warp::http::StatusCode::OK))
}

pub async fn handle_finalize_deployment(
    sender: Arc<mpsc::Sender<PodManagerInstruction>>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let (one_sender, result) = oneshot::channel();
    let _ = sender
        .send(PodManagerInstruction::FinalizeDeployment(one_sender))
        .await;

    let result = result
        .await
        .map_err(|_| Wrapper("oneshot sender dropped unexpectedly".into()))??;
    Ok(warp::reply::with_status(result, warp::http::StatusCode::OK))
}
