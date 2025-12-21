pub(crate) async fn get_quote_from_dstack(report_data: &str) -> anyhow::Result<String> {
    Ok(
        reqwest::get(format!("http://0.0.0.0:3030/quote/{}", hex::encode(report_data)))
            .await?
            .text()
            .await?,
    )
}

#[tokio::main]
async fn main() {
    let quote = get_quote_from_dstack("testdata").await;
    println!("{:?}", quote);
}

