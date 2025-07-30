use std::{env, thread, time::Duration};

use reqwest::Client;
use anyhow::{bail, Error, Ok, Result};
use dotenv::dotenv;
use crate::Output;

pub async fn verify_proof(proof_output: Output) -> Result<String, anyhow::Error>{

    const API_URL: &str = "https://relayer-api.horizenlabs.io/api/v1";

    dotenv().ok();
    let api_key = env::var("API_KEY")?;

    let client = Client::new();

    let submit_params = serde_json::json!({
        "proofType": "sp1",
        "vkRegistered": false,
        "proofData": {
            "proof": proof_output.proof,
            "publicSignals": proof_output.pub_inputs,
            "vk": proof_output.image_id
        }
    });

    let response = client
        .post(format!("{}/submit-proof/{}", API_URL, api_key))
        .json(&submit_params)
        .send()
        .await?;

    let submit_response: serde_json::Value = response.json().await?;
    println!("{:#?}", submit_response);

    if submit_response["optimisticVerify"] != "success" {
        eprintln!("Proof verification failed.");
        bail!("Proof verification failed: {}", submit_response["optimisticVerify"]);
    }

    let job_id = submit_response["jobId"].as_str().unwrap();

    loop {
        let job_status = client
            .get(format!("{}/job-status/{}/{}", API_URL, api_key, job_id))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let status = job_status["status"].as_str().unwrap_or("Unknown");

        if status == "Finalized" || status == "Aggregated" || status == "AggregationPending"{
            println!("Job Finalized successfully");
            println!("{:?}", job_status);
            return Ok(job_status["txHash"].as_str().unwrap_or("Unknown").to_string());
        } else {
            println!("Job status: {}", status);
            println!("Waiting for job to finalized...");
            thread::sleep(Duration::from_secs(5));
        }
    }

}