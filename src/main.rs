mod tee_utils;
mod zkverify_utils;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_zkv_sdk::{SP1ZkvProofWithPublicValues, ZkvProver};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;
use sp1_sdk::{utils, HashableKey, ProverClient, SP1Stdin};
use tower_http::cors::{Any, CorsLayer};


pub const DCAP_ELF: &[u8] = include_bytes!("../dcap-sp1-guest-program-elf");

// Struct of the output we need
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Output{
    image_id: String,
    pub_inputs: String,
    proof: String
}


#[derive(Serialize, Clone, Debug)]
#[serde(tag = "status", content = "data")]
enum TaskStatus {
    Processing,
    Verifying { },
    Completed { tx_hash: String },
    Failed { error: String },
}

/// The request body for the /prove endpoint.
#[derive(Deserialize)]
struct ProveRequest {
    quote: String,
}

#[derive(Serialize)]
struct ProveResponse {
    task_id: String,
}

// A thread-safe, shared mapping from task_id to its current status.
type TaskDb = Arc<RwLock<HashMap<String, TaskStatus>>>;

// A thread-safe cache mapping a specific stdin to its final, completed result.
type ProofCache = Arc<RwLock<HashMap<String, TaskStatus>>>;

/// A struct to hold all shared state for the application.
/// This makes it easy to add more shared resources in the future.
#[derive(Clone)]
struct AppState {
    task_db: TaskDb,
    proof_cache: ProofCache,
}

#[tokio::main]
async fn main() {
    // Initialize the shared state, including the new proof cache.
    let state = AppState {
        task_db: Arc::new(RwLock::new(HashMap::new())),
        proof_cache: Arc::new(RwLock::new(HashMap::new())),
    };

    let cors = CorsLayer::very_permissive();

    // Define the application routes.
    let app = Router::new()
        .route("/prove", post(prove_handler))
        .route("/status/:task_id", get(status_handler))
        .with_state(state) // Make the combined state available to all handlers.
        .layer(cors); 

    // Start the server.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    println!("🚀 Server listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}


async fn prove_handler(
    State(state): State<AppState>,
    Json(payload): Json<ProveRequest>,
) -> Response{

    let mut hasher = Sha256::new();
    hasher.update(&payload.quote.as_bytes());
    let quote_hash = hex::encode(hasher.finalize());

    let proof_cache_reader = state.proof_cache.read().await;
    if let Some(cached_result) = proof_cache_reader.get(&quote_hash) {
        println!("✅ Cache HIT for stdin: '{}'", quote_hash);
        // If it exists, return the cached result immediately with a 200 OK.
        return (StatusCode::OK, Json(cached_result.clone())).into_response();
    }
    // Drop the read lock explicitly so we can acquire a write lock later if needed.
    drop(proof_cache_reader);
    println!("❌ Cache MISS for stdin: '{}'. Starting new task.", quote_hash);

    // --- NEW TASK LOGIC (if not in cache) ---
    // 2. If not cached, create a new task ID and spawn a background job.
    let task_id = Uuid::new_v4().to_string();

    let state_clone = state.clone();
    let task_id_clone = task_id.clone();
    let quote_clone = quote_hash.clone();

    tokio::spawn(async move{

        {
            let mut db_writer = state_clone.task_db.write().await;
            db_writer.insert(task_id_clone.clone(), TaskStatus::Processing);
        }

        let formatted_quote = tee_utils::remove_prefix_if_found(&payload.quote);
        let quote_bytes = hex::decode(formatted_quote).expect("Failed to decode hex string");
        let input = tee_utils::get_sp1_input(quote_bytes).await.unwrap();

        let client = ProverClient::from_env();
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input);
        let (pk, vk) = client.setup(DCAP_ELF);
        let proof = client.prove(&pk, &stdin).compressed().run();

        let proof_result = match proof{
            Ok(p) => {
                // Convert proof and vk into a zkVerify-compatible proof.
                let SP1ZkvProofWithPublicValues {
                    proof: shrunk_proof,
                    public_values,
                } = client
                    .convert_proof_to_zkv(p, Default::default())
                    .unwrap();
                let vk_hash = vk.hash_bytes();

                // Serialize the proof
                let serialized_proof = bincode::serde::encode_to_vec(&shrunk_proof, bincode::config::legacy())
                    .expect("failed to serialize proof");

                // Convert to required struct
                Output{
                    proof: tee_utils::to_hex_with_prefix(&serialized_proof),
                    image_id: tee_utils::to_hex_with_prefix(&vk_hash),
                    pub_inputs: tee_utils::to_hex_with_prefix(&public_values),
                }
            },
            Err(e)=> {
                let final_status = TaskStatus::Failed{ error: e.to_string() };
                let mut db_writer = state_clone.task_db.write().await;
                let mut cache_writer = state_clone.proof_cache.write().await;
                db_writer.insert(task_id_clone.clone(), final_status.clone());
                cache_writer.insert(quote_clone, final_status);
                println!("❌ Task {} failed during proof generation.", task_id_clone);
                return; // End the task.
            }
        };

        println!("➡️ Task {} completed proving, now verifying.", task_id_clone);
        {
            let mut db_writer = state_clone.task_db.write().await;
            db_writer.insert(task_id_clone.clone(), TaskStatus::Verifying { });
        }

        let verification_result = zkverify_utils::verify_proof(proof_result.clone()).await;
        let final_status = match verification_result{
            Ok(tx_hash) => TaskStatus::Completed { tx_hash },
            Err(e) => TaskStatus::Failed { error: e.to_string() },
        };

        let mut db_writer = state_clone.task_db.write().await;
        let mut cache_writer = state_clone.proof_cache.write().await;
        db_writer.insert(task_id_clone.clone(), final_status.clone());
        cache_writer.insert(quote_clone.clone(), final_status);

        println!("✅ Task {} finished full pipeline. Result is now cached.", task_id_clone);
    });

    (
        StatusCode::ACCEPTED,
        Json(ProveResponse { task_id }),
    ).into_response()

}

/// Handles requests to check the status of a specific task by its ID.
async fn status_handler(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Response {
    let db_reader = state.task_db.read().await;
    match db_reader.get(&task_id) {
        Some(status) => (StatusCode::OK, Json(status.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, "Task not found").into_response(),
    }
}