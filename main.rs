// Minimal SIRA server — echo pipeline
// Run: SIRA_MASTER_SECRET=$(openssl rand -hex 32) cargo run

use std::net::SocketAddr;
use std::sync::Arc;

use sira::{
    load_master_secret_from_env, router, Pipeline, RefreshAuthenticator, RevocationState, SiraState,
};

struct EchoPipeline;

#[async_trait::async_trait]
impl Pipeline for EchoPipeline {
    async fn process(
        &self,
        action: serde_json::Value,
        session_id: &str,
        window_id: &str,
        user_id: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "echo": action,
            "session": &session_id[..session_id.len().min(16)],
            "window": window_id,
            "user_id": user_id,
            "message": "SIRA is working"
        })
    }
}

/// Demo refresh auth: non-empty app token becomes `user:<token>`.
struct EchoRefreshAuth;

#[async_trait::async_trait]
impl RefreshAuthenticator for EchoRefreshAuth {
    async fn authenticate_app_token(&self, token: &str) -> Result<String, ()> {
        let t = token.trim();
        if t.is_empty() {
            Err(())
        } else {
            Ok(format!("user:{t}"))
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let master = load_master_secret_from_env();
    let revocation = RevocationState::from_env().map(Arc::new);
    let refresh_auth: Arc<dyn RefreshAuthenticator> = Arc::new(EchoRefreshAuth);
    let state = SiraState::new(
        master,
        Arc::new(EchoPipeline),
        revocation,
        Some(refresh_auth),
    );
    state.clone().spawn_maintenance();

    let app = router(state);

    let port: u16 = std::env::var("SIRA_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("SIRA server running on http://localhost:{port}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
