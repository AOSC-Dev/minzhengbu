use axum::{
    extract::Query,
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use once_cell::sync::Lazy;
use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Debug)]
struct CallbackLoginArgs {
    code: String,
}

#[derive(Deserialize, Debug)]
struct CallbackSecondLoginArgs {
    access_token: String,
    expires_in: i64,
    refresh_token: String,
    refresh_token_expires_in: i64,
    scope: String,
    token_type: String,
}

#[derive(Deserialize, Debug)]
struct ErrMessage {
    err: String,
}

static CLIENT_ID: Lazy<String> =
    Lazy::new(|| std::env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID is not set"));
static CLIENT_SECRET: Lazy<String> =
    Lazy::new(|| std::env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET is not set"));
static REDIRECT_URL: Lazy<String> =
    Lazy::new(|| std::env::var("REDIRECT_URL").expect("REDIRECT_URL is not set"));

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // 加载环境变量
    dotenvy::dotenv().ok();
    let _ = &*CLIENT_ID;
    let _ = &*CLIENT_SECRET;
    let _ = &*REDIRECT_URL;

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/login", get(login))
        .route("/", get(root))
        .route("/error", get(error));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn login(Query(payload): Query<CallbackLoginArgs>) -> Redirect {
    let code = payload.code;

    let mut url = Url::parse("https://github.com/login/oauth/access_token").unwrap();
    url.query_pairs_mut().extend_pairs(&[
        ("client_id", &*CLIENT_ID),
        ("client_secret", &*CLIENT_SECRET),
        ("code", &code),
        ("redirect_uri", &*REDIRECT_URL),
    ]);

    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .send()
        .await
        .and_then(|x| x.error_for_status());

    match resp {
        Ok(resp) => match resp.text().await {
            Ok(s) => Redirect::permanent(&format!("/?{s}")),
            Err(e) => return Redirect::permanent(&format!("/error?err={e}")),
        },
        Err(e) => return Redirect::permanent(&format!("/error?err={e}")),
    }
}

async fn root(Query(payload): Query<CallbackSecondLoginArgs>) -> &'static str {
    let CallbackSecondLoginArgs {
        access_token,
        expires_in,
        refresh_token,
        refresh_token_expires_in,
        scope,
        token_type,
    } = payload;

    "Hello"
}

async fn error(Query(payload): Query<ErrMessage>) -> String {
    payload.err
}
