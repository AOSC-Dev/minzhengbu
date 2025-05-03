use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use rand::{Rng, distr::Alphanumeric};
use tokio::sync::Mutex;
use tracing::{log::error, warn};

use dashmap::DashMap;
use redis::{AsyncCommands, aio::MultiplexedConnection};
use serde::{Deserialize, Serialize};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Deserialize, Debug)]
struct CallbackLoginArgs {
    code: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct CallbackSecondLoginArgs {
    access_token: String,
    expires_in: i64,
    refresh_token: String,
    refresh_token_expires_in: i64,
    scope: String,
    token_type: String,
}

#[derive(Deserialize, Debug)]
struct TelegramInfo {
    telegram_id: String,
    rid: String,
}

#[derive(Debug, Clone)]
struct AppState {
    conn: Arc<Mutex<MultiplexedConnection>>,
    client_id: String,
    client_secret: String,
    secret: String,
    temp_kv: Arc<DashMap<String, CallbackSecondLoginArgs>>,
    redirect_url: String,
}

// learned from https://github.com/tokio-rs/axum/blob/main/examples/anyhow-error-response/src/main.rs
pub struct AnyhowError(anyhow::Error);

impl IntoResponse for AnyhowError {
    fn into_response(self) -> Response {
        error!("Returning internal server error for {}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", self.0)).into_response()
    }
}

impl<E> From<E> for AnyhowError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

#[tokio::main]
async fn main() {
    // initialize tracing
    let env_log = EnvFilter::try_from_default_env();

    if let Ok(filter) = env_log {
        tracing_subscriber::registry()
            .with(fmt::layer().with_filter(filter))
            .init();
    } else {
        tracing_subscriber::registry().with(fmt::layer()).init();
    }

    // console_subscriber::init();

    dotenvy::dotenv().ok();
    let client_id = std::env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID is not set");
    let client_secret =
        std::env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET is not set");
    let redirect_url = std::env::var("REDIRECT_URL").expect("REDIRECT_URL is not set");
    let redis = std::env::var("REDIS").expect("REDIS is not set");
    let secret = std::env::var("SECRET").expect("SECRET is not set");
    let local_url = std::env::var("LOCAL_URL").expect("LOCAL_URL is not set");

    let client = redis::Client::open(&*redis).expect("Failed to connect redis database");
    let connect = Arc::new(Mutex::new(
        client
            .get_multiplexed_tokio_connection()
            .await
            .expect("Failed to get multiplexed connection"),
    ));
    let temp_kv: Arc<DashMap<String, CallbackSecondLoginArgs>> = Arc::new(DashMap::new());

    // build our application with a route
    let app = Router::new()
        .route("/login", get(login))
        .route("/login_from_telegram", get(login_from_telegram))
        .route("/get_token", get(get_token))
        .route("/refresh_token", get(refresh_token))
        .with_state(AppState {
            conn: connect,
            client_id,
            client_secret,
            secret,
            temp_kv,
            redirect_url,
        });

    let listener = tokio::net::TcpListener::bind(local_url).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn refresh_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(payload): Query<TelegramId>,
) -> Result<impl IntoResponse, AnyhowError> {
    let AppState {
        conn,
        client_id,
        client_secret,
        secret,
        ..
    } = state;

    let TelegramId { id } = payload;

    if !secret_check(&headers, &secret) {
        return Err(anyhow!("secret not match").into());
    }

    let res = {
        let mut conn = conn.lock().await;
        let res: Result<String, redis::RedisError> = conn.get(&id).await;
        res
    }?;

    let res: CallbackSecondLoginArgs = serde_json::from_str(&res)?;

    let client = reqwest::Client::new();
    let resp = client
        .post("https://github.com/login/oauth/access_token")
        .query(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", &res.refresh_token),
        ])
        .send()
        .await
        .and_then(|x| x.error_for_status())?;

    let login_args = format_github_query(resp.text().await?)?;

    let s = serde_json::to_string(&login_args)?;

    {
        let mut conn = conn.lock().await;
        let _: () = conn.set(&id, &s).await?;
    }

    let mut headers = HeaderMap::new();
    headers.insert("cache-control", "no-cache".parse().unwrap());

    Ok((headers, "Successful refresh".to_string()))
}

fn secret_check(headers: &HeaderMap, set_secret: &str) -> bool {
    let secret = headers.get("secret");

    secret
        .and_then(|x| x.to_str().ok())
        .map(|x| x == set_secret)
        .unwrap_or(false)
}

async fn login_from_telegram(
    State(state): State<AppState>,
    Query(payload): Query<TelegramInfo>,
) -> Result<impl IntoResponse, AnyhowError> {
    let TelegramInfo { telegram_id, rid } = payload;

    let AppState { conn, temp_kv, .. } = state;

    let s = {
        let access_info = temp_kv
            .get(&rid)
            .context("Could not find telegram access info by id: {rid}")?;

        serde_json::to_string(access_info.value())?
    };

    {
        let mut conn = conn.lock().await;
        let _: () = conn.set(telegram_id, s).await?;
    }

    temp_kv.remove(&rid);

    let mut headers = HeaderMap::new();
    headers.insert("cache-control", "no-cache".parse().unwrap());

    Ok((headers, "Successful login".to_string()))
}

async fn login(
    State(state): State<AppState>,
    Query(payload): Query<CallbackLoginArgs>,
) -> Result<impl IntoResponse, AnyhowError> {
    let CallbackLoginArgs { code } = payload;

    let AppState {
        temp_kv,
        client_id,
        client_secret,
        redirect_url,
        ..
    } = state;

    let client = reqwest::Client::new();
    let resp = client
        .post("https://github.com/login/oauth/access_token")
        .query(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", redirect_url),
        ])
        .send()
        .await
        .and_then(|x| x.error_for_status())?;

    let query = resp.text().await?;
    let login_args = format_github_query(query)?;

    let s = tokio::task::spawn_blocking(move || {
        let rng = rand::rng();
        let s: String = rng
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        temp_kv.insert(s.clone(), login_args);

        s
    })
    .await?;

    let mut headers = HeaderMap::new();
    headers.insert("cache-control", "no-cache".parse().unwrap());

    Ok((
        headers,
        Html::from(format!(
            "<a href=\"https://t.me/aosc_buildit_bot?start={s}\">Please click on this link to complete authentication.</a>"
        )),
    ))
}

fn format_github_query(query: String) -> Result<CallbackSecondLoginArgs> {
    let map = querify(&query);
    let mut access_token = None;
    let mut expires_in = None;
    let mut refresh_token = None;
    let mut refresh_token_expires_in = None;
    let mut scope = None;
    let mut token_type = None;
    for (k, v) in map {
        match k {
            "access_token" => access_token = Some(v),
            "expires_in" => expires_in = Some(v),
            "refresh_token" => refresh_token = Some(v),
            "refresh_token_expires_in" => refresh_token_expires_in = Some(v),
            "scope" => scope = Some(v),
            "token_type" => token_type = Some(v),
            x => {
                warn!("Has invalid key '{x}: {v}'");
                continue;
            }
        }
    }

    let login_args = CallbackSecondLoginArgs {
        access_token: access_token
            .context("access_token does not exist")?
            .to_string(),
        expires_in: expires_in
            .context("expires_in does not exist")?
            .parse::<i64>()
            .context("failed parse expires_in to i64")?,
        refresh_token: refresh_token
            .context("refresh_token does not exist")?
            .to_string(),
        refresh_token_expires_in: refresh_token_expires_in
            .context("refresh_token_expires_in does not exist")?
            .parse::<i64>()
            .context("failed parse refresh_token_expires_in to i64")?,
        token_type: token_type.context("token_type does not exist")?.to_string(),
        scope: scope.context("scope does not exist")?.to_string(),
    };

    Ok(login_args)
}

fn querify(string: &str) -> Vec<(&str, &str)> {
    let mut v = Vec::new();
    for pair in string.split('&') {
        let mut it = pair.split('=').take(2);
        let kv = match (it.next(), it.next()) {
            (Some(k), Some(v)) => (k, v),
            _ => continue,
        };
        v.push(kv);
    }

    v
}

#[derive(Deserialize, Debug)]
struct TelegramId {
    id: String,
}

async fn get_token(
    State(state): State<AppState>,
    Query(payload): Query<TelegramId>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AnyhowError> {
    let AppState { conn, secret, .. } = state;

    if !secret_check(&headers, &secret) {
        return Err(anyhow!("secret not match").into());
    }

    let res = {
        let mut conn = conn.lock().await;
        let res: Result<String, redis::RedisError> = conn.get(payload.id).await;
        res
    };

    let mut headers = HeaderMap::new();
    headers.insert("cache-control", "no-cache".parse().unwrap());

    let s = res?;

    Ok((headers, s))
}
