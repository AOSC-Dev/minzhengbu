use std::{error::Error, io};

use axum::{
    extract::Query,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use tracing::{log::error, warn};

use dashmap::DashMap;
use once_cell::sync::{Lazy, OnceCell};
use rand::{distributions::Alphanumeric, Rng};
use redis::{aio::MultiplexedConnection, AsyncCommands};
use serde::{Deserialize, Serialize};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

static TEMP_MAP: Lazy<DashMap<String, CallbackSecondLoginArgs>> = Lazy::new(DashMap::new);

static CLIENT_ID: Lazy<String> =
    Lazy::new(|| std::env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID is not set"));
static CLIENT_SECRET: Lazy<String> =
    Lazy::new(|| std::env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET is not set"));
static REDIRECT_URL: Lazy<String> =
    Lazy::new(|| std::env::var("REDIRECT_URL").expect("REDIRECT_URL is not set"));
static REDIS: Lazy<String> = Lazy::new(|| std::env::var("REDIS").expect("REDIS is not set"));
static SECRET: Lazy<String> = Lazy::new(|| std::env::var("SECRET").expect("SECRET is not set"));
static LOCAL_URL: Lazy<String> =
    Lazy::new(|| std::env::var("LOCAL_URL").expect("LOCAL_URL is not set"));

static DB_CONN: OnceCell<MultiplexedConnection> = OnceCell::new();

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // console_subscriber::init();

    // 加载环境变量
    dotenvy::dotenv().ok();
    let _ = &*CLIENT_ID;
    let _ = &*CLIENT_SECRET;
    let _ = &*REDIRECT_URL;
    let _ = &*SECRET;

    let client = redis::Client::open(REDIS.as_str()).expect("Failed to connect redis database");

    let connect = client
        .get_multiplexed_tokio_connection()
        .await
        .expect("Failed to get multiplexed connection");

    DB_CONN.get_or_init(|| connect);

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/login", get(login))
        .route("/login_from_telegram", get(login_from_telegram))
        .route("/get_token", get(get_token));

    let listener = tokio::net::TcpListener::bind(&*LOCAL_URL).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn login_from_telegram(
    Query(payload): Query<TelegramInfo>,
) -> Result<impl IntoResponse, StatusCode> {
    let TelegramInfo { telegram_id, rid } = payload;

    let access_info = TEMP_MAP.get(&rid).ok_or_else(|| {
        let err = io::Error::new(
            io::ErrorKind::Other,
            format!("Could not find telegram access info by id: {rid}"),
        );
        error!("{err}");
        StatusCode::NOT_FOUND
    })?;

    let mut conn = DB_CONN
        .get()
        .ok_or_else(|| {
            let err = io::Error::new(
                io::ErrorKind::Other,
                "Could not open redis database connection",
            );
            error(&err)
        })?
        .to_owned();

    let s = serde_json::to_string(access_info.value()).map_err(|e| error(&e))?;

    conn.set(telegram_id, s).await.map_err(|e| error(&e))?;

    drop(access_info);
    TEMP_MAP.remove(&rid);

    let mut headers = HeaderMap::new();
    headers.insert("cache-control", "no-cache".parse().unwrap());

    Ok((headers, "Successfully login".to_string()))
}

async fn login(Query(payload): Query<CallbackLoginArgs>) -> Result<impl IntoResponse, StatusCode> {
    let CallbackLoginArgs { code } = payload;

    let client = reqwest::Client::new();
    let resp = client
        .post("https://github.com/login/oauth/access_token")
        .query(&[
            ("client_id", &*CLIENT_ID),
            ("client_secret", &*CLIENT_SECRET),
            ("code", &code),
            ("redirect_uri", &*REDIRECT_URL),
        ])
        .send()
        .await
        .and_then(|x| x.error_for_status())
        .map_err(|e| error(&e))?;

    let query = resp.text().await.map_err(|e| error(&e))?;
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
            .ok_or_else(|| err_message("access_token does not exist"))?
            .to_string(),
        expires_in: expires_in
            .ok_or_else(|| err_message("expires_in does not exist"))?
            .parse::<i64>()
            .map_err(|e| error(&e))?,
        refresh_token: refresh_token
            .ok_or_else(|| err_message("refresh_token does not exist"))?
            .to_string(),
        refresh_token_expires_in: refresh_token_expires_in
            .ok_or_else(|| err_message("refresh_token_expires_in does not exist"))?
            .parse::<i64>()
            .map_err(|e| error(&e))?,
        token_type: token_type
            .ok_or_else(|| err_message("token_type does not exist"))?
            .to_string(),
        scope: scope
            .ok_or_else(|| err_message("scope does not exist"))?
            .to_string(),
    };

    let s = tokio::task::spawn_blocking(|| {
        let rng = rand::thread_rng();
        let s: String = rng
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        TEMP_MAP.insert(s.clone(), login_args);

        s
    })
    .await
    .map_err(|e| error(&e))?;

    let mut headers = HeaderMap::new();
    headers.insert("cache-control", "no-cache".parse().unwrap());

    Ok((
        headers,
        Html::from(format!(
            "<a href=\"https://t.me/aosc_buildit_bot?start={s}\">Hit me!</a>"
        )),
    ))
}

fn err_message(err: &str) -> StatusCode {
    error!("{err}");

    StatusCode::INTERNAL_SERVER_ERROR
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
    Query(payload): Query<TelegramId>,
    header: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let secret = header.get("secret");

    if secret
        .and_then(|x| x.to_str().ok())
        .map(|x| x != &*SECRET)
        .unwrap_or(true)
    {
        error!("Auth failed: secret not match");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let mut conn = DB_CONN
        .get()
        .ok_or_else(|| {
            let err = io::Error::new(io::ErrorKind::Other, "database connection does not exist");
            error(&err)
        })?
        .to_owned();

    let res: Result<String, redis::RedisError> = conn.get(payload.id).await;

    let mut headers = HeaderMap::new();
    headers.insert("cache-control", "no-cache".parse().unwrap());

    let s = res.map_err(|e| error(&e))?;

    Ok((headers, s))
}

fn error(err: &dyn Error) -> StatusCode {
    error!("{err}");

    StatusCode::INTERNAL_SERVER_ERROR
}
