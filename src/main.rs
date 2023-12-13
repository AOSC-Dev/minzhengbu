use axum::{
    extract::Query,
    response::{Html, Redirect},
    routing::get,
    Router,
};
use dashmap::DashMap;
use once_cell::sync::{Lazy, OnceCell};
use rand::{distributions::Alphanumeric, Rng};
use redis::{aio::MultiplexedConnection, AsyncCommands};
use serde::{Deserialize, Serialize};
use url::Url;

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
struct ErrMessage {
    err: String,
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

static DB_CONN: OnceCell<MultiplexedConnection> = OnceCell::new();

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // 加载环境变量
    dotenvy::dotenv().ok();
    let _ = &*CLIENT_ID;
    let _ = &*CLIENT_SECRET;
    let _ = &*REDIRECT_URL;

    let client =
        redis::Client::open("redis://127.0.0.1/").expect("Failed to connect redis database");

    let connect = client
        .get_multiplexed_tokio_connection()
        .await
        .expect("Failed to get multiplexed connection");

    DB_CONN.get_or_init(|| connect);

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/login", get(login))
        .route("/", get(root))
        .route("/error", get(error))
        .route("/login_from_telegram", get(login_from_telegram));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn login_from_telegram(Query(payload): Query<TelegramInfo>) -> String {
    let TelegramInfo { telegram_id, rid } = payload;

    let access_info = TEMP_MAP.get(&rid);

    match access_info {
        Some(access_info) => {
            let mut conn = DB_CONN.get().unwrap().to_owned();
            let s = match serde_json::to_string(access_info.value()) {
                Ok(s) => s,
                Err(e) => return format!("Failed to serialize access info: {e}"),
            };
            match conn.set(telegram_id, s).await {
                Ok(()) => "Success".to_owned(),
                Err(e) => format!("Got Error: {e}"),
            }
        }
        None => "Failed to get access info, You need to re-verify.".to_owned(),
    }
}

async fn login(Query(payload): Query<CallbackLoginArgs>) -> Redirect {
    let CallbackLoginArgs { code } = payload;

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
            Err(e) => Redirect::permanent(&format!("/error?err={e}")),
        },
        Err(e) => Redirect::permanent(&format!("/error?err={e}")),
    }
}

async fn root(Query(payload): Query<CallbackSecondLoginArgs>) -> Html<String> {
    let insert_temp_map = tokio::spawn(async {
        let rng = rand::thread_rng();
        let s: String = rng
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();

        TEMP_MAP.insert(s.clone(), payload);

        s
    });

    match insert_temp_map.await {
        Ok(s) => Html::from(format!(
            "<a href=\"https://t.me/aosc_buildit_bot?start={s}\">Hit me!</a>"
        )),
        Err(e) => Html::from(format!("Got error: {e}")),
    }
}

async fn error(Query(payload): Query<ErrMessage>) -> String {
    payload.err
}
