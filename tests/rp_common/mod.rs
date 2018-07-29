extern crate env_logger;
extern crate failure;

use std::cell::RefCell;
use std::sync::{Once, ONCE_INIT};

use failure::Fail;
use oauth2::RedirectUrl;
use oauth2::prelude::NewType;
use url::Url;

use openidconnect;
use openidconnect::core::{CoreApplicationType, CoreClientRegistrationRequest,
                          CoreClientRegistrationResponse, CoreProviderMetadata};
use openidconnect::discovery::ProviderMetadata;
use openidconnect::registration::ClientRegistrationRequest;
use openidconnect::{ClientName, ContactEmail, IssuerUrl};

pub const CERTIFICATION_BASE_URL: &str = "https://rp.certification.openid.net:8080";
pub const RP_CONTACT_EMAIL: &str = "ramos@cs.stanford.edu";
pub const RP_NAME: &str = "openidconnect-rs";
pub const RP_REDIRECT_URI: &str = "http://localhost:8080";

static INIT_LOG: Once = ONCE_INIT;

thread_local! {
    static TEST_ID: RefCell<&'static str> = RefCell::new("UNINITIALIZED_TEST_ID");
}

pub fn get_test_id() -> &'static str {
    TEST_ID.with(|id| *id.borrow())
}

pub fn set_test_id(test_id: &'static str) {
    TEST_ID.with(|id| *id.borrow_mut() = test_id);
}

#[macro_export]
macro_rules! log_error {
    ($($args:tt)+) => {
        error!("[{}] {}", rp_common::get_test_id(), format!($($args)+));
    }
}
#[macro_export]
macro_rules! log_info {
    ($($args:tt)+) => {
        info!("[{}] {}", rp_common::get_test_id(), format!($($args)+));
    }
}
#[macro_export]
macro_rules! log_debug {
    ($($args:tt)+) => {
        debug!("[{}] {}", rp_common::get_test_id(), format!($($args)+));
    }
}

#[macro_export]
macro_rules! log_container_field {
    ($container:ident. $field:ident) => {
        log_info!(
            concat!("  ", stringify!($field), " = {:?}"),
            $container.$field()
        );
    };
}

fn _init_log() {
    env_logger::init();
}

pub fn init_log(test_id: &'static str) {
    INIT_LOG.call_once(_init_log);
    set_test_id(test_id);
}

// FIXME: convert this to a trait on Result<_, Fail>
pub trait PanicIfFail<T, F>
where
    F: Fail,
{
    fn panic_if_fail(self, msg: &'static str) -> T;
}
impl<T, F> PanicIfFail<T, F> for Result<T, F>
where
    F: Fail,
{
    fn panic_if_fail(self, msg: &'static str) -> T {
        match self {
            Ok(ret) => ret,
            Err(fail) => {
                let mut err_msg = format!("Panic: {}", msg);

                let mut cur_fail: Option<&Fail> = Some(&fail);
                while let Some(cause) = cur_fail {
                    err_msg += &format!("\n    caused by: {}", cause);
                    cur_fail = cause.cause();
                }
                error!("[{}] {}", get_test_id(), err_msg);
                panic!(msg);
            }
        }
    }
}

pub fn issuer_url(test_id: &str) -> IssuerUrl {
    IssuerUrl::new(
        Url::parse(&format!(
            "{}/{}/{}",
            CERTIFICATION_BASE_URL, RP_NAME, test_id
        )).expect("Failed to parse issuer URL"),
    )
}

pub fn get_provider_metadata(test_id: &str) -> CoreProviderMetadata {
    let _issuer_url = issuer_url(test_id);
    openidconnect::discovery::get_provider_metadata(&_issuer_url).expect(&format!(
        "Failed to fetch provider metadata from {:?}",
        _issuer_url
    ))
}

pub fn register_client<F>(
    provider_metadata: &CoreProviderMetadata,
    request_fn: F,
) -> CoreClientRegistrationResponse
where
    F: FnOnce(CoreClientRegistrationRequest) -> CoreClientRegistrationRequest,
{
    let registration_request_pre = CoreClientRegistrationRequest::new(vec![
        RedirectUrl::new(Url::parse(RP_REDIRECT_URI).unwrap()),
    ]).set_application_type(Some(CoreApplicationType::Native))
        .set_client_name(Some(ClientName::new(RP_NAME.to_string())), None)
        .set_contacts(Some(vec![ContactEmail::new(RP_CONTACT_EMAIL.to_string())]));

    let registration_request_post = request_fn(registration_request_pre);

    let registration_endpoint = provider_metadata
        .registration_endpoint()
        .expect("provider does not support dynamic registration");
    registration_request_post
        .register(&registration_endpoint)
        .expect(&format!(
            "Failed to register client at {:?}",
            registration_endpoint
        ))
}
