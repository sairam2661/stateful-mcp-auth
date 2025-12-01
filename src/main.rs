use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request, Response};
use clap::Parser;
use std::str::FromStr;
use std::time::Instant;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "cedar-authorize")]
#[command(about = "Authorize requests using Cedar Policy", long_about = None)]
struct Args {
    /// Principal entity (e.g., "User::\"alice\"")
    #[arg(short, long)]
    principal: Option<String>,

    /// Action entity (e.g., "Action::\"update\"")
    #[arg(short, long)]
    action: Option<String>,

    /// Resource entity (e.g., "Photo::\"flower.jpg\"")
    #[arg(short, long)]
    resource: Option<String>,

    /// Cedar policy string
    #[arg(short = 'P', long)]
    policy: Option<String>,

    /// Entities JSON string (default: "[]")
    #[arg(short, long, default_value = "[]")]
    entities: String,

    /// Context JSON string (default: "{}")
    #[arg(short, long)]
    context: Option<String>,

    /// Output timing information as JSON
    #[arg(long, default_value = "false")]
    timing: bool,
}

#[derive(Serialize)]
struct TimingOutput {
    decision: String,
    parse_policy_us: u128,
    parse_context_us: u128,
    parse_entities_us: u128,
    build_request_us: u128,
    authorization_us: u128,
    total_us: u128,
}

/// Authorize a request using Cedar Policy with timing
pub fn authorize_with_timing(
    principal: &str,
    action: &str,
    resource: &str,
    policies: &str,
    entities: &str,
    context: Option<&str>,
) -> (Response, TimingOutput) {
    let total_start = Instant::now();

    // Parse principal, action, resource
    let principal = EntityUid::from_str(principal).expect("failed to parse principal");
    let action = EntityUid::from_str(action).expect("failed to parse action");
    let resource = EntityUid::from_str(resource).expect("failed to parse resource");

    // Parse context
    let context_start = Instant::now();
    let context_str = context.unwrap_or("{}");
    let context_json: serde_json::Value =
        serde_json::from_str(context_str).expect("failed to parse context JSON");
    let context = Context::from_json_value(context_json, None).expect("failed to create context");
    let parse_context_us = context_start.elapsed().as_micros();

    // Build request
    let request_start = Instant::now();
    let request =
        Request::new(principal, action, resource, context, None).expect("failed to create request");
    let build_request_us = request_start.elapsed().as_micros();

    // Parse policies
    let policy_start = Instant::now();
    let policy_set = PolicySet::from_str(policies).expect("failed to parse policies");
    let parse_policy_us = policy_start.elapsed().as_micros();

    // Parse entities
    let entities_start = Instant::now();
    let entities = Entities::from_json_str(entities, None).expect("failed to parse entities");
    let parse_entities_us = entities_start.elapsed().as_micros();

    // Authorization
    let auth_start = Instant::now();
    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&request, &policy_set, &entities);
    let authorization_us = auth_start.elapsed().as_micros();

    let total_us = total_start.elapsed().as_micros();

    let timing = TimingOutput {
        decision: format!("{:?}", response.decision()),
        parse_policy_us,
        parse_context_us,
        parse_entities_us,
        build_request_us,
        authorization_us,
        total_us,
    };

    (response, timing)
}

fn main() {
    let args = Args::parse();

    let principal = args.principal.as_deref().unwrap_or("User::\"alice\"");
    let action = args.action.as_deref().unwrap_or("Action::\"update\"");
    let resource = args.resource.as_deref().unwrap_or("Photo::\"flower.jpg\"");
    let policies = args.policy.as_deref().unwrap_or(
        r#"permit(
            principal in User::"alice",
            action in [Action::"update", Action::"delete"],
            resource == Photo::"flower.jpg")
        when {
            context.mfa_authenticated == true &&
            context.request_client_ip == "222.222.222.222"
        };"#,
    );
    let entities = &args.entities;
    let context_default = r#"{"mfa_authenticated": true, "request_client_ip": "222.222.222.222", "oidc_scope": "profile"}"#;
    let context = args.context.as_deref().or(Some(context_default));

    let (response, timing) = authorize_with_timing(principal, action, resource, policies, entities, context);

    if args.timing {
        println!("{}", serde_json::to_string(&timing).unwrap());
    } else {
        println!("{:?}", response.decision());
    }
}