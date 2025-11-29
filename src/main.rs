use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request, Response};
use clap::Parser;
use std::str::FromStr;


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
}


/// Authorize a request using Cedar Policy
pub fn authorize(
   principal: &str,
   action: &str,
   resource: &str,
   policies: &str,
   entities: &str,
   context: Option<&str>,
) -> Response {
   let principal = EntityUid::from_str(principal).expect("failed to parse principal");
   let action = EntityUid::from_str(action).expect("failed to parse action");
   let resource = EntityUid::from_str(resource).expect("failed to parse resource");


   let context_str = context.unwrap_or("{}");
   let context_json: serde_json::Value =
       serde_json::from_str(context_str).expect("failed to parse context JSON");
   let context = Context::from_json_value(context_json, None).expect("failed to create context");


   let request =
       Request::new(principal, action, resource, context, None).expect("failed to create request");
   let policy_set = PolicySet::from_str(policies).expect("failed to parse policies");
   let entities = Entities::from_json_str(entities, None).expect("failed to parse entities");


   let authorizer = Authorizer::new();
   authorizer.is_authorized(&request, &policy_set, &entities)
}


fn main() {
   let args = Args::parse();


   // Use CLI args if provided, otherwise use example values
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


   let response = authorize(principal, action, resource, policies, entities, context);
   println!("{:?}", response.decision());
}
