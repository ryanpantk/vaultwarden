use rocket::serde::json::Json;
use rocket::{http::Status, Route, request::{FromRequest, Outcome, Request}};
use serde::{Deserialize, Serialize};

use crate::{
    api::JsonResult,
    auth::{encode_jwt, generate_invite_claims},
    db::{models::*, DbConn},
    CONFIG,
};

pub const FAKE_ADMIN_UUID: &str = "00000000-0000-0000-0000-000000000000";

pub struct VWApi;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for VWApi {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let api_key = request.headers().get_one("x-vaultwarden-api");

        match api_key {
            Some(key) if !key.is_empty() => {
                if let Some(expected_key) = CONFIG.x_vaultwarden_api() {
                    if key == expected_key {
                        Outcome::Success(VWApi)
                    } else {
                        Outcome::Error((Status::Unauthorized, "Invalid x-vaultwarden-api"))
                    }
                } else {
                    Outcome::Error((Status::InternalServerError, "x-vaultwarden-api not configured"))
                }
            }
            _ => Outcome::Error((Status::Unauthorized, "Missing x-vaultwarden-api header"))
        }
    }
}

pub fn routes() -> Vec<Route> {
    routes![invite_user, get_user_details, get_invite_link, get_user_invite_link]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    email: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InviteResponse {
    user_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InviteLinkResponse {
    invite_link: String,
}

#[post("/invite", format = "application/json", data = "<data>")]
async fn invite_user(_auth: VWApi, data: Json<InviteData>, mut conn: DbConn) -> JsonResult {
    let data: InviteData = data.into_inner();
    if let Some(existing_user) = User::find_by_mail(&data.email, &mut conn).await {
        return Ok(Json(serde_json::to_value(InviteResponse {
            user_id: existing_user.uuid.to_string(),
        }).unwrap()))
    }

    let mut user = User::new(&data.email, None);

    // Create invitation record without sending email.
    // The invite link can be retrieved via GET /user/invite-link?email=<email>
    if !CONFIG.mail_enabled() {
        let invitation = Invitation::new(&user.email);
        invitation.save(&mut conn).await.map_err(|e| e.with_code(Status::InternalServerError.code))?;
    }
    user.save(&mut conn).await.map_err(|e| e.with_code(Status::InternalServerError.code))?;

    Ok(Json(serde_json::to_value(InviteResponse {
        user_id: user.uuid.to_string(),
    }).unwrap()))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberInfo {
    email: String,
    role: String,
    status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserDetailsResponse {
    status: String,
    org_id: Option<String>,
    members_count: usize,
    members: Vec<MemberInfo>,
}

#[get("/user/<user_id>/details")]
async fn get_user_details(_auth: VWApi, user_id: &str, mut conn: DbConn) -> JsonResult {
    let user_uuid = UserId::from(user_id);

    match User::find_by_uuid(&user_uuid, &mut conn).await {
        Some(user) => {
            // Get user memberships to determine status
            let memberships = Membership::find_by_user(&user_uuid, &mut conn).await;

            let status = if user.password_hash.is_empty() {
                "PendingSetupPassword".to_string()
            } else if memberships.is_empty() {
                "Pending".to_string()
            } else {
                "Active".to_string()
            };

            // Members: get all members of the user's organization with their emails and status
            let (members_count, members) = if let Some(membership) = memberships.first() {
                let org_memberships = Membership::find_by_org(&membership.org_uuid, &mut conn).await;
                let members_count = org_memberships.len();
                let mut member_list = Vec::new();
                for m in org_memberships {
                    if let Some(user) = User::find_by_uuid(&m.user_uuid, &mut conn).await {
                        let member_role = match m.atype {
                            0 => "Owner",
                            1 => "Admin",
                            2 => "User",
                            3 => "Custom",
                            _ => "Unknown",
                        };
                        let member_status = match m.status {
                            -1 => "Revoked",
                            0 => "Invited",
                            1 => "Accepted",
                            2 => "Confirmed",
                            _ => "Unknown",
                        };
                        member_list.push(MemberInfo {
                            email: user.email,
                            role: member_role.to_string(),
                            status: member_status.to_string(),
                        });
                    }
                }
                (members_count, member_list)
            } else {
                (0, Vec::new())
            };

            let org_id = memberships.first().map(|m| m.org_uuid.to_string());

            Ok(Json(serde_json::to_value(UserDetailsResponse {
                status,
                org_id,
                members_count,
                members,
            }).unwrap()))
        }
        None => err_code!("User not found", Status::NotFound.code),
    }
}

#[get("/organization/<org_id>/invite-link?<email>")]
async fn get_invite_link(_auth: VWApi, org_id: String, email: String, mut conn: DbConn) -> JsonResult {
    let org_uuid = OrganizationId::from(org_id);

    // Find the user by email
    let user = match User::find_by_mail(&email, &mut conn).await {
        Some(user) => user,
        None => err_code!("User not found", Status::NotFound.code),
    };

    // Find the organization
    let org = match Organization::find_by_uuid(&org_uuid, &mut conn).await {
        Some(org) => org,
        None => err_code!("Organization not found", Status::NotFound.code),
    };

    // Find the membership
    let membership = match Membership::find_by_user_and_org(&user.uuid, &org_uuid, &mut conn).await {
        Some(m) => m,
        None => err_code!("User is not a member of this organization", Status::NotFound.code),
    };

    // Verify membership is in Invited status
    if membership.status != MembershipStatus::Invited as i32 {
        err_code!("User is not in invited status", Status::BadRequest.code);
    }

    // Generate the invite token
    let claims = generate_invite_claims(
        user.uuid.clone(),
        user.email.clone(),
        org_uuid.clone(),
        membership.uuid.clone(),
        membership.invited_by_email.clone(),
    );
    let invite_token = encode_jwt(&claims);

    // Build the invite URL
    let mut query = url::Url::parse("https://query.builder").unwrap();
    {
        let mut query_params = query.query_pairs_mut();
        query_params
            .append_pair("email", &user.email)
            .append_pair("organizationName", &org.name)
            .append_pair("organizationId", &org_uuid.to_string())
            .append_pair("organizationUserId", &membership.uuid.to_string())
            .append_pair("token", &invite_token);

        if CONFIG.sso_enabled() && CONFIG.sso_only() {
            query_params.append_pair("orgUserHasExistingUser", "false");
            query_params.append_pair("orgSsoIdentifier", &org.name);
        } else if user.private_key.is_some() {
            query_params.append_pair("orgUserHasExistingUser", "true");
        }
    }

    let query_string = query.query().unwrap_or("");
    let invite_link = format!("{}/#/accept-organization/?{}", CONFIG.domain(), query_string);

    Ok(Json(serde_json::to_value(InviteLinkResponse {
        invite_link,
    }).unwrap()))
}

#[get("/user/invite-link?<email>")]
async fn get_user_invite_link(_auth: VWApi, email: String, mut conn: DbConn) -> JsonResult {
    // Find the user by email
    let user = match User::find_by_mail(&email, &mut conn).await {
        Some(user) => user,
        None => err_code!("User not found", Status::NotFound.code),
    };

    // Verify user hasn't set up password yet (still pending)
    if !user.password_hash.is_empty() {
        err_code!("User has already set up their account", Status::BadRequest.code);
    }

    // Generate the invite token using fake admin UUIDs (same as /invite endpoint)
    let org_id: OrganizationId = FAKE_ADMIN_UUID.to_string().into();
    let member_id: MembershipId = FAKE_ADMIN_UUID.to_string().into();

    let claims = generate_invite_claims(
        user.uuid.clone(),
        user.email.clone(),
        org_id.clone(),
        member_id.clone(),
        None,
    );
    let invite_token = encode_jwt(&claims);

    // Build the invite URL
    let org_name = CONFIG.invitation_org_name();
    let mut query = url::Url::parse("https://query.builder").unwrap();
    {
        let mut query_params = query.query_pairs_mut();
        query_params
            .append_pair("email", &user.email)
            .append_pair("organizationName", &org_name)
            .append_pair("organizationId", &org_id.to_string())
            .append_pair("organizationUserId", &member_id.to_string())
            .append_pair("token", &invite_token);

        if CONFIG.sso_enabled() && CONFIG.sso_only() {
            query_params.append_pair("orgUserHasExistingUser", "false");
        } else if user.private_key.is_some() {
            query_params.append_pair("orgUserHasExistingUser", "true");
        }
    }

    let query_string = query.query().unwrap_or("");
    let invite_link = format!("{}/#/accept-organization/?{}", CONFIG.domain(), query_string);

    Ok(Json(serde_json::to_value(InviteLinkResponse {
        invite_link,
    }).unwrap()))
}
