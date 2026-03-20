use rocket::serde::json::Json;
use rocket::{http::Status, Route, request::{FromRequest, Outcome, Request}};
use serde::{Deserialize, Serialize};

use crate::{
    api::{EmptyResult, JsonResult},
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
    routes![invite_user, get_user_details, exposed, get_invite_link, get_user_invite_link]
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CountData {
    #[serde(default)]
    org: std::collections::HashMap<String, i32>,
    #[serde(default)]
    me: i32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExposedData {
    user_id: String,
    #[serde(default)]
    org: std::collections::HashMap<String, i32>,
    #[serde(default)]
    me: i32,
    #[serde(default)]
    weak: Option<CountData>,
    #[serde(default)]
    reused: Option<CountData>,
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
    exposed_count: i64,
    weak_count: i64,
    reused_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserDetailsResponse {
    status: String,
    org_id: Option<String>,
    members_count: usize,
    members: Vec<MemberInfo>,
    exposed_count: i64,
    weak_count: i64,
    reused_count: i64,
    last_updated_at: Option<String>,
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
                        let (exposed_count, weak_count, reused_count) = Report::find_by_user_personal(&m.user_uuid, &conn)
                            .await
                            .map(|r| (r.exposed_count as i64, r.weak_count as i64, r.reused_count as i64))
                            .unwrap_or((0, 0, 0));
                        member_list.push(MemberInfo {
                            email: user.email,
                            role: member_role.to_string(),
                            status: member_status.to_string(),
                            exposed_count,
                            weak_count,
                            reused_count,
                        });
                    }
                }
                (members_count, member_list)
            } else {
                (0, Vec::new())
            };

            // Org counts and last_updated_at: search reports by org_uuid (0 if no organization)
            let (exposed_count, weak_count, reused_count, last_updated_at) = if let Some(membership) = memberships.first() {
                match Report::find_by_org(&membership.org_uuid, &conn).await {
                    Some(report) => (
                        report.exposed_count,
                        report.weak_count,
                        report.reused_count,
                        Some(report.last_updated_at.and_utc().to_rfc3339()),
                    ),
                    None => (0, 0, 0, None),
                }
            } else {
                (0, 0, 0, None)
            };

            let org_id = memberships.first().map(|m| m.org_uuid.to_string());

            Ok(Json(serde_json::to_value(UserDetailsResponse {
                status,
                org_id,
                members_count,
                members,
                exposed_count: exposed_count as i64,
                weak_count: weak_count as i64,
                reused_count: reused_count as i64,
                last_updated_at,
            }).unwrap()))
        }
        None => err_code!("User not found", Status::NotFound.code),
    }
}

#[post("/exposed", format = "application/json", data = "<data>")]
async fn exposed(data: Json<ExposedData>, mut conn: DbConn) -> EmptyResult {
    let data: ExposedData = data.into_inner();

    let user_uuid = UserId::from(data.user_id.clone());

    // Extract personal counts
    let personal_weak = data.weak.as_ref().map(|w| w.me).unwrap_or(0);
    let personal_reused = data.reused.as_ref().map(|r| r.me).unwrap_or(0);

    match User::find_by_uuid(&user_uuid, &mut conn).await {
        Some(_) => {
            // Get user's memberships once for efficiency
            let user_memberships = Membership::find_by_user(&user_uuid, &mut conn).await;

            // 1. Store personal counts (me field) - with userId, no org
            match Report::find_by_user_personal(&user_uuid, &conn).await {
                Some(mut existing_report) => {
                    existing_report.update_counts(data.me, personal_weak, personal_reused);
                    existing_report.save(&conn).await?;
                }
                None => {
                    let mut report = Report::new_personal(user_uuid.clone(), data.me, personal_weak, personal_reused);
                    report.save(&conn).await?;
                }
            }

            // 2. Store organization-specific counts (no userId, only orgId)
            for (org_id_str, exposed_count) in &data.org {
                let org_uuid = OrganizationId::from(org_id_str.clone());

                // Verify user is member of this organization
                let is_member = user_memberships
                    .iter()
                    .any(|membership| membership.org_uuid == org_uuid);

                if !is_member {
                    continue; // Skip if user is not a member of this org
                }

                // Get org-specific weak and reused counts
                let org_weak = data.weak.as_ref().and_then(|w| w.org.get(org_id_str)).copied().unwrap_or(0);
                let org_reused = data.reused.as_ref().and_then(|r| r.org.get(org_id_str)).copied().unwrap_or(0);

                // Find and update or create new report for this specific org (no userId stored)
                match Report::find_by_org(&org_uuid, &conn).await {
                    Some(mut existing_report) => {
                        existing_report.update_counts(*exposed_count, org_weak, org_reused);
                        existing_report.save(&conn).await?;
                    }
                    None => {
                        let mut report = Report::new_org(org_uuid, *exposed_count, org_weak, org_reused);
                        report.save(&conn).await?;
                    }
                }
            }
        }
        None => (),
    }

    Ok(())
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
