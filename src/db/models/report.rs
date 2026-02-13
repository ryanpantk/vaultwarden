use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;

use super::{OrganizationId, UserId};
use crate::db::schema::reports;
use crate::{
    api::EmptyResult,
    db::DbConn,
    error::MapResult,
    util::get_uuid,
};
use macros::UuidFromParam;

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Selectable)]
#[diesel(table_name = reports)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct Report {
    pub uuid: ReportId,
    pub user_uuid: Option<UserId>,
    pub org_uuid: Option<OrganizationId>,
    pub exposed_count: i32,
    pub created_at: NaiveDateTime,
    pub last_updated_at: NaiveDateTime,
    pub weak_count: i32,
    pub reused_count: i32,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    UuidFromParam,
)]
#[deref(forward)]
#[from(forward)]
pub struct ReportId(String);

impl Report {
    pub fn new_personal(user_uuid: UserId, exposed_count: i32, weak_count: i32, reused_count: i32) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: ReportId::from(get_uuid()),
            user_uuid: Some(user_uuid),
            org_uuid: None,
            exposed_count,
            created_at: now,
            last_updated_at: now,
            weak_count,
            reused_count,
        }
    }

    pub fn new_org(org_uuid: OrganizationId, exposed_count: i32, weak_count: i32, reused_count: i32) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: ReportId::from(get_uuid()),
            user_uuid: None,
            org_uuid: Some(org_uuid),
            exposed_count,
            created_at: now,
            last_updated_at: now,
            weak_count,
            reused_count,
        }
    }

    pub async fn find_by_user_personal(user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            reports::table
                .filter(reports::user_uuid.eq(user_uuid))
                .filter(reports::org_uuid.is_null())
                .first::<Self>(conn)
                .ok()
        }}
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        db_run! { conn: {
            reports::table
                .filter(reports::user_uuid.is_null())
                .filter(reports::org_uuid.eq(org_uuid))
                .first::<Self>(conn)
                .ok()
        }}
    }


    pub fn update_counts(&mut self, exposed_count: i32, weak_count: i32, reused_count: i32) {
        self.exposed_count = if exposed_count < 0 { 0 } else { exposed_count };
        self.weak_count = if weak_count < 0 { 0 } else { weak_count };
        self.reused_count = if reused_count < 0 { 0 } else { reused_count };
        self.last_updated_at = Utc::now().naive_utc();
    }

    pub async fn save(&mut self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                diesel::replace_into(reports::table)
                    .values(&*self)
                    .execute(conn)
                    .map_res("Error saving report")
            }
            postgresql {
                diesel::insert_into(reports::table)
                    .values(&*self)
                    .on_conflict(reports::uuid)
                    .do_update()
                    .set(&*self)
                    .execute(conn)
                    .map_res("Error saving report")
            }
        }
    }
}
