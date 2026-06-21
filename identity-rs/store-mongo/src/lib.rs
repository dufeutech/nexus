//! MongoDB adapter for the `ProfileStore` port (RFC §3.5 + C4).
//!
//! - Documents are keyed by `_id = sub` (so delete change-events, which only
//!   carry `documentKey._id`, still tell us which subject to evict).
//! - `watch` uses change streams with `full_document = updateLookup` so every
//!   insert/update/replace carries the whole Profile. Change streams REQUIRE the
//!   server to run as a replica set (even a single-node one).
//! - Point reads/writes/deletes use the default `_id` index — no extra index.

use async_trait::async_trait;
use futures::stream::{StreamExt, TryStreamExt};
use mongodb::bson::{doc, from_document, from_slice, to_document, to_vec, Document};
use mongodb::change_stream::event::{OperationType, ResumeToken};
use mongodb::options::FullDocumentType;
use mongodb::{Client, Collection};
use tracing::warn;

use identity_core::store::{BoxError, Change, ChangeEvent, ChangeFeed, ProfileStore, WatchToken};
use identity_core::Profile;

#[derive(Clone)]
pub struct MongoStore {
    coll: Collection<Document>,
}

impl MongoStore {
    pub async fn connect(uri: &str, db: &str, collection: &str) -> Result<Self, BoxError> {
        let client = Client::with_uri_str(uri).await?;
        let coll = client.database(db).collection::<Document>(collection);
        Ok(Self { coll })
    }

    fn to_doc(profile: &Profile) -> Result<Document, BoxError> {
        let mut d = to_document(profile)?;
        // _id IS the subject — drives point lookups and delete-event resolution.
        d.insert("_id", &profile.sub);
        Ok(d)
    }
}

#[async_trait]
impl ProfileStore for MongoStore {
    async fn get(&self, sub: &str) -> Result<Option<Profile>, BoxError> {
        match self.coll.find_one(doc! { "_id": sub }).await? {
            Some(d) => Ok(Some(from_document(d)?)),
            None => Ok(None),
        }
    }

    async fn put(&self, profile: &Profile) -> Result<(), BoxError> {
        let d = Self::to_doc(profile)?;
        self.coll
            .replace_one(doc! { "_id": &profile.sub }, d)
            .upsert(true)
            .await?;
        Ok(())
    }

    async fn delete(&self, sub: &str) -> Result<(), BoxError> {
        self.coll.delete_one(doc! { "_id": sub }).await?;
        Ok(())
    }

    async fn scan_all(&self) -> Result<Vec<Profile>, BoxError> {
        let mut cursor = self.coll.find(doc! {}).await?;
        let mut out = Vec::new();
        while let Some(d) = cursor.try_next().await? {
            match from_document::<Profile>(d) {
                Ok(p) => out.push(p),
                Err(e) => warn!(error = %e, "skipping undecodable profile doc"),
            }
        }
        Ok(out)
    }

    async fn watch(&self, after: Option<WatchToken>) -> Result<ChangeFeed, BoxError> {
        let mut builder = self.coll.watch().full_document(FullDocumentType::UpdateLookup);
        if let Some(tok) = after {
            // Resume strictly after the last event we processed, so a reconnect
            // replays the gap and no change (e.g. a suspension) is lost.
            let rt: ResumeToken = from_slice(&tok)?;
            builder = builder.start_after(rt);
        }
        let cs = builder.await?;
        let stream = cs.filter_map(|res| async move {
            match res {
                Err(e) => Some(Err(Box::new(e) as BoxError)),
                Ok(ev) => {
                    // `ev.id` is this event's resume token — encode it opaquely.
                    let token = match to_vec(&ev.id) {
                        Ok(t) => t,
                        Err(_) => return None,
                    };
                    let change = match ev.operation_type {
                        OperationType::Insert
                        | OperationType::Update
                        | OperationType::Replace => ev
                            .full_document
                            .and_then(|d| from_document::<Profile>(d).ok())
                            .map(Change::Upsert),
                        OperationType::Delete => ev
                            .document_key
                            .as_ref()
                            .and_then(|k| k.get_str("_id").ok())
                            .map(|sub| Change::Delete(sub.to_string())),
                        _ => None,
                    };
                    change.map(|change| Ok(ChangeEvent { change, token }))
                }
            }
        });
        Ok(stream.boxed())
    }
}
