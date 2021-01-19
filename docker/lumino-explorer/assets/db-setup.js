databaseName = "lumino_explorer";
db = db.getSiblingDB(databaseName);
db.event_job_metadata.insert({ _id: "1",  lastSyncBlockChannels:"0", lastSyncBlockTokens: "0", periodOfSchedule: "500", _class: "org.rif.lumino.explorer.models.documents.EventJobMetadata"});
db.getCollectionNames();
db.event_job_metadata.count();
