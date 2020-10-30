from collections import namedtuple


class TimestampedEvent(namedtuple("TimestampedEvent", "wrapped_event log_time")):
    def __getattr__(self, item):
        return getattr(self.wrapped_event, item)


DB_CREATE_SETTINGS = """
CREATE TABLE IF NOT EXISTS settings (
    name VARCHAR[24] NOT NULL PRIMARY KEY,
    value TEXT
);
"""

DB_CREATE_STATE_CHANGES = """
CREATE TABLE IF NOT EXISTS state_changes (
    identifier INTEGER PRIMARY KEY AUTOINCREMENT,
    data JSON,
    log_time TEXT
);
"""

DB_CREATE_SNAPSHOT = """
CREATE TABLE IF NOT EXISTS state_snapshot (
    identifier INTEGER PRIMARY KEY,
    statechange_id INTEGER,
    data JSON,
    FOREIGN KEY(statechange_id) REFERENCES state_changes(identifier)
);
"""

DB_CREATE_STATE_EVENTS = """
CREATE TABLE IF NOT EXISTS state_events (
    identifier INTEGER PRIMARY KEY,
    source_statechange_id INTEGER NOT NULL,
    log_time TEXT,
    data JSON,
    FOREIGN KEY(source_statechange_id) REFERENCES state_changes(identifier)
);
"""

DB_CREATE_RUNS = """
CREATE TABLE IF NOT EXISTS runs (
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP PRIMARY KEY,
    raiden_version TEXT NOT NULL
);
"""

DB_CREATE_TOKEN_ACTION = """
CREATE TABLE IF NOT EXISTS token_action (
    identifier INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT,
    expires_at TEXT,
    action_request TEXT
);
"""

DB_CREATE_INVOICES = """
CREATE TABLE IF NOT EXISTS invoices
(
    identifier      INTEGER
        constraint invoices_pk
            primary key autoincrement,
    type            INTEGER,
    status          INTEGER,
    expiration_date TEXT,
    encode          TEXT,
    payment_hash    TEXT,
    secret          TEXT,
    currency        TEXT,
    amount          TEXT,
    description     TEXT,
    target_address  TEXT,
    token_address   TEXT,
    created_at      TEXT
);
"""

DB_CREATE_INVOICES_PAYMENTS = """
CREATE TABLE IF NOT EXISTS invoices_payments (
    identifier INTEGER constraint invoices_payments_pk PRIMARY KEY AUTOINCREMENT,
    invoice_id INTEGER references invoices,
    state_event_id INTEGER references state_events
);
"""

DB_CREATE_CLIENT = """
CREATE TABLE IF NOT EXISTS client (
    address TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    display_name TEXT NOT NULL,
    seed_retry TEXT NOT NULL,
    api_key TEXT NOT NULL,
    type TEXT CHECK ( type IN ('HUB','FULL','LIGHT') ) NOT NULL DEFAULT 'FULL',
    current_server_name TEXT NULL,
    pending_for_deletion INTEGER NULL DEFAULT 0
);
"""

DB_CREATE_LIGHT_CLIENT_PAYMENT = """
CREATE TABLE IF NOT EXISTS light_client_payment(
    payment_id TEXT PRIMARY KEY,
    partner_address TEXT NOT NULL,
    is_lc_initiator INTEGER DEFAULT 1,
    token_network_id TEXT NOT NULL,
    amount TEXT NOT NULL,
    created_on TEXT NOT NULL,
    payment_status  TEXT CHECK  (payment_status in ('InProgress', 'Expired', 'Failed', 'Done', 'Pending', 'Deleted' ) ) NOT NULL DEFAULT 'Pending'
);
"""

DB_CREATE_LIGHT_CLIENT_PROTOCOL_MESSAGE = """
CREATE TABLE IF NOT EXISTS light_client_protocol_message (
    internal_msg_identifier INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT,
    light_client_payment_id TEXT NULLABLE REFERENCES light_client_payment(payment_id) ON DELETE CASCADE ON UPDATE CASCADE,
    message_order INTEGER,
    unsigned_message JSON,
    signed_message JSON,
    message_type TEXT CHECK (message_type in ('PaymentSuccessful', 'PaymentFailure', 'PaymentExpired', 'SettlementRequired', 'PaymentRefund', 'RequestRegisterSecret', 'UnlockLightRequest')) NOT NULL,
    light_client_address TEXT NOT NULL,
    FOREIGN KEY(light_client_address) REFERENCES client(address) ON DELETE CASCADE ON UPDATE CASCADE
);
"""

DB_CREATE_LIGHT_CLIENT_BALANCE_PROOF = """
CREATE TABLE IF NOT EXISTS light_client_balance_proof (
    internal_bp_identifier INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    light_client_payment_id TEXT,
    secret_hash TEXT,
    nonce INTEGER,
    channel_id INTEGER,
    token_network_address TEXT,
    balance_proof JSON,
    lc_balance_proof_signature TEXT,
    FOREIGN KEY(light_client_payment_id)  REFERENCES light_client_payment(payment_id) ON DELETE CASCADE ON UPDATE CASCADE
);
"""

DB_SCRIPT_CREATE_TABLES = """
PRAGMA foreign_keys=off;
BEGIN TRANSACTION;
{}{}{}{}{}{}{}{}{}{}{}{}
COMMIT;
PRAGMA foreign_keys=on;
""".format(
    DB_CREATE_SETTINGS,
    DB_CREATE_STATE_CHANGES,
    DB_CREATE_SNAPSHOT,
    DB_CREATE_STATE_EVENTS,
    DB_CREATE_RUNS,
    DB_CREATE_TOKEN_ACTION,
    DB_CREATE_INVOICES,
    DB_CREATE_INVOICES_PAYMENTS,
    DB_CREATE_CLIENT,
    DB_CREATE_LIGHT_CLIENT_PAYMENT,
    DB_CREATE_LIGHT_CLIENT_PROTOCOL_MESSAGE,
    DB_CREATE_LIGHT_CLIENT_BALANCE_PROOF
)

DB_STATE_EVENT_ADD_CLIENT_FK = """
ALTER TABLE state_events ADD COLUMN client_address TEXT NULLABLE REFERENCES client(address);
"""

DB_UPDATE_TABLES = """
BEGIN TRANSACTION;
{}
COMMIT;
""".format(
    DB_STATE_EVENT_ADD_CLIENT_FK
)
