import sqlite3
import threading
from contextlib import contextmanager
import datetime

from eth_utils import to_checksum_address

from raiden.constants import RAIDEN_DB_VERSION, SQLITE_MIN_REQUIRED_VERSION
from raiden.exceptions import InvalidDBData, InvalidNumberInput
from raiden.storage.serialize import SerializationBase
from raiden.storage.utils import DB_SCRIPT_CREATE_TABLES, TimestampedEvent, DB_UPDATE_TABLES
from raiden.utils import get_system_spec
from raiden.utils.typing import Any, Dict, Iterator, List, NamedTuple, Optional, Tuple, Union
from dateutil.relativedelta import relativedelta
from raiden.lightclient.client_model import ClientType


class EventRecord(NamedTuple):
    event_identifier: int
    state_change_identifier: int
    data: Any


class StateChangeRecord(NamedTuple):
    state_change_identifier: int
    data: Any


class SnapshotRecord(NamedTuple):
    identifier: int
    state_change_identifier: int
    data: Any


def assert_sqlite_version() -> bool:
    if sqlite3.sqlite_version_info < SQLITE_MIN_REQUIRED_VERSION:
        return False
    return True


def _sanitize_limit_and_offset(limit: int = None, offset: int = None) -> Tuple[int, int]:
    if limit is not None and (not isinstance(limit, int) or limit < 0):
        raise InvalidNumberInput("limit must be a positive integer")

    if offset is not None and (not isinstance(offset, int) or offset < 0):
        raise InvalidNumberInput("offset must be a positive integer")

    limit = -1 if limit is None else limit
    offset = 0 if offset is None else offset
    return limit, offset


def _filter_from_dict(current: Dict[str, Any]) -> Dict[str, Any]:
    """Takes in a nested dictionary as a filter and returns a flattened filter dictionary"""
    filter_ = dict()

    for k, v in current.items():
        if isinstance(v, dict):
            for sub, v2 in _filter_from_dict(v).items():
                filter_[f"{k}.{sub}"] = v2
        else:
            filter_[k] = v

    return filter_


class SQLiteStorage:
    def __init__(self, database_path):
        conn = sqlite3.connect(database_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.text_factory = str
        conn.execute("PRAGMA foreign_keys=ON")

        # Skip the acquire/release cycle for the exclusive write lock.
        # References:
        # https://sqlite.org/atomiccommit.html#_exclusive_access_mode
        # https://sqlite.org/pragma.html#pragma_locking_mode

        conn.execute("PRAGMA locking_mode=NORMAL")

        # Keep the journal around and skip inode updates.
        # References:
        # https://sqlite.org/atomiccommit.html#_persistent_rollback_journals
        # https://sqlite.org/pragma.html#pragma_journal_mode
        try:
            conn.execute("PRAGMA journal_mode=PERSIST")
        except sqlite3.DatabaseError:
            raise InvalidDBData(
                f"Existing DB {database_path} was found to be corrupt at Raiden startup. "
                f"Manual user intervention required. Bailing."
            )

        with conn:
            conn.executescript(DB_SCRIPT_CREATE_TABLES)

        # When writting to a table where the primary key is the identifier and we want
        # to return said identifier we use cursor.lastrowid, which uses sqlite's last_insert_rowid
        # https://github.com/python/cpython/blob/2.7/Modules/_sqlite/cursor.c#L727-L732
        #
        # According to the documentation (http://www.sqlite.org/c3ref/last_insert_rowid.html)
        # if a different thread tries to use the same connection to write into the table
        # while we query the last_insert_rowid, the result is unpredictable. For that reason
        # we have this write lock here.
        #
        # TODO (If possible):
        # Improve on this and find a better way to protect against this potential race
        # condition.
        self.conn = conn
        self.write_lock = threading.Lock()
        self.in_transaction = False

    def update_version(self):
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO settings(name, value) VALUES("version", ?)',
            (str(RAIDEN_DB_VERSION),),
        )
        self.maybe_commit()

    def log_run(self):
        """ Log timestamp and raiden version to help with debugging """
        version = get_system_spec()["raiden"]
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO runs(raiden_version) VALUES (?)", [version])
        self.maybe_commit()

    def get_version(self) -> int:
        cursor = self.conn.cursor()
        query = cursor.execute('SELECT value FROM settings WHERE name="version";')
        query = query.fetchall()
        # If setting is not set, it's the latest version
        if len(query) == 0:
            return RAIDEN_DB_VERSION

        return int(query[0][0])

    def count_state_changes(self) -> int:
        cursor = self.conn.cursor()
        query = cursor.execute("SELECT COUNT(1) FROM state_changes")
        query = query.fetchall()

        if len(query) == 0:
            return 0

        return int(query[0][0])

    def write_state_change(self, state_change, log_time):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO state_changes(identifier, data, log_time) VALUES(null, ?, ?)",
                (state_change, log_time),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_light_client_payment(self, light_client_payment):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO light_client_payment("
                "payment_id, "
                "light_client_address, "
                "partner_address, "
                "is_lc_initiator, "
                "token_network_id, "
                "amount, "
                "created_on, "
                "payment_status "
                ") VALUES(?, ?, ?, ?, ?,  ?, ?, ?)",
                (str(light_client_payment.payment_id),
                 to_checksum_address(light_client_payment.light_client_address),
                 light_client_payment.partner_address,
                 light_client_payment.is_lc_initiator,
                 light_client_payment.token_network_id,
                 light_client_payment.amount,
                 light_client_payment.created_on,
                 str(light_client_payment.payment_status.value))
            )
            last_id = cursor.lastrowid
        return last_id

    def write_light_client_protocol_message(self, msg_dto):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO light_client_protocol_message("
                "identifier, "
                "message_order, "
                "unsigned_message, "
                "signed_message, "
                "light_client_payment_id "
                ")"
                "VALUES(?, ?, ?, ?, ?)",
                (str(msg_dto.identifier),
                 msg_dto.message_order,
                 msg_dto.unsigned_message,
                 msg_dto.signed_message,
                 str(msg_dto.light_client_payment_id),
                 ),
            )
            last_id = cursor.lastrowid
        return last_id

    def write_light_client_protocol_messages(self, msg_dtos):
        with self.write_lock, self.conn:
            cursor = self.conn.executemany(
                "INSERT INTO light_client_protocol_message("
                "identifier, "
                "message_order, "
                "unsigned_message, "
                "signed_message, "
                "light_client_payment_id "
                ")"
                "VALUES(?, ?, ?, ?, ?)",
                msg_dtos,
            )
            last_id = cursor.lastrowid
        return last_id

    def is_light_client_protocol_message_already_stored(self, payment_id: int, order: int):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT *
                FROM light_client_protocol_message WHERE light_client_payment_id = ? and message_order = ?;
            """,
            (str(payment_id), order)
        )

        return cursor.fetchone()

    def is_light_client_protocol_message_already_stored_with_message_id(self, message_id: int, payment_id: int,
                                                                        order: int):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT *
                FROM light_client_protocol_message WHERE identifier = ? and light_client_payment_id = ? and message_order = ?;
            """,
            (str(message_id), str(payment_id), order)
        )

        return cursor.fetchone()

    def exists_payment(self, payment_id: int):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT *
                FROM light_client_payment WHERE payment_id = ?;
            """,
            (str(payment_id),)
        )
        return cursor.fetchone()

    def write_state_snapshot(self, statechange_id, snapshot):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO state_snapshot(statechange_id, data) VALUES(?, ?)",
                (statechange_id, snapshot),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_token_action(self, token_data):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO token_action(identifier, token, expires_at, action_request) VALUES(null, ?, ?, ?)",
                (token_data['token'], token_data['expires_at'], token_data['action_request']),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_invoice(self, invoice_data):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO invoices("
                "identifier, "
                "type, "
                "status, "
                "expiration_date, "
                "encode, "
                "payment_hash, "
                "secret, "
                "currency, "
                "amount, "
                "description, "
                "target_address, "
                "token_address, "
                "created_at)"
                "VALUES(null, ?, ?, ?, ?, ?, ?, ?, ?, ? ,?, ?, ?)",
                (invoice_data['type'],
                 invoice_data['status'],
                 invoice_data['expiration_date'],
                 invoice_data['encode'],
                 invoice_data['payment_hash'],
                 invoice_data['secret'],
                 invoice_data['currency'],
                 invoice_data['amount'],
                 invoice_data['description'],
                 invoice_data['target_address'],
                 invoice_data['token_address'],
                 invoice_data['created_at'],),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_invoice_payments(self, invoice_data):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO invoices_payments(identifier, "
                "invoice_id, "
                "state_event_id) VALUES(null, ?, ?)",

                (invoice_data['invoice_id'],
                 invoice_data['state_event_id'],)
            )
            last_id = cursor.lastrowid

        return last_id

    def update_invoice(self, data):
        if isinstance(data, (bytes, bytearray)):
            payment_hash = data["payment_hash"].hex()
        else:
            payment_hash = data["payment_hash"]

        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "UPDATE invoices SET status =? WHERE payment_hash=?", (data["status"], payment_hash)
            )
            last_id = cursor.lastrowid

        return last_id

    def query_invoice(self, payment_hash):
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT 
                identifier, 
                type, 
                status, 
                expiration_date, 
                encode, 
                payment_hash, 
                secret, 
                currency, 
                amount, 
                description, 
                target_address, 
                token_address
            FROM invoices WHERE payment_hash = ?;
            """,
            (payment_hash,)
        )

        invoice = cursor.fetchone()
        invoice_dict = None
        if invoice is not None:
            invoice_dict = {"identifier": invoice[0],
                            "type": invoice[1],
                            "status": invoice[2],
                            "expiration_date": invoice[3],
                            "encode": invoice[4],
                            "payment_hash": invoice[5],
                            "secret": invoice[6],
                            "currency": invoice[7],
                            "amount": invoice[8],
                            "description": invoice[9],
                            "target_address": invoice[10],
                            "token_address": invoice[11]}

        return invoice_dict

    def get_all_light_clients(self):
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT 
                address,
                password,
                api_key,
                type,
                display_name,
                seed_retry
            FROM client;
            """,
            ()
        )

        light_clients = cursor.fetchall()

        light_clients = self.light_clients_to_list_of_dicts(light_clients)

        return light_clients

    def light_clients_to_list_of_dicts(self, light_clients):
        list_of_dicts = []
        for light_client in light_clients:
            light_client_dict = {"address": light_client[0],
                                 "password": light_client[1],
                                 "api_key": light_client[2],
                                 "type": light_client[3],
                                 "display_name": light_client[4],
                                 "seed_retry": light_client[5]}
            list_of_dicts.append(light_client_dict)

        return list_of_dicts

    def get_light_client(self, address):
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT 
                address,
                password,
                api_key,
                type,
                display_name,
                seed_retry
            FROM client WHERE address = ?;
            """,
            (address,)
        )

        light_client = cursor.fetchone()
        light_client_dict = None
        if light_client is not None:
            light_client_dict = {"address": light_client[0],
                                 "password": light_client[1],
                                 "api_key": light_client[2],
                                 "type": light_client[3],
                                 "display_name": light_client[4],
                                 "seed_retry": light_client[5]}

        return light_client_dict

    def save_light_client(self, **kwargs):
        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                "INSERT INTO client("
                "address, "
                "password, "
                "api_key, "
                "type, "
                "display_name, "
                "seed_retry)"
                "VALUES(?, ?, ?, ?, ?, ?)",
                (kwargs['address'],
                 kwargs['encrypt_signed_password'],
                 kwargs['api_key'],
                 ClientType.LIGHT.value,
                 kwargs['encrypt_signed_display_name'],
                 kwargs['encrypt_signed_seed_retry'],),
            )
            last_id = cursor.lastrowid

        return last_id

    def query_token_action(self, token):
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT identifier, token, expires_at, action_request
                FROM token_action WHERE token = ?;
            """,
            (token,)
        )

        return cursor.fetchone()

    def query_clients(self, client_type):
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT * FROM client where type = ?;
            """,
            (client_type,)
        )

        return cursor.fetchall()

    def query_client(self, hex_address):
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT * FROM client where address = ?;
            """,
            (hex_address,)
        )

        return cursor.fetchone()

    def query_client_by_api_key(self, api_key):
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT * FROM client where api_key = ?;
            """,
            (api_key,)
        )

        return cursor.fetchone()

    def write_events(self, events):
        """ Save events.
        Args:
            state_change_identifier: Id of the state change that generate these events.
            events: List of Event objects.
        """
        with self.write_lock, self.conn:
            self.conn.executemany(
                "INSERT INTO state_events("
                "   identifier, source_statechange_id, log_time, data"
                ") VALUES(?, ?, ?, ?)",
                events,
            )

    def delete_state_changes(self, state_changes_to_delete: List[Tuple[int]]) -> None:
        """ Delete state changes.
        Args:
            state_changes_to_delete: List of ids to delete.
        """
        with self.write_lock:
            self.conn.executemany(
                "DELETE FROM state_changes WHERE identifier = ?", state_changes_to_delete
            )
            self.maybe_commit()

    def get_latest_state_snapshot(self) -> Optional[Tuple[int, Any]]:
        """ Return the tuple of (last_applied_state_change_id, snapshot) or None"""
        cursor = self.conn.execute(
            "SELECT statechange_id, data from state_snapshot ORDER BY identifier DESC LIMIT 1"
        )
        rows = cursor.fetchall()

        if rows:
            assert len(rows) == 1
            last_applied_state_change_id = rows[0][0]
            snapshot_state = rows[0][1]
            return (last_applied_state_change_id, snapshot_state)

        return None

    def get_snapshot_closest_to_state_change(
        self, state_change_identifier: int
    ) -> Tuple[int, Any]:
        """ Get snapshots earlier than state_change with provided ID. """

        if not (state_change_identifier == "latest" or isinstance(state_change_identifier, int)):
            raise ValueError("from_identifier must be an integer or 'latest'")

        cursor = self.conn.cursor()
        if state_change_identifier == "latest":
            cursor.execute("SELECT identifier FROM state_changes ORDER BY identifier DESC LIMIT 1")
            result = cursor.fetchone()

            if result:
                state_change_identifier = result[0]
            else:
                state_change_identifier = 0

        cursor = self.conn.execute(
            "SELECT statechange_id, data FROM state_snapshot "
            "WHERE statechange_id <= ? "
            "ORDER BY identifier DESC LIMIT 1",
            (state_change_identifier,),
        )
        rows = cursor.fetchall()

        if rows:
            assert len(rows) == 1, "LIMIT 1 must return one element"
            last_applied_state_change_id = rows[0][0]
            snapshot_state = rows[0][1]
            result = (last_applied_state_change_id, snapshot_state)
        else:
            result = (0, None)

        return result

    def get_latest_event_by_data_field(self, filters: Dict[str, Any]) -> EventRecord:
        """ Return all state changes filtered by a named field and value."""
        cursor = self.conn.cursor()

        filters = _filter_from_dict(filters)
        where_clauses = []
        args = []
        for field, value in filters.items():
            where_clauses.append("json_extract(data, ?)=?")
            args.append(f"$.{field}")
            args.append(value)

        cursor.execute(
            "SELECT identifier, source_statechange_id, data FROM state_events WHERE "
            f"{' AND '.join(where_clauses)}"
            "ORDER BY identifier DESC LIMIT 1",
            args,
        )

        result = EventRecord(event_identifier=0, state_change_identifier=0, data=None)

        row = cursor.fetchone()
        if row:
            event_id = row[0]
            state_change_identifier = row[1]
            event = row[2]
            result = EventRecord(
                event_identifier=event_id,
                state_change_identifier=state_change_identifier,
                data=event,
            )

        return result

    def _form_and_execute_json_query(
        self,
        query: str,
        limit: int = None,
        offset: int = None,
        filters: List[Tuple[str, Any]] = None,
        logical_and: bool = True,
    ) -> sqlite3.Cursor:
        limit, offset = _sanitize_limit_and_offset(limit, offset)
        cursor = self.conn.cursor()
        where_clauses = []
        args: List[Union[str, int]] = []
        if filters:
            for field, value in filters:
                where_clauses.append(f"json_extract(data, ?) LIKE ?")
                args.append(f"$.{field}")
                args.append(value)

            if logical_and:
                query += f"WHERE {' AND '.join(where_clauses)}"
            else:
                query += f"WHERE {' OR '.join(where_clauses)}"

        query += "ORDER BY identifier ASC LIMIT ? OFFSET ?"
        args.append(limit)
        args.append(offset)

        cursor.execute(query, args)
        return cursor

    def get_latest_state_change_by_data_field(self, filters: Dict[str, Any]) -> StateChangeRecord:
        """ Return all state changes filtered by a named field and value."""
        cursor = self.conn.cursor()

        where_clauses = []
        args = []
        filters = _filter_from_dict(filters)
        for field, value in filters.items():
            where_clauses.append("json_extract(data, ?)=?")
            args.append(f"$.{field}")
            args.append(value)

        where = " AND ".join(where_clauses)
        sql = (
            f"SELECT identifier, data "
            f"FROM state_changes "
            f"WHERE {where} "
            f"ORDER BY identifier "
            f"DESC LIMIT 1"
        )
        cursor.execute(sql, args)

        result = StateChangeRecord(state_change_identifier=0, data=None)
        row = cursor.fetchone()
        if row:
            state_change_identifier = row[0]
            state_change = row[1]
            result = StateChangeRecord(
                state_change_identifier=state_change_identifier, data=state_change
            )

        return result

    def _get_state_changes(
        self,
        limit: int = None,
        offset: int = None,
        filters: List[Tuple[str, Any]] = None,
        logical_and: bool = True,
    ) -> List[StateChangeRecord]:
        """ Return a batch of state change records (identifier and data)
        The batch size can be tweaked with the `limit` and `offset` arguments.
        Additionally the returned state changes can be optionally filtered with
        the `filters` parameter to search for specific data in the state change data.
        """
        cursor = self._form_and_execute_json_query(
            query="SELECT identifier, data FROM state_changes ",
            limit=limit,
            offset=offset,
            filters=filters,
            logical_and=logical_and,
        )
        result = [StateChangeRecord(state_change_identifier=row[0], data=row[1]) for row in cursor]

        return result

    def batch_query_state_changes(
        self, batch_size: int, filters: List[Tuple[str, Any]] = None, logical_and: bool = True
    ) -> Iterator[List[StateChangeRecord]]:
        """Batch query state change records with a given batch size and an optional filter
        This is a generator function returning each batch to the caller to work with.
        """
        limit = batch_size
        offset = 0
        result_length = 1

        while result_length != 0:
            result = self._get_state_changes(
                limit=limit, offset=offset, filters=filters, logical_and=logical_and
            )
            result_length = len(result)
            offset += result_length
            yield result

    def update_state_changes(self, state_changes_data: List[Tuple[str, int]]) -> None:
        """Given a list of identifier/data state tuples update them in the DB"""
        cursor = self.conn.cursor()
        cursor.executemany(
            "UPDATE state_changes SET data=? WHERE identifier=?", state_changes_data
        )
        self.maybe_commit()

    def get_statechanges_by_identifier(self, from_identifier, to_identifier):
        if not (from_identifier == "latest" or isinstance(from_identifier, int)):
            raise ValueError("from_identifier must be an integer or 'latest'")

        if not (to_identifier == "latest" or isinstance(to_identifier, int)):
            raise ValueError("to_identifier must be an integer or 'latest'")

        cursor = self.conn.cursor()

        if from_identifier == "latest":
            assert to_identifier is None

            cursor.execute("SELECT identifier FROM state_changes ORDER BY identifier DESC LIMIT 1")
            from_identifier = cursor.fetchone()

        if to_identifier == "latest":
            cursor.execute(
                "SELECT data FROM state_changes WHERE identifier >= ? ORDER BY identifier ASC",
                (from_identifier,),
            )
        else:
            cursor.execute(
                "SELECT data FROM state_changes WHERE identifier "
                "BETWEEN ? AND ? ORDER BY identifier ASC",
                (from_identifier, to_identifier),
            )

        result = [entry[0] for entry in cursor]
        return result

    def _query_events(self, limit: int = None, offset: int = None):
        limit, offset = _sanitize_limit_and_offset(limit, offset)
        cursor = self.conn.cursor()

        cursor.execute(
            """
            SELECT data, log_time FROM state_events
                ORDER BY identifier ASC LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )

        return cursor.fetchall()

    def _get_event_records(
        self,
        limit: int = None,
        offset: int = None,
        filters: List[Tuple[str, Any]] = None,
        logical_and: bool = True,
    ) -> List[EventRecord]:
        """ Return a batch of event records
        The batch size can be tweaked with the `limit` and `offset` arguments.
        Additionally the returned events can be optionally filtered with
        the `filters` parameter to search for specific data in the event data.
        """
        cursor = self._form_and_execute_json_query(
            query="SELECT identifier, source_statechange_id, data FROM state_events ",
            limit=limit,
            offset=offset,
            filters=filters,
            logical_and=logical_and,
        )

        result = [
            EventRecord(event_identifier=row[0], state_change_identifier=row[1], data=row[2])
            for row in cursor
        ]
        return result

    def batch_query_event_records(
        self, batch_size: int, filters: List[Tuple[str, Any]] = None, logical_and: bool = True
    ) -> Iterator[List[EventRecord]]:
        """Batch query event records with a given batch size and an optional filter
        This is a generator function returning each batch to the caller to work with.
        """
        limit = batch_size
        offset = 0
        result_length = 1

        while result_length != 0:
            result = self._get_event_records(
                limit=limit, offset=offset, filters=filters, logical_and=logical_and
            )
            result_length = len(result)
            offset += result_length
            yield result

    def update_events(self, events_data: List[Tuple[str, int]]) -> None:
        """Given a list of identifier/data event tuples update them in the DB"""
        cursor = self.conn.cursor()
        cursor.executemany("UPDATE state_events SET data=? WHERE identifier=?", events_data)
        self.maybe_commit()

    def get_events_with_timestamps(self, limit: int = None, offset: int = None):
        entries = self._query_events(limit, offset)
        return [TimestampedEvent(entry[0], entry[1]) for entry in entries]

    def get_payment_events(self,
                           token_network_identifier,
                           our_address,
                           initiator_address,
                           target_address,
                           from_date,
                           to_date,
                           event_type: int = None,
                           limit: int = None,
                           offset: int = None):

        entries = self._query_payments_events(token_network_identifier,
                                              our_address,
                                              initiator_address,
                                              target_address,
                                              from_date,
                                              to_date,
                                              event_type,
                                              limit,
                                              offset)

        result = [
            TimestampedEvent(self.serializer.deserialize(entry[0]), entry[1])
            for entry in entries
        ]
        return result

    def get_payment_event(self, identifier, event_type):
        cursor = self.conn.cursor()

        query = """

           SELECT identifier, data FROM state_events
                   WHERE json_extract(state_events.data,
                      '$.identifier') IN ({})
                   AND
                   json_extract(state_events.data,
                      '$._type') IN ({})        
           """

        query = query.format("\'" + str(identifier) + "\'", "\'" + event_type + "\'")

        cursor.execute(
            query
        )

        payment_event = cursor.fetchone()

        payment_event_dict = {"identifier": payment_event[0],
                              "data": payment_event[1]}

        return payment_event_dict

    def _query_payments_events(self,
                               token_network_identifier,
                               our_address,
                               initiator_address,
                               target_address,
                               from_date,
                               to_date,
                               event_type: int = None,
                               limit: int = None,
                               offset: int = None):

        if limit is not None and (not isinstance(limit, int) or limit < 0):
            raise InvalidNumberInput('limit must be a positive integer')

        if offset is not None and (not isinstance(offset, int) or offset < 0):
            raise InvalidNumberInput('offset must be a positive integer')

        limit = -1 if limit is None else limit
        offset = 0 if offset is None else offset

        query = self._get_query_with_values(token_network_identifier,
                                            our_address,
                                            initiator_address,
                                            target_address,
                                            event_type,
                                            from_date,
                                            to_date,
                                            limit,
                                            offset)

        cursor = self.conn.cursor()

        print(query[0])
        print(query[1])

        cursor.execute(
            query[0],
            query[1],
        )

        return cursor.fetchall()

    def _get_query_with_values(self,
                               token_network_identifier,
                               our_address,
                               initiator_address,
                               target_address,
                               event_type,
                               from_date,
                               to_date,
                               limit,
                               offset):

        query = """ 

            SELECT
                data, 
                log_time
            FROM
                state_events
            WHERE
                json_extract(state_events.data,
                        '$._type') IN ({}) {} {} {} {} 
            LIMIT ? OFFSET ?

                    """

        target_query = ""
        initiator_query = ""
        or_conditional = False

        event_type_result = self._get_event_type_query(event_type)
        token_network_identifier_result = self._get_token_network_identifier_query(token_network_identifier)

        if target_address is not None and target_address.lower() == our_address.lower():
            event_type_result = self._get_event_type_query(1)
        elif target_address is not None:
            target_query = self._get_query_for_node_address('target', or_conditional)

        if initiator_address is not None and initiator_address.lower() == our_address.lower():
            event_type_result = self._get_event_type_query(3)
        elif initiator_address is not None:
            if target_address:
                or_conditional = True
            initiator_query = self._get_query_for_node_address('initiator', or_conditional)

        event_range_query = self._get_date_range_query(from_date, to_date)
        query = query.format(', '.join(['"{}"'.format(value) for value in event_type_result]),
                             token_network_identifier_result,
                             event_range_query,
                             target_query,
                             initiator_query)

        tuple_for_execute = self._get_tuple_to_get_payments(token_network_identifier,
                                                            our_address,
                                                            initiator_address,
                                                            target_address,
                                                            from_date,
                                                            to_date,
                                                            limit,
                                                            offset,
                                                            or_conditional)

        return query, tuple_for_execute

    def _get_query_for_node_address(self, node_address_label, or_contiional):

        result = " AND json_extract(state_events.data, '$.{}') = ? "

        if or_contiional:
            result = " OR json_extract(state_events.data, '$.{}') = ?  " \
                     " AND json_extract(state_events.data, '$.token_network_identifier') = ?"

        if node_address_label is not None:
            result = result.format(node_address_label)
        return result

    def _get_token_network_identifier_query(self, token_network_identifier):
        result = " "
        if token_network_identifier is not None:
            result = " AND json_extract(state_events.data,'$.token_network_identifier') = ? "
        return result

    def _get_event_type_query(self, event_type: int = None):

        event_type_result = ['raiden.transfer.events.EventPaymentReceivedSuccess',
                             'raiden.transfer.events.EventPaymentSentFailed',
                             'raiden.transfer.events.EventPaymentSentSuccess']

        if event_type == 1:
            event_type_result = [event_type_result[0]]
        elif event_type == 2:
            event_type_result = [event_type_result[1]]
        elif event_type == 3:
            event_type_result = [event_type_result[2]]

        return event_type_result

    def _get_date_range_query(self, from_date, to_date):
        date_range_result = " "
        if from_date is not None and to_date is not None:
            date_range_result = " AND log_time BETWEEN ? and ? "
        elif from_date is not None and to_date is None:
            date_range_result = " AND log_time >= ?"
        elif to_date is not None and from_date is None:
            date_range_result = " AND log_time <= ?"

        return date_range_result

    def _get_tuple_to_get_payments(self,
                                   token_network_identifier,
                                   our_address,
                                   initiator_address,
                                   target_address,
                                   from_date,
                                   to_date,
                                   limit,
                                   offset,
                                   or_conditional):

        result = [limit, offset]

        if initiator_address is not None and initiator_address.lower() != our_address.lower():
            if or_conditional:
                result.insert(0, token_network_identifier)
            result.insert(0, initiator_address)
        if target_address is not None and target_address.lower() != our_address.lower():
            result.insert(0, target_address)
        if from_date is not None and to_date is not None:
            result.insert(0, to_date)
            result.insert(0, from_date)
        if from_date is not None and to_date is None:
            result.insert(0, from_date)
        if to_date is not None and from_date is None:
            result.insert(0, to_date)
        if token_network_identifier is not None:
            result.insert(0, token_network_identifier)

        return tuple(result)

    def get_events(self, limit: int = None, offset: int = None):
        entries = self._query_events(limit, offset)
        return [entry[0] for entry in entries]

    def get_state_changes(self, limit: int = None, offset: int = None):
        entries = self._get_state_changes(limit, offset)
        return [entry.data for entry in entries]

    def get_snapshots(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT identifier, statechange_id, data FROM state_snapshot")

        return [SnapshotRecord(snapshot[0], snapshot[1], snapshot[2]) for snapshot in cursor]

    def update_snapshot(self, identifier, new_snapshot):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE state_snapshot SET data=? WHERE identifier=?", (new_snapshot, identifier)
        )
        self.maybe_commit()

    def update_snapshots(self, snapshots_data: List[Tuple[str, int]]):
        """Given a list of snapshot data, update them in the DB
        The snapshots_data should be a list of tuples of snapshots data
        and identifiers in that order.
        """
        cursor = self.conn.cursor()
        cursor.executemany("UPDATE state_snapshot SET data=? WHERE identifier=?", snapshots_data)
        self.maybe_commit()

    def maybe_commit(self):
        if not self.in_transaction:
            self.conn.commit()

    @contextmanager
    def transaction(self):
        cursor = self.conn.cursor()
        self.in_transaction = True
        try:
            cursor.execute("BEGIN")
            yield
            cursor.execute("COMMIT")
        except:  # noqa
            cursor.execute("ROLLBACK")
            raise
        finally:
            self.in_transaction = False

    def get_dashboard_data(self, graph_from_date: int = None, graph_to_date: int = None, table_limit: int = None):
        data_graph = self._get_graph_data(graph_from_date, graph_to_date)
        data_table = self._get_table_data(table_limit)
        data_general_payments = self._get_general_data_payments()
        result = {
            "data_graph": data_graph,
            "data_table": data_table,
            "data_general_payments": data_general_payments
        }
        return result

    def _get_general_data_payments(self):

        query = """ 
            SELECT
                CASE
                    {}
                END event_type_code,
                json_extract(state_events.data, '$._type') AS event_type_class_name,
                COUNT(json_extract(state_events.data, '$._type')) AS quantity
            FROM
                state_events
            WHERE
                json_extract(state_events.data,'$._type') IN ({})
            GROUP BY                
                json_extract(state_events.data,'$._type')          
        """

        event_type_result = self._get_event_type_query()
        case_type_event = self._get_sql_case_type_event_payment()
        query = query.format(case_type_event, ', '.join(['"{}"'.format(value) for value in event_type_result]))

        cursor = self.conn.cursor()

        cursor.execute(
            query
        )

        return cursor.fetchall()

    def _get_sql_case_type_event_payment(self):
        case_type_event = """

        json_extract(state_events.data,'$._type')
                    WHEN 'raiden.transfer.events.EventPaymentReceivedSuccess' THEN '1'
                    WHEN 'raiden.transfer.events.EventPaymentSentFailed' THEN '2'
                    WHEN 'raiden.transfer.events.EventPaymentSentSuccess' THEN '3' 

        """
        return case_type_event

    def _get_sql_case_type_label_event_type(self):
        case_event_type_label = """        

        json_extract(state_events.data,'$._type')
                    WHEN 'raiden.transfer.events.EventPaymentReceivedSuccess' THEN 'Payment Received'
                    WHEN 'raiden.transfer.events.EventPaymentSentFailed' THEN 'Payment Sent Failed'
                    WHEN 'raiden.transfer.events.EventPaymentSentSuccess' THEN 'Payment Sent Success'

        """
        return case_event_type_label

    def _get_table_data(self, limit: int = None):

        if limit is not None and (not isinstance(limit, int) or limit < 0):
            raise InvalidNumberInput('limit must be a positive integer')

        limit = -1 if limit is None else limit

        base_query = '''

            SELECT
                log_time, 
                data
            FROM
                state_events
            WHERE
                json_extract(state_events.data,
                '$._type') IN ({})	
            LIMIT ?	

        '''

        payments_received = self._get_payments_event(base_query, limit, 1)
        payments_sent = self._get_payments_event(base_query, limit, 3)

        result = {
            "payments_received": payments_received,
            "payments_sent": payments_sent
        }

        return result

    def _get_payments_event(self, base_query, limit: int = None, event_type: int = None):
        cursor = self.conn.cursor()
        query = base_query

        if event_type == 1:
            in_clause_value = ['raiden.transfer.events.EventPaymentReceivedSuccess']
        elif event_type == 3:
            in_clause_value = ['raiden.transfer.events.EventPaymentSentSuccess']

        query = query.format(', '.join(['"{}"'.format(value) for value in in_clause_value]))

        cursor.execute(
            query,
            (limit,),
        )

        return cursor.fetchall()

    def _get_graph_data(self, from_date, to_date):
        cursor = self.conn.cursor()

        query = """

        SELECT
            CASE
		        {}
	        END event_type_code,
	        json_extract(state_events.data, '$._type') AS event_type_class_name,
	        CASE
		        {}
	        END event_type_label,
	        COUNT(json_extract(state_events.data, '$._type')) AS quantity,
	        log_time,	                   
	        STRFTIME("%m", log_time) AS month_of_year_code,
	        CASE 
	            STRFTIME("%m", log_time)
	                WHEN '01' THEN 'JAN'
	                WHEN '02' THEN 'FEB'
	                WHEN '03' THEN 'MAR'
	                WHEN '04' THEN 'APR'
	                WHEN '05' THEN 'MAY'
	                WHEN '06' THEN 'JUN'
	                WHEN '07' THEN 'JUL'
	                WHEN '08' THEN 'AUG'
	                WHEN '09' THEN 'SET'
	                WHEN '10' THEN 'OCT'
	                WHEN '11' THEN 'NOV'
	                WHEN '12' THEN 'DIC'
	        END month_of_year_label 	     
        FROM
	        state_events
        WHERE
	        json_extract(state_events.data,
	        '$._type') IN ({})
	    AND log_time BETWEEN ? AND ?
        GROUP BY STRFTIME("%m", log_time), json_extract(state_events.data,'$._type')


        """
        event_type_result = self._get_event_type_query()
        case_type_event = self._get_sql_case_type_event_payment()
        case_type_event_label = self._get_sql_case_type_label_event_type()
        query = query.format(case_type_event, case_type_event_label,
                             ', '.join(['"{}"'.format(value) for value in event_type_result]), )

        default_from_date = from_date
        default_to_date = to_date
        if from_date is None:
            default_from_date = datetime.datetime.utcnow() - relativedelta(years=1)
        if to_date is None:
            default_to_date = datetime.datetime.utcnow()

        if isinstance(default_from_date, datetime.datetime):
            default_from_date = default_from_date.isoformat()
        if isinstance(default_to_date, datetime.datetime):
            default_to_date = default_to_date.isoformat()

        cursor.execute(
            query,
            (default_from_date, default_to_date)
        )

        return cursor.fetchall()

    def get_light_client_payment(self, payment_id):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT payment_id, light_client_address, partner_address, is_lc_initiator,
            token_network_id, amount, created_on, payment_status
            FROM light_client_payment
            WHERE payment_id = ?
            """,
            (str(payment_id),),
        )
        return cursor.fetchone()

    def get_light_client_messages(self, from_message):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT identifier, message_order, unsigned_message, signed_message, light_client_payment_id" +
            " FROM light_client_protocol_message" +
            " WHERE internal_msg_identifier >= ?" 
            "ORDER BY light_client_payment_id, message_order ASC",
            (from_message,),

        )
        return cursor.fetchall()

    def get_light_client_protocol_message_by_identifier(self, identifier):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT identifier, message_order, unsigned_message, signed_message, light_client_payment_id
            FROM light_client_protocol_message
            WHERE identifier  = ?
            ORDER BY message_order ASC
            """,
            (str(identifier),),
        )
        return cursor.fetchone()

    def __del__(self):
        self.conn.close()


class SerializedSQLiteStorage(SQLiteStorage):
    def __init__(self, database_path, serializer: SerializationBase):
        super().__init__(database_path)

        self.serializer = serializer

    def get_light_client_messages(self, from_message):
        messages = super().get_light_client_messages(from_message)
        result = []
        if messages:
            for message in messages:
                signed = False
                if message[3] is not None:
                    signed = True
                if message[3] is not None:
                    serialized_signed_msg = self.serializer.deserialize(message[3])
                else:
                    serialized_signed_msg = None
                if message[2] is not None:
                    serialized_unsigned_msg = self.serializer.deserialize(message[2])
                else:
                    serialized_unsigned_msg = None
                result.append(
                    (signed, message[1], message[4], serialized_unsigned_msg,
                     serialized_signed_msg, message[0]))
        return result

    def query_invoice(self, payment_hash_invoice):
        return super().query_invoice(payment_hash_invoice)

    def update_invoice(self, payment_hash_invoice):
        return super().update_invoice(payment_hash_invoice)

    def write_light_client_protocol_messages(self, msg_dtos):
        data = [
            (msg_dto.identifier, msg_dto.message_order, self.serializer.serialize(msg_dto.unsigned_message),
             self.serializer.serialize(msg_dto.signed_message),
             msg_dto.state_change_id, msg_dto.light_client_payment_id)
            for msg_dto in msg_dtos
        ]
        return super().write_light_client_protocol_messages(data)

    def write_light_client_protocol_message(self, new_message, msg_dto):
        serialized_data = self.serializer.serialize(new_message)
        if msg_dto.is_signed:
            msg_dto.signed_message = serialized_data
        else:
            msg_dto.unsigned_message = serialized_data
        return super().write_light_client_protocol_message(msg_dto)

    def write_state_change(self, state_change, log_time):
        serialized_data = self.serializer.serialize(state_change)
        return super().write_state_change(serialized_data, log_time)

    def write_state_snapshot(self, statechange_id, snapshot):
        serialized_data = self.serializer.serialize(snapshot)
        return super().write_state_snapshot(statechange_id, serialized_data)

    def write_events(self, state_change_identifier, events, log_time):
        """ Save events.
        Args:
            state_change_identifier: Id of the state change that generate these events.
            events: List of Event objects.
        """
        events_data = [
            (None, state_change_identifier, log_time, self.serializer.serialize(event))
            for event in events
        ]
        return super().write_events(events_data)

    def get_latest_state_snapshot(self) -> Optional[Tuple[int, Any]]:
        """ Return the tuple of (last_applied_state_change_id, snapshot) or None"""
        row = super().get_latest_state_snapshot()

        if row:
            last_applied_state_change_id = row[0]
            snapshot_state = self.serializer.deserialize(row[1])
            return (last_applied_state_change_id, snapshot_state)

        return None

    def get_snapshot_closest_to_state_change(
        self, state_change_identifier: int
    ) -> Tuple[int, Any]:
        """ Get snapshots earlier than state_change with provided ID. """

        row = super().get_snapshot_closest_to_state_change(state_change_identifier)

        if row[1]:
            last_applied_state_change_id = row[0]
            snapshot_state = self.serializer.deserialize(row[1])
            result = (last_applied_state_change_id, snapshot_state)
        else:
            result = (0, None)

        return result

    def get_latest_event_by_data_field(self, filters: Dict[str, Any]) -> EventRecord:
        """ Return all state changes filtered by a named field and value."""
        event = super().get_latest_event_by_data_field(filters)

        if event.event_identifier > 0:
            event = EventRecord(
                event_identifier=event.event_identifier,
                state_change_identifier=event.state_change_identifier,
                data=self.serializer.deserialize(event.data),
            )

        return event

    def get_latest_state_change_by_data_field(self, filters: Dict[str, str]) -> StateChangeRecord:
        """ Return all state changes filtered by a named field and value."""

        state_change = super().get_latest_state_change_by_data_field(filters)

        if state_change.state_change_identifier > 0:
            state_change = StateChangeRecord(
                state_change_identifier=state_change.state_change_identifier,
                data=self.serializer.deserialize(state_change.data),
            )

        return state_change

    def get_statechanges_by_identifier(self, from_identifier, to_identifier):
        state_changes = super().get_statechanges_by_identifier(from_identifier, to_identifier)
        return [self.serializer.deserialize(state_change) for state_change in state_changes]

    def get_events_with_timestamps(self, limit: int = None, offset: int = None):
        events = super().get_events_with_timestamps(limit, offset)
        return [
            TimestampedEvent(self.serializer.deserialize(event.wrapped_event), event.log_time)
            for event in events
        ]

    def get_events(self, limit: int = None, offset: int = None):
        events = super().get_events(limit, offset)
        return [self.serializer.deserialize(event) for event in events]
