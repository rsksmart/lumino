import sqlite3
import threading
import datetime
import ast
import json

from raiden.constants import SQLITE_MIN_REQUIRED_VERSION
from raiden.exceptions import InvalidDBData, InvalidNumberInput
from raiden.storage.utils import DB_SCRIPT_CREATE_TABLES, TimestampedEvent
from raiden.utils import get_system_spec
from raiden.utils.typing import Any, Dict, NamedTuple, Optional, Tuple
from dateutil.relativedelta import relativedelta

# The latest DB version
RAIDEN_DB_VERSION = 17


class EventRecord(NamedTuple):
    event_identifier: int
    state_change_identifier: int
    data: Any


class StateChangeRecord(NamedTuple):
    state_change_identifier: int
    data: Any


def assert_sqlite_version() -> bool:
    if sqlite3.sqlite_version_info < SQLITE_MIN_REQUIRED_VERSION:
        return False
    return True


class SQLiteStorage:
    def __init__(self, database_path, serializer):
        conn = sqlite3.connect(database_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.text_factory = str
        conn.execute('PRAGMA foreign_keys=ON')
        self.conn = conn

        with conn:
            try:
                conn.executescript(DB_SCRIPT_CREATE_TABLES)
            except sqlite3.DatabaseError:
                raise InvalidDBData(
                    'Existing DB {} was found to be corrupt at Raiden startup. '
                    'Manual user intervention required. Bailing ...'.format(database_path),
                )

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
        self.write_lock = threading.Lock()
        self.serializer = serializer

        self.update_version()

    def update_version(self):
        cursor = self.conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO settings(name, value) VALUES(?, ?)',
            ('version', str(RAIDEN_DB_VERSION)),
        )
        self.conn.commit()

    def log_run(self):
        """ Log timestamp and raiden version to help with debugging """
        version = get_system_spec()['raiden']
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO runs(raiden_version) VALUES (?)', [version])
        self.conn.commit()

    def get_version(self) -> int:
        cursor = self.conn.cursor()
        query = cursor.execute(
            'SELECT value FROM settings WHERE name=?;', ('version',),
        )
        query = query.fetchall()
        # If setting is not set, it's the latest version
        if len(query) == 0:
            return RAIDEN_DB_VERSION

        return int(query[0][0])

    def count_state_changes(self) -> int:
        cursor = self.conn.cursor()
        query = cursor.execute('SELECT COUNT(1) FROM state_changes')
        query = query.fetchall()

        if len(query) == 0:
            return 0

        return int(query[0][0])

    def write_state_change(self, state_change, log_time):
        serialized_data = self.serializer.serialize(state_change)

        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                'INSERT INTO state_changes(identifier, data, log_time) VALUES(null, ?, ?)',
                (serialized_data, log_time),
            )
            last_id = cursor.lastrowid

        return last_id

    def write_state_snapshot(self, statechange_id, snapshot):
        serialized_data = self.serializer.serialize(snapshot)

        with self.write_lock, self.conn:
            cursor = self.conn.execute(
                'INSERT INTO state_snapshot(statechange_id, data) VALUES(?, ?)',
                (statechange_id, serialized_data),
            )
            last_id = cursor.lastrowid

        return last_id

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

        with self.write_lock, self.conn:
            self.conn.executemany(
                'INSERT INTO state_events('
                '   identifier, source_statechange_id, log_time, data'
                ') VALUES(?, ?, ?, ?)',
                events_data,
            )

    def get_latest_state_snapshot(self) -> Optional[Tuple[int, Any]]:
        """ Return the tuple of (last_applied_state_change_id, snapshot) or None"""
        cursor = self.conn.execute(
            'SELECT statechange_id, data from state_snapshot ORDER BY identifier DESC LIMIT 1',
        )
        serialized = cursor.fetchall()

        result = None
        if serialized:
            assert len(serialized) == 1
            last_applied_state_change_id = serialized[0][0]
            snapshot_state = self.serializer.deserialize(serialized[0][1])
            return (last_applied_state_change_id, snapshot_state)

        return result

    def get_snapshot_closest_to_state_change(
            self,
            state_change_identifier: int,
    ) -> Tuple[int, Any]:
        """ Get snapshots earlier than state_change with provided ID. """

        if not (state_change_identifier == 'latest' or isinstance(state_change_identifier, int)):
            raise ValueError("from_identifier must be an integer or 'latest'")

        cursor = self.conn.cursor()
        if state_change_identifier == 'latest':
            cursor.execute(
                'SELECT identifier FROM state_changes ORDER BY identifier DESC LIMIT 1',
            )
            result = cursor.fetchone()

            if result:
                state_change_identifier = result[0]
            else:
                state_change_identifier = 0

        cursor = self.conn.execute(
            'SELECT statechange_id, data FROM state_snapshot '
            'WHERE statechange_id <= ? '
            'ORDER BY identifier DESC LIMIT 1',
            (state_change_identifier, ),
        )
        serialized = cursor.fetchall()

        if serialized:
            assert len(serialized) == 1, 'LIMIT 1 must return one element'
            last_applied_state_change_id = serialized[0][0]
            snapshot_state = self.serializer.deserialize(serialized[0][1])
            result = (last_applied_state_change_id, snapshot_state)
        else:
            result = (0, None)

        return result

    def get_latest_event_by_data_field(
            self,
            filters: Dict[str, Any],
    ) -> EventRecord:
        """ Return all state changes filtered by a named field and value."""
        cursor = self.conn.cursor()

        where_clauses = []
        args = []
        for field, value in filters.items():
            where_clauses.append('json_extract(data, ?)=?')
            args.append(f'$.{field}')
            args.append(value)

        cursor.execute(
            "SELECT identifier, source_statechange_id, data FROM state_events WHERE "
            f"{' AND '.join(where_clauses)}"
            "ORDER BY identifier DESC LIMIT 1",
            args,
        )

        result = EventRecord(
            event_identifier=0,
            state_change_identifier=0,
            data=None,
        )
        try:
            row = cursor.fetchone()
            if row:
                event_id = row[0]
                state_change_identifier = row[1]
                event = self.serializer.deserialize(row[2])
                result = EventRecord(
                    event_identifier=event_id,
                    state_change_identifier=state_change_identifier,
                    data=event,
                )
        except AttributeError:
            raise InvalidDBData(
                'Your local database is corrupt. Bailing ...',
            )

        return result

    def get_latest_state_change_by_data_field(
            self,
            filters: Dict[str, str],
    ) -> StateChangeRecord:
        """ Return all state changes filtered by a named field and value."""
        cursor = self.conn.cursor()

        where_clauses = []
        args = []
        for field, value in filters.items():
            where_clauses.append('json_extract(data, ?)=?')
            args.append(f'$.{field}')
            args.append(value)

        where = ' AND '.join(where_clauses)
        sql = (
            f'SELECT identifier, data '
            f'FROM state_changes '
            f'WHERE {where} '
            f'ORDER BY identifier '
            f'DESC LIMIT 1'
        )
        cursor.execute(sql, args)

        result = StateChangeRecord(state_change_identifier=0, data=None)
        try:
            row = cursor.fetchone()
            if row:
                state_change_identifier = row[0]
                state_change = self.serializer.deserialize(row[1])
                result = StateChangeRecord(
                    state_change_identifier=state_change_identifier,
                    data=state_change,
                )
        except AttributeError:
            raise InvalidDBData(
                'Your local database is corrupt. Bailing ...',
            )

        return result

    def get_statechanges_by_identifier(self, from_identifier, to_identifier):
        if not (from_identifier == 'latest' or isinstance(from_identifier, int)):
            raise ValueError("from_identifier must be an integer or 'latest'")

        if not (to_identifier == 'latest' or isinstance(to_identifier, int)):
            raise ValueError("to_identifier must be an integer or 'latest'")

        cursor = self.conn.cursor()

        if from_identifier == 'latest':
            assert to_identifier is None

            cursor.execute(
                'SELECT identifier FROM state_changes ORDER BY identifier DESC LIMIT 1',
            )
            from_identifier = cursor.fetchone()

        if to_identifier == 'latest':
            cursor.execute(
                'SELECT data FROM state_changes WHERE identifier >= ? ORDER BY identifier ASC',
                (from_identifier,),
            )
        else:
            cursor.execute(
                'SELECT data FROM state_changes WHERE identifier '
                'BETWEEN ? AND ? ORDER BY identifier ASC', (from_identifier, to_identifier),
            )

        try:
            result = [
                self.serializer.deserialize(entry[0])
                for entry in cursor.fetchall()
            ]
        except AttributeError:
            raise InvalidDBData(
                'Your local database is corrupt. Bailing ...',
            )

        return result

    def _query_events(self, limit: int = None, offset: int = None):
        if limit is not None and (not isinstance(limit, int) or limit < 0):
            raise InvalidNumberInput('limit must be a positive integer')

        if offset is not None and (not isinstance(offset, int) or offset < 0):
            raise InvalidNumberInput('offset must be a positive integer')

        limit = -1 if limit is None else limit
        offset = 0 if offset is None else offset

        cursor = self.conn.cursor()

        cursor.execute(
            '''
            SELECT data, log_time FROM state_events
                ORDER BY identifier ASC LIMIT ? OFFSET ?
            ''',
            (limit, offset),
        )

        return cursor.fetchall()

    def get_events_with_timestamps(self, limit: int = None, offset: int = None):
        entries = self._query_events(limit, offset)
        result = [
            TimestampedEvent(self.serializer.deserialize(entry[0]), entry[1])
            for entry in entries
        ]
        return result

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
        return [self.serializer.deserialize(entry[0]) for entry in entries]

    def get_dashboard_data(self, graph_from_date:int = None, graph_to_date:int = None, table_limit:int = None):
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

    def _get_payments_event(self, base_query, limit:int = None, event_type:int = None):
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

    def __del__(self):
        self.conn.close()
