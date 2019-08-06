from datetime import datetime
import calendar
from dateutil.relativedelta import relativedelta
from dateutil import parser

UTC_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def get_utc_unix_time():
    utc_date_time = datetime.utcnow()
    unix_time = calendar.timegm(utc_date_time.utctimetuple())
    return unix_time


def get_utc_expiration_time(expiration):
    expires_at = datetime.utcnow() + relativedelta(seconds=expiration)
    expires_at_iso_format = expires_at.isoformat()
    return expires_at_iso_format


def parse_utc_str(utc_str):
    return parser.parse(utc_str)


def is_invoice_expired(expiration_date):
    expiration_date = parse_utc_str(expiration_date)
    is_expired = False
    utc_now = datetime.utcnow()

    if expiration_date < utc_now:
        is_expired = True

    return is_expired
