from apscheduler.schedulers.gevent import GeventScheduler
from raiden.schedulers.alive_schedule import notice_explorer_to_be_alive


def setup_schedule_config(self, endpoint_explorer, node_address):
    scheduler = GeventScheduler()
    scheduler.add_job(lambda : notice_explorer_to_be_alive(endpoint_explorer, node_address), 'interval', minutes=30)
    scheduler.start()
