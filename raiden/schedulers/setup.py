from apscheduler.schedulers.background import BackgroundScheduler
from raiden.schedulers.alive_schedule import notice_explorer_to_be_alive


def setup_schedule_config(self, endpoint_explorer, node_address):
    scheduler = BackgroundScheduler()
    scheduler.add_job(lambda : notice_explorer_to_be_alive(endpoint_explorer, node_address), 'interval', seconds=3)
    scheduler.start()
