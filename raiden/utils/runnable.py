from typing import Any

import structlog
from gevent import Greenlet

log = structlog.get_logger(__name__)


class Runnable:
    """Greenlet-like class, __run() inside one, but can be stopped and restarted

    Allows subtasks to crash self, and bubble up the exception in the greenlet
    In the future, when proper restart is implemented, may be replaced by actual greenlet
    """

    def __init__(self) -> None:
        self._set_greenlet()

    def start(self) -> None:
        """ Synchronously start task

        Reimplements in children an call super().start() at end to start _run()
        Start-time exceptions may be raised
        """
        if self.greenlet:
            raise RuntimeError(f"Greenlet {self.greenlet!r} already started")
        if self.greenlet.dead:
            self._set_greenlet()
        self.greenlet.start()

    def _set_greenlet(self):
        self.greenlet = Greenlet(self._run)
        self.greenlet.name = f"{self.__class__.__name__}|{self.greenlet.name}"

    def _run(self, *args: Any, **kwargs: Any) -> None:
        """ Reimplements in children to busy wait here

        This busy wait should be finished gracefully after stop(),
        or be killed and re-raise on subtasks exception """
        raise NotImplementedError

    def stop(self) -> None:
        """ Synchronous stop, gracefully tells _run() to exit

        Should wait subtasks to finish.
        Stop-time exceptions may be raised, run exceptions should not (accessible via get())
        """
        raise NotImplementedError

    def on_error(self, subtask: Greenlet) -> None:
        """ Default callback for substasks link_exception

        Default callback re-raises the exception inside _run() """
        log.error(
            "Runnable subtask died!",
            this=self,
            running=bool(self),
            subtask=subtask,
            exc=subtask.exception,
        )
        if self.greenlet:
            self.greenlet.kill(subtask.exception)

    # redirect missing members to underlying greenlet for compatibility
    # but better use greenlet directly for now, to make use of the c extension optimizations
    def __getattr__(self, item: str) -> Any:
        return getattr(self.greenlet, item)

    def __bool__(self) -> bool:
        return bool(self.greenlet)
