from time import sleep, time

from django.conf import settings

from psycopg2 import OperationalError


def starts_with_any(string, patterns_list):
    for pattern in patterns_list:
        if string.startswith(pattern):
            return True
    return False


def ensure_connection_with_retries(self):
    """
    A function supposed to be used for patching the standard django database connection class' method
     in order to try to connect to DB multiple times using exponential backoff algorithm.
    After each consecutive connection error it waits 1, 2, 4, 8, 16, 32, ... seconds until success or
     the end of time allowed to spend on reconnection attempts.
    """
    handled_errors_patterns = ('could not connect to server: Connection refused',
                               'could not connect to server: No route to host'
                               'could not translate host name')

    def custom_properties_cleanup(obj):
        delattr(obj, '_is_connecting')
        if hasattr(obj, "_connection_retry"):
            delattr(obj, '_connection_retry')

    if self.connection is not None and hasattr(self.connection, 'closed') and self.connection.closed:
        self.connection = None

    if self.connection is None and not hasattr(self, '_is_connecting'):
        with self.wrap_database_errors:
            self._is_connecting = True
            try:
                self.connect()
            except OperationalError as e:
                # We need to reconnect only after particular OperationalError types.
                if e.args and isinstance(e.args[0], str) and starts_with_any(e.args[0], handled_errors_patterns):
                    # Connection error.
                    if not hasattr(self, "_connection_retry"):
                        self._connection_retry = 0
                        self._stop_trying_at = time() + settings.DB_RETRY_TO_CONNECT_SEC
                    if time() > self._stop_trying_at:  # Stop trying to reconnect.
                        custom_properties_cleanup(self)
                        raise
                    else:
                        seconds = 0
                        # We're gonna make the last try at the very end of allowed time.
                        while time() < self._stop_trying_at:
                            sleep(1)
                            seconds += 1
                            if seconds >= 2 ** self._connection_retry:
                                break
                        self._connection_retry += 1
                        self.connection = None
                        delattr(self, '_is_connecting')
                        self.ensure_connection()
                else:
                    # Other types of OperationalError.
                    custom_properties_cleanup(self)
                    raise
            except Exception:
                # Other errors.
                custom_properties_cleanup(self)
                raise
            else:
                custom_properties_cleanup(self)
