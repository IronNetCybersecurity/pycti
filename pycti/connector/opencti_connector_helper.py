from __future__ import annotations

import base64
import json
import logging
import os
import signal
import ssl
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import FrameType, TracebackType
from typing import Any, Callable, Dict, List, Mapping, Optional, Type, Union

import pika
import yaml
from pika.exceptions import NackError, UnroutableError
from sseclient import SSEClient

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.connector.opencti_connector import OpenCTIConnector
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter

STIX_EXT_MITRE = "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"
STIX_EXT_OCTI = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
STIX_EXT_OCTI_SCO = "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"

log = logging.getLogger(__name__)
logging.getLogger("pika").setLevel(logging.ERROR)


def kill_program_hook(
    etype: Type[BaseException],
    value: BaseException,
    tb: TracebackType,
):
    """
    Print an exception and then kill the program
    :param etype: Exception type
    :param value: The exception itself
    :param tb: Traceback
    :return: None
    """
    traceback.print_exception(etype, value, tb)
    os.kill(os.getpid(), signal.SIGKILL)


sys.excepthook = kill_program_hook


def get_config_variable(
    env_var: str,
    yaml_path: List,
    config: Dict[str, Any] = None,
    is_number: bool = False,
    default=None,
) -> Union[bool, int, str, None]:
    """Get a configuration variable from various sources
    :param env_var: Environment variable name
    :param yaml_path: Path to yaml config
    :param config: Client config dict
    :param is_number: Specify if the variable is a number
    :param default: Default value
    """
    if config is None:
        config = {}

    if os.getenv(env_var) is not None:
        result = os.getenv(env_var)
    elif yaml_path is not None:
        result = config
        for path in yaml_path:
            result = result.get(path)
            if result is None:
                return default
    else:
        return default

    if isinstance(result, str):
        if len(result) == 0:
            return default

        lowered = result.lower()
        if lowered in ["yes", "true"]:
            return True
        if lowered in ["no", "false"]:
            return False

    if is_number:
        return int(result)

    return result


def create_ssl_context() -> ssl.SSLContext:
    """Set strong SSL defaults, requires TLSv1.2+
    `ssl` uses bitwise operations to specify context `<enum 'Options'>`
    """
    ssl_context_options: List[int] = [
        ssl.OP_NO_COMPRESSION,
        ssl.OP_NO_TICKET,  # pylint: disable=no-member
        ssl.OP_NO_RENEGOTIATION,  # pylint: disable=no-member
        ssl.OP_SINGLE_DH_USE,
        ssl.OP_SINGLE_ECDH_USE,
    ]
    ssl_context = ssl.create_default_context()
    ssl_context.options &= ~ssl.OP_ENABLE_MIDDLEBOX_COMPAT
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    for option in ssl_context_options:
        ssl_context.options |= option

    return ssl_context


def read_yaml_config(path: str) -> Optional[Dict[str, Any]]:
    """Find the `config.yml` file within the hierarchy of `path`
    :param path: Arbitrary path, use __file__ or relative ./config.yml
    :return: The loaded YAML or None
    """
    config_name = "config.yml"
    base_path = Path(path).absolute()

    # Passed an explicit path
    if base_path.name == config_name:
        if not base_path.exists():
            log.warning("Config path does not exist: %s", base_path)
            return None
        elif not base_path.is_file():
            log.warning("Config path is not a file: %s", base_path)
            return None
        else:
            return yaml.load(base_path.open(), Loader=yaml.SafeLoader)

    # Arbitrarily check 3 nodes deep, safer than `while True`
    for _ in range(3):
        config_path = base_path.joinpath(config_name)
        if config_path.exists() and config_path.is_file():
            return yaml.load(config_path.open(), Loader=yaml.SafeLoader)

        if not config_path.parents:
            break

        base_path = base_path.parent

    log.warning(f"Could not find '{config_name}' in hierarchy of {path}")
    return None


class ListenQueue(threading.Thread):
    """Main class for the ListenQueue used in OpenCTIConnectorHelper"""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: Dict[str, Any],
        callback: Callable[[Dict[str, Any]], None],
    ) -> None:
        """
        Create a new ListenQueue object
        :param helper: OpenCTI connector helper
        :param config: Client configuration
        :param callback: Callable for processing queue messages
        """
        super().__init__()
        self.pika_credentials = None
        self.pika_parameters = None
        self.pika_connection = None
        self.channel = None
        self.helper = helper
        self.callback = callback
        self.host = config["connection"]["host"]
        self.vhost = config["connection"]["vhost"]
        self.use_ssl = config["connection"]["use_ssl"]
        self.port = config["connection"]["port"]
        self.user = config["connection"]["user"]
        self.password = config["connection"]["pass"]
        self.queue_name = config["listen"]
        self.exit_event = threading.Event()
        self.thread = None

    def _process_message(
        self,
        channel: pika.adapters.blocking_connection.BlockingChannel,
        method: pika.spec.Basic.Deliver,
        _properties: pika.spec.BasicProperties,
        body: bytes,
    ) -> None:
        """Process a message from the queue
        :param channel: Active message channel
        :param method: Message delivery spec
        :param _properties: Message properties spec
        :param body: message body (data)
        """
        json_data = json.loads(body)
        channel.basic_ack(delivery_tag=method.delivery_tag)
        self.thread = threading.Thread(target=self._data_handler, args=[json_data])
        self.thread.start()
        five_minutes = 60 * 5
        time_wait = 0
        while self.thread.is_alive():  # Loop while the thread is processing
            if (
                self.helper.work_id is not None and time_wait > five_minutes
            ):  # Ping every 5 minutes
                self.helper.api.work.ping(self.helper.work_id)
                time_wait = 0
            else:
                time_wait += 1
            time.sleep(1)

        log.info(
            "Message (delivery_tag=%s) processed, thread terminated",
            method.delivery_tag,
        )

    def _data_handler(self, json_data) -> None:
        # Set the API headers
        work_id = json_data["internal"]["work_id"]
        applicant_id = json_data["internal"]["applicant_id"]
        self.helper.work_id = work_id
        if applicant_id is not None:
            self.helper.applicant_id = applicant_id
            self.helper.api.set_applicant_id_header(applicant_id)
        # Execute the callback
        try:
            self.helper.api.work.to_received(
                work_id, "Connector ready to process the operation"
            )
            message = self.callback(json_data["event"])
            self.helper.api.work.to_processed(work_id, message)
        except Exception as e:  # pylint: disable=broad-except
            logging.exception("Error in message processing, reporting error to API")
            try:
                self.helper.api.work.to_processed(work_id, str(e), True)
            except:  # pylint: disable=bare-except
                logging.error("Failing reporting the processing")

    def run(self) -> None:
        while not self.exit_event.is_set():
            try:
                # Connect the broker
                self.pika_credentials = pika.PlainCredentials(self.user, self.password)
                self.pika_parameters = pika.ConnectionParameters(
                    host=self.host,
                    port=self.port,
                    virtual_host=self.vhost,
                    credentials=self.pika_credentials,
                    ssl_options=pika.SSLOptions(create_ssl_context(), self.host)
                    if self.use_ssl
                    else None,
                )
                self.pika_connection = pika.BlockingConnection(self.pika_parameters)
                self.channel = self.pika_connection.channel()
                assert self.channel is not None
                self.channel.basic_consume(
                    queue=self.queue_name, on_message_callback=self._process_message
                )
                self.channel.start_consuming()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                sys.exit(0)
            except Exception as e:  # pylint: disable=broad-except
                self.helper.log_error(str(e))
                time.sleep(10)

    def stop(self):
        self.exit_event.set()
        if self.thread:
            self.thread.join()


class PingAlive(threading.Thread):
    def __init__(self, connector_id, api, get_state, set_state) -> None:
        super().__init__()
        self.connector_id = connector_id
        self.in_error = False
        self.api = api
        self.get_state = get_state
        self.set_state = set_state
        self.exit_event = threading.Event()

    def ping(self) -> None:
        while not self.exit_event.is_set():
            try:
                initial_state = self.get_state()
                result = self.api.connector.ping(self.connector_id, initial_state)
                remote_state = (
                    json.loads(result["connector_state"])
                    if result["connector_state"] is not None
                    and len(result["connector_state"]) > 0
                    else None
                )
                if initial_state != remote_state:
                    self.set_state(result["connector_state"])
                    logging.info(
                        "%s",
                        (
                            "Connector state has been remotely reset to: "
                            f'"{self.get_state()}"'
                        ),
                    )
                if self.in_error:
                    self.in_error = False
                    logging.error("API Ping back to normal")
            except Exception:  # pylint: disable=broad-except
                self.in_error = True
                logging.error("Error pinging the API")
            self.exit_event.wait(40)

    def run(self) -> None:
        logging.info("Starting ping alive thread")
        self.ping()

    def stop(self) -> None:
        logging.info("Preparing for clean shutdown")
        self.exit_event.set()


class ListenStream(threading.Thread):
    def __init__(
        self,
        helper,
        callback,
        url,
        token,
        verify_ssl,
        start_timestamp,
        live_stream_id,
        listen_delete,
        no_dependencies,
        recover_iso_date,
        with_inferences,
    ) -> None:
        super().__init__()
        self.helper = helper
        self.callback = callback
        self.url = url
        self.token = token
        self.verify_ssl = verify_ssl
        self.start_timestamp = start_timestamp
        self.live_stream_id = live_stream_id
        self.listen_delete = listen_delete if listen_delete is not None else True
        self.no_dependencies = no_dependencies if no_dependencies is not None else False
        self.recover_iso_date = recover_iso_date
        self.with_inferences = with_inferences if with_inferences is not None else False
        self.exit_event = threading.Event()

    def run(self) -> None:  # pylint: disable=too-many-branches
        try:
            current_state = self.helper.get_state()
            if current_state is None:
                current_state = {
                    "connectorStartTime": self.helper.date_now_z(),
                    "connectorLastEventId": f"{self.start_timestamp}-0"
                    if self.start_timestamp is not None
                    and len(self.start_timestamp) > 0
                    else "-",
                }
                self.helper.set_state(current_state)

            # If URL and token are provided, likely consuming a remote stream
            if self.url is not None and self.token is not None:
                # If a live stream ID, appending the URL
                if self.live_stream_id is not None:
                    live_stream_uri = f"/{self.live_stream_id}"
                elif self.helper.connect_live_stream_id is not None:
                    live_stream_uri = f"/{self.helper.connect_live_stream_id}"
                else:
                    live_stream_uri = ""
                # Live stream "from" should be empty if start from the beginning
                if (
                    self.live_stream_id is not None
                    or self.helper.connect_live_stream_id is not None
                ):

                    live_stream_from = (
                        f"?from={current_state['connectorLastEventId']}"
                        if "connectorLastEventId" in current_state
                        and current_state["connectorLastEventId"] != "-"
                        else "?from=0-0&recover="
                        + (
                            current_state["connectorStartTime"]
                            if self.recover_iso_date is None
                            else self.recover_iso_date
                        )
                    )
                # Global stream "from" should be 0 if starting from the beginning
                else:
                    live_stream_from = "?from=" + (
                        current_state["connectorLastEventId"]
                        if "connectorLastEventId" in current_state
                        and current_state["connectorLastEventId"] != "-"
                        else "0-0"
                    )
                live_stream_url = (
                    f"{self.url}/stream{live_stream_uri}{live_stream_from}"
                )
                opencti_ssl_verify = (
                    self.verify_ssl if self.verify_ssl is not None else True
                )
                logging.info(
                    "%s",
                    (
                        "Starting listening stream events (URL: "
                        f"{live_stream_url}, SSL verify: {opencti_ssl_verify}, Listen Delete: {self.listen_delete})"
                    ),
                )
                messages = SSEClient(
                    live_stream_url,
                    headers={
                        "authorization": "Bearer " + self.token,
                        "listen-delete": "false"
                        if self.listen_delete is False
                        else "true",
                        "no-dependencies": "true"
                        if self.no_dependencies is True
                        else "false",
                        "with-inferences": "true"
                        if self.helper.connect_live_stream_with_inferences is True
                        else "false",
                    },
                    verify=opencti_ssl_verify,
                )
            else:
                live_stream_uri = (
                    f"/{self.helper.connect_live_stream_id}"
                    if self.helper.connect_live_stream_id is not None
                    else ""
                )
                if self.helper.connect_live_stream_id is not None:
                    live_stream_from = (
                        f"?from={current_state['connectorLastEventId']}"
                        if "connectorLastEventId" in current_state
                        and current_state["connectorLastEventId"] != "-"
                        else "?from=0-0&recover="
                        + (
                            self.helper.date_now_z()
                            if self.recover_iso_date is None
                            else self.recover_iso_date
                        )
                    )
                # Global stream "from" should be 0 if starting from the beginning
                else:
                    live_stream_from = "?from=" + (
                        current_state["connectorLastEventId"]
                        if "connectorLastEventId" in current_state
                        and current_state["connectorLastEventId"] != "-"
                        else "0-0"
                    )
                live_stream_url = f"{self.helper.opencti_url}/stream{live_stream_uri}{live_stream_from}"
                logging.info(
                    "%s",
                    (
                        f"Starting listening stream events (URL: {live_stream_url}"
                        f", SSL verify: {self.helper.opencti_ssl_verify}, Listen Delete: {self.helper.connect_live_stream_listen_delete}, No Dependencies: {self.helper.connect_live_stream_no_dependencies})"
                    ),
                )
                messages = SSEClient(
                    live_stream_url,
                    headers={
                        "authorization": "Bearer " + self.helper.opencti_token,
                        "listen-delete": "false"
                        if self.helper.connect_live_stream_listen_delete is False
                        else "true",
                        "no-dependencies": "true"
                        if self.helper.connect_live_stream_no_dependencies is True
                        else "false",
                        "with-inferences": "true"
                        if self.helper.connect_live_stream_with_inferences is True
                        else "false",
                    },
                    verify=self.helper.opencti_ssl_verify,
                )
            # Iter on stream messages
            for msg in messages:
                if self.exit_event.is_set():
                    break
                if msg.event == "heartbeat" or msg.event == "connected":
                    continue
                if msg.event == "sync":
                    if msg.id is not None:
                        state = self.helper.get_state()
                        state["connectorLastEventId"] = str(msg.id)
                        self.helper.set_state(state)
                else:
                    self.callback(msg)
                    if msg.id is not None:
                        state = self.helper.get_state()
                        state["connectorLastEventId"] = str(msg.id)
                        self.helper.set_state(state)
        except:
            sys.excepthook(*sys.exc_info())

    def stop(self):
        self.exit_event.set()


class ConnectorLoop(threading.Thread):
    """Helper that reduces external-import boilerplate for looping and state management"""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        callback: Callable[[str], None],
        stop_on_error: bool = False,
    ) -> None:
        """
        Create a new ListenQueue object
        :param helper: OpenCTI connector helper
        :param callback: callback(work_id), executed after the interval has elapsed
        :param stop_on_error: Stop looping when an unhandled exception is thrown
        """
        super().__init__()
        self._helper = helper
        self._callback = callback
        self._stop_on_error = stop_on_error
        self._exit_event = threading.Event()

    def run(self) -> None:
        """Run the connector loop.
        :return: None
        """
        log.info("Starting connector loop")

        while True:
            try:
                self._run_loop()
            except KeyboardInterrupt:
                log.info("Connector stop (interrupt)")
                break
            except SystemExit:
                log.info("Connector stop (exit)")
                break
            except Exception as ex:
                log.exception("Unhandled exception in connector loop: %s", ex)
                if self._stop_on_error:
                    break

            if self._helper.connect_run_and_terminate:
                log.info("Connector stop (run-once)")
                break

            if self._exit_event.is_set():
                log.info("Connector stop (event)")
                break

            time.sleep(self._helper.loop_interval)

        # Ensure the state is pushed
        self._helper.force_ping()

    def _run_loop(self) -> None:
        """The looping portion of the connector loop.
        :return: None
        """
        # Get the current timestamp and check
        state = self._helper.get_state() or {}

        now = datetime.utcnow().replace(microsecond=0)
        last_run = state.get("last_run", 0)
        last_run = datetime.utcfromtimestamp(last_run).replace(microsecond=0)

        if last_run.year == 1970:
            log.info("Connector has never run")
        else:
            log.info(f"Connector last run: {last_run}")

        # Check the difference between now and the last run to the interval
        if (now - last_run).total_seconds() > self._helper.interval:
            log.info("Connector will now run")
            last_run = now

            name = self._helper.connect_name or "Connector"
            work_id = self._helper.api.work.initiate_work(
                self._helper.connect_id,
                f"{name} run @ {now}",
            )

            try:
                self._callback(work_id)
            except Exception as ex:
                log.exception(f"Unhandled exception processing connector feed: %s", ex)
                self._helper.api.work.to_processed(work_id, "Failed", in_error=True)
            else:
                log.info("Connector successfully run")
                self._helper.api.work.to_processed(work_id, "Complete")

            # Get the state again, incase it changed in the callback
            state = self._helper.get_state() or {}

            # Store the start time as the last run
            state["last_run"] = int(now.timestamp())
            self._helper.set_state(state)

            next_run = last_run + timedelta(seconds=self._helper.interval)
            log.info(f"Last_run stored, next run at %s", next_run)
        else:
            next_run = last_run + timedelta(seconds=self._helper.interval)
            log.info(f"Connector will not run, next run at %s", next_run)

    def stop(self) -> None:
        """Stop the thread
        :return: None
        """
        self._exit_event.set()


class OpenCTIConnectorHelper:
    """Python API for OpenCTI connector"""

    def __init__(self, config: Dict[str, Any]) -> None:
        """Initialize an OpenCTIConnectorHelper
        :param config: Configuration dictionary
        """

        # Load API config
        self.opencti_url = get_config_variable(
            "OPENCTI_URL",
            ["opencti", "url"],
            config,
        )  # type: Optional[str]
        self.opencti_token = get_config_variable(
            "OPENCTI_TOKEN",
            ["opencti", "token"],
            config,
        )  # type: Optional[str]
        self.opencti_ssl_verify = get_config_variable(
            "OPENCTI_SSL_VERIFY",
            ["opencti", "ssl_verify"],
            config,
            default=True,
        )  # type: bool
        self.opencti_json_logging = get_config_variable(
            "OPENCTI_JSON_LOGGING",
            ["opencti", "json_logging"],
            config,
            default=False,
        )  # type: bool

        # Load connector config
        self.connect_id = get_config_variable(
            "CONNECTOR_ID",
            ["connector", "id"],
            config,
        )  # type: Optional[str]
        self.connect_type = get_config_variable(
            "CONNECTOR_TYPE",
            ["connector", "type"],
            config,
        )  # type: Optional[str]
        self.connect_name = get_config_variable(
            "CONNECTOR_NAME",
            ["connector", "name"],
            config,
        )  # type: Optional[str]
        self.connect_scope = get_config_variable(
            "CONNECTOR_SCOPE",
            ["connector", "scope"],
            config,
        )  # type: Optional[str]
        self.connect_auto = get_config_variable(
            "CONNECTOR_AUTO",
            ["connector", "auto"],
            config,
            default=False,
        )  # type: bool
        self.connect_only_contextual = get_config_variable(
            "CONNECTOR_ONLY_CONTEXTUAL",
            ["connector", "only_contextual"],
            config,
            default=False,
        )  # type: bool

        # ConnectorLoop config
        self.interval = get_config_variable(
            "CONNECTOR_INTERVAL",
            ["connector", "interval"],
            is_number=True,
            default=60 * 60 * 24,  # 1 day
        )  # type: int
        self.loop_interval = get_config_variable(
            "CONNECTOR_LOOP_INTERVAL",
            ["connector", "loop_interval"],
            is_number=True,
            default=60,  # 1 min
        )  # type: int

        # ListenStream config
        self.connect_live_stream_id = get_config_variable(
            "CONNECTOR_LIVE_STREAM_ID",
            ["connector", "live_stream_id"],
            config,
        )  # type: Optional[str]
        self.connect_live_stream_listen_delete = get_config_variable(
            "CONNECTOR_LIVE_STREAM_LISTEN_DELETE",
            ["connector", "live_stream_listen_delete"],
            config,
            default=True,
        )  # type: bool
        self.connect_live_stream_no_dependencies = get_config_variable(
            "CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES",
            ["connector", "live_stream_no_dependencies"],
            config,
            default=False,
        )  # type: bool
        self.connect_live_stream_with_inferences = get_config_variable(
            "CONNECTOR_LIVE_STREAM_WITH_INFERENCES",
            ["connector", "live_stream_with_inferences"],
            config,
            default=False,
        )  # type: bool

        # Generic config
        self.connect_confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            config,
            is_number=True,
        )  # type: int
        self.log_level = get_config_variable(
            "CONNECTOR_LOG_LEVEL",
            ["connector", "log_level"],
            config,
            default="INFO",
        )  # type: Optional[str]
        self.connect_run_and_terminate = get_config_variable(
            "CONNECTOR_RUN_AND_TERMINATE",
            ["connector", "run_and_terminate"],
            config,
            default=False,
        )  # type: bool
        self.connect_validate_before_import = get_config_variable(
            "CONNECTOR_VALIDATE_BEFORE_IMPORT",
            ["connector", "validate_before_import"],
            config,
            default=False,
        )  # type: bool

        # Configure logger
        numeric_level = getattr(logging, self.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {self.log_level}")
        logging.basicConfig(level=numeric_level)

        # Initialize configuration
        self.api = OpenCTIApiClient(
            self.opencti_url,
            self.opencti_token,
            self.log_level,
            json_logging=self.opencti_json_logging,
        )

        # Register the connector in OpenCTI
        self.connector = OpenCTIConnector(
            self.connect_id,
            self.connect_name,
            self.connect_type,
            self.connect_scope,
            self.connect_auto,
            self.connect_only_contextual,
        )

        connector_configuration = self.api.connector.register(self.connector)
        logging.info("%s", f"Connector registered with ID: {self.connect_id}")
        self.connector_id = connector_configuration["id"]
        self.work_id = None
        self.applicant_id = connector_configuration["connector_user"]["id"]
        self.connector_state = connector_configuration["connector_state"]
        self.connector_config = connector_configuration["config"]

        # Shutdown on SIGTERM
        signal.signal(signal.SIGTERM, self._sigterm_handler)

        # Start ping thread
        if not self.connect_run_and_terminate:
            self.ping = PingAlive(
                self.connector.id, self.api, self.get_state, self.set_state
            )
            self.ping.start()

        self.connector_loop: Optional[ConnectorLoop] = None
        self.listen_queue: Optional[ListenQueue] = None
        self.listen_stream: Optional[ListenStream] = None

    def stop(self) -> None:
        if self.connector_loop:
            self.connector_loop.stop()
        if self.listen_queue:
            self.listen_queue.stop()
        if self.listen_stream:
            self.listen_stream.stop()
        self.ping.stop()
        self.api.connector.unregister(self.connector_id)

    def get_name(self) -> Optional[Union[bool, int, str]]:
        return self.connect_name

    def get_only_contextual(self) -> Optional[Union[bool, int, str]]:
        return self.connect_only_contextual

    def get_run_and_terminate(self) -> Optional[Union[bool, int, str]]:
        return self.connect_run_and_terminate

    def get_validate_before_import(self) -> Optional[Union[bool, int, str]]:
        return self.connect_validate_before_import

    def set_state(self, state: Dict[str, Any]) -> None:
        """Set the connector state
        :param state: State object
        :return: None
        """
        self.connector_state = json.dumps(state)

    def get_state(self) -> Optional[Dict[str, Any]]:
        """Get the connector state
        :return: The current state of the connector or None
        """
        if not self.connector_state:
            return None

        try:
            state = json.loads(self.connector_state)
        except (TypeError, ValueError):
            log.exception("Invalid state: %s", self.connector_state)
            return None

        if state is None or isinstance(state, dict):
            return state
        else:
            log.exception("Invalid state type: %s", self.connector_state)
            return None

    def force_ping(self):
        try:
            initial_state = self.get_state()
            result = self.api.connector.ping(self.connector_id, initial_state)
            remote_state = (
                json.loads(result["connector_state"])
                if result["connector_state"] is not None
                and len(result["connector_state"]) > 0
                else None
            )
            if initial_state != remote_state:
                self.api.connector.ping(self.connector_id, initial_state)
        except Exception as ex:
            log.exception("Error pinging the API: %s", ex)

    def run_loop(
        self,
        callback: Callable[[str], None],
    ) -> None:
        """Run a loop, executing the callback after the interval has elapsed
        :param callback: callback(work_id), executed after the interval has elapsed
        """
        self.connector_loop = ConnectorLoop(self, callback)
        self.connector_loop.start()

    def listen(
        self,
        message_callback: Callable[[Dict[str, Any]], None],
    ) -> None:
        """listen for messages and register callback function
        :param message_callback: Callback function to process messages
        """
        self.listen_queue = ListenQueue(self, self.connector_config, message_callback)
        self.listen_queue.start()

    def listen_stream(
        self,
        message_callback: Callable[[Dict[str, Any]], None],
        url: str = None,
        token: str = None,
        verify_ssl=None,
        start_timestamp=None,
        live_stream_id=None,
        listen_delete=True,
        no_dependencies=False,
        recover_iso_date=None,
        with_inferences=False,
    ) -> ListenStream:
        """listen for messages and register callback function

        :param message_callback: callback function to process messages
        """
        self.listen_stream = ListenStream(
            self,
            message_callback,
            url,
            token,
            verify_ssl,
            start_timestamp,
            live_stream_id,
            listen_delete,
            no_dependencies,
            recover_iso_date,
            with_inferences,
        )
        self.listen_stream.start()
        return self.listen_stream

    def _sigterm_handler(self, _signum: int, _frame: Optional[FrameType]) -> None:
        """SIGTERM handler for when listen() has been called.
        :param _signum: Signal number
        :param _frame: Stack frame
        :return: None
        """
        log.info("Received SIGTERM, stopping threads")
        self.stop()

    def get_opencti_url(self) -> Optional[Union[bool, int, str]]:
        return self.opencti_url

    def get_opencti_token(self) -> Optional[Union[bool, int, str]]:
        return self.opencti_token

    def get_connector(self) -> OpenCTIConnector:
        return self.connector

    def log_error(self, msg: str) -> None:
        logging.error(msg)

    def log_info(self, msg: str) -> None:
        logging.info(msg)

    def log_debug(self, msg: str) -> None:
        logging.debug(msg)

    def log_warning(self, msg: str) -> None:
        logging.warning(msg)

    def date_now(self) -> str:
        """Get the current date (UTC)
        :return: The current datetime for UTC
        """
        return datetime.utcnow().replace(microsecond=0, tzinfo=timezone.utc).isoformat()

    def date_now_z(self) -> str:
        """Get the current date (UTC) in "...+00:00Z" format
        :return: The current datetime for UTC
        """
        return (
            datetime.utcnow()
            .replace(microsecond=0, tzinfo=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    # Push Stix2 helper
    def send_stix2_bundle(self, bundle, **kwargs) -> list:
        """Send a stix2 bundle to the API
        :param work_id: a valid work id
        :param bundle: valid stix2 bundle
        :type bundle:
        :param entities_types: list of entities, defaults to None
        :type entities_types: list, optional
        :param update: whether to updated data in the database, defaults to False
        :type update: bool, optional
        :raises ValueError: if the bundle is empty
        :return: list of bundles
        :rtype: list
        """
        work_id = kwargs.get("work_id", self.work_id)
        entities_types = kwargs.get("entities_types", None)
        update = kwargs.get("update", False)
        event_version = kwargs.get("event_version", None)
        bypass_split = kwargs.get("bypass_split", False)
        bypass_validation = kwargs.get("bypass_validation", False)
        entity_id = kwargs.get("entity_id", None)
        file_name = kwargs.get("file_name", None)

        if not file_name and work_id:
            file_name = f"{work_id}.json"

        if self.connect_validate_before_import and not bypass_validation and file_name:
            self.api.upload_pending_file(
                file_name=file_name,
                data=bundle,
                mime_type="application/json",
                entity_id=entity_id,
            )
            return []

        if entities_types is None:
            entities_types = []

        if bypass_split:
            bundles = [bundle]
        else:
            stix2_splitter = OpenCTIStix2Splitter()
            bundles = stix2_splitter.split_bundle(bundle, True, event_version)

        if len(bundles) == 0:
            raise ValueError("Nothing to import")

        if work_id:
            self.api.work.add_expectations(work_id, len(bundles))

        pika_credentials = pika.PlainCredentials(
            self.connector_config["connection"]["user"],
            self.connector_config["connection"]["pass"],
        )
        pika_parameters = pika.ConnectionParameters(
            host=self.connector_config["connection"]["host"],
            port=self.connector_config["connection"]["port"],
            virtual_host=self.connector_config["connection"]["vhost"],
            credentials=pika_credentials,
            ssl_options=pika.SSLOptions(
                create_ssl_context(), self.connector_config["connection"]["host"]
            )
            if self.connector_config["connection"]["use_ssl"]
            else None,
        )

        pika_connection = pika.BlockingConnection(pika_parameters)
        channel = pika_connection.channel()
        for sequence, bundle in enumerate(bundles, start=1):
            self._send_bundle(
                channel,
                bundle,
                work_id=work_id,
                entities_types=entities_types,
                sequence=sequence,
                update=update,
            )
        channel.close()
        return bundles

    def _send_bundle(self, channel, bundle, **kwargs) -> None:
        """send a STIX2 bundle to RabbitMQ to be consumed by workers

        :param channel: RabbitMQ channel
        :type channel: callable
        :param bundle: valid stix2 bundle
        :type bundle:
        :param entities_types: list of entity types, defaults to None
        :type entities_types: list, optional
        :param update: whether to update data in the database, defaults to False
        :type update: bool, optional
        """
        work_id = kwargs.get("work_id", None)
        sequence = kwargs.get("sequence", 0)
        update = kwargs.get("update", False)
        entities_types = kwargs.get("entities_types", None)

        if entities_types is None:
            entities_types = []

        # Validate the STIX 2 bundle
        # validation = validate_string(bundle)
        # if not validation.is_valid:
        # raise ValueError('The bundle is not a valid STIX2 JSON')

        # Prepare the message
        # if self.current_work_id is None:
        #    raise ValueError('The job id must be specified')
        message = {
            "applicant_id": self.applicant_id,
            "action_sequence": sequence,
            "entities_types": entities_types,
            "content": base64.b64encode(bundle.encode("utf-8")).decode("utf-8"),
            "update": update,
        }
        if work_id is not None:
            message["work_id"] = work_id

        # Send the message
        try:
            routing_key = "push_routing_" + self.connector_id
            channel.basic_publish(
                exchange=self.connector_config["push_exchange"],
                routing_key=routing_key,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                ),
            )
        except (UnroutableError, NackError) as e:
            logging.error("Unable to send bundle, retry...%s", e)
            self._send_bundle(channel, bundle, **kwargs)

    def stix2_get_embedded_objects(self, item) -> Dict:
        """gets created and marking refs for a stix2 item

        :param item: valid stix2 item
        :type item:
        :return: returns a dict of created_by of object_marking_refs
        :rtype: Dict
        """
        # Marking definitions
        object_marking_refs = []
        if "object_marking_refs" in item:
            for object_marking_ref in item["object_marking_refs"]:
                if object_marking_ref in self.cache_index:
                    object_marking_refs.append(self.cache_index[object_marking_ref])
        # Created by ref
        created_by_ref = None
        if "created_by_ref" in item and item["created_by_ref"] in self.cache_index:
            created_by_ref = self.cache_index[item["created_by_ref"]]

        return {
            "object_marking_refs": object_marking_refs,
            "created_by_ref": created_by_ref,
        }

    def stix2_get_entity_objects(self, entity) -> list:
        """process a stix2 entity

        :param entity: valid stix2 entity
        :type entity:
        :return: entity objects as list
        :rtype: list
        """

        items = [entity]
        # Get embedded objects
        embedded_objects = self.stix2_get_embedded_objects(entity)
        # Add created by ref
        if embedded_objects["created_by_ref"] is not None:
            items.append(embedded_objects["created_by_ref"])
        # Add marking definitions
        if len(embedded_objects["object_marking_refs"]) > 0:
            items = items + embedded_objects["object_marking_refs"]

        return items

    def stix2_get_relationship_objects(self, relationship) -> list:
        """get a list of relations for a stix2 relationship object

        :param relationship: valid stix2 relationship
        :type relationship:
        :return: list of relations objects
        :rtype: list
        """

        items = [relationship]
        # Get source ref
        if relationship["source_ref"] in self.cache_index:
            items.append(self.cache_index[relationship["source_ref"]])

        # Get target ref
        if relationship["target_ref"] in self.cache_index:
            items.append(self.cache_index[relationship["target_ref"]])

        # Get embedded objects
        embedded_objects = self.stix2_get_embedded_objects(relationship)
        # Add created by ref
        if embedded_objects["created_by"] is not None:
            items.append(embedded_objects["created_by"])
        # Add marking definitions
        if len(embedded_objects["object_marking_refs"]) > 0:
            items = items + embedded_objects["object_marking_refs"]

        return items

    def stix2_get_report_objects(self, report) -> list:
        """get a list of items for a stix2 report object

        :param report: valid stix2 report object
        :type report:
        :return: list of items for a stix2 report object
        :rtype: list
        """

        items = [report]
        # Add all object refs
        for object_ref in report["object_refs"]:
            items.append(self.cache_index[object_ref])
        for item in items:
            if item["type"] == "relationship":
                items = items + self.stix2_get_relationship_objects(item)
            else:
                items = items + self.stix2_get_entity_objects(item)
        return items

    @staticmethod
    def stix2_deduplicate_objects(items) -> list:
        """deduplicate stix2 items

        :param items: valid stix2 items
        :type items:
        :return: de-duplicated list of items
        :rtype: list
        """

        ids = []
        final_items = []
        for item in items:
            if item["id"] not in ids:
                final_items.append(item)
                ids.append(item["id"])
        return final_items

    @staticmethod
    def stix2_create_bundle(items: List[Any]) -> str:
        """create a stix2 bundle with items

        :param items: valid stix2 items
        :return: JSON of the stix2 bundle
        """
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": items,
        }
        return json.dumps(bundle)

    @staticmethod
    def check_max_tlp(tlp: str, max_tlp: str) -> bool:
        """Check the allowed TLP levels for a TLP string
        :param tlp: TLP level to check
        :param max_tlp: The highest allowed TLP level
        :return: True if the TLP is in the allowed TLPs
        """
        allowed_tlps: Dict[str, List[str]] = {
            "TLP:RED": ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"],
            "TLP:AMBER": ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER"],
            "TLP:GREEN": ["TLP:WHITE", "TLP:GREEN"],
            "TLP:WHITE": ["TLP:WHITE"],
        }

        return tlp in allowed_tlps[max_tlp]

    @staticmethod
    def get_attribute_in_extension(
        key,
        obj: Mapping[str, Any],
    ) -> Optional[Any]:
        """
        Try to get data from the EXT_OCTI or EXT_OCTI_SCO extensions.
        :param key: Key within the extension.
        :param obj: Data object.
        :return: Extension key data, or None.
        """
        extensions = obj.get("extensions")
        if extensions is None:
            return None

        value = extensions.get(STIX_EXT_OCTI, {}).get(key)
        if value is not None:
            return value

        value = extensions.get(STIX_EXT_OCTI_SCO, {}).get(key)
        if value is not None:
            return value

        return None

    @staticmethod
    def get_attribute_in_mitre_extension(
        key: str,
        obj: Mapping[str, Any],
    ) -> Optional[Any]:
        """
        Try to get data from the EXT_MITRE extension.
        :param key: Key within the extension.
        :param obj: Data object.
        :return: Extension key data, or None.
        """
        extensions = obj.get("extensions")
        if extensions is None:
            return None

        value = extensions.get(STIX_EXT_MITRE, {}).get(key)
        if value is not None:
            return value

        return None
