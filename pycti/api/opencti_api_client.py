"""OpenCTI main API"""

from __future__ import annotations

import base64
import io
import json
import logging
import warnings
from datetime import date, datetime
from typing import (
    Any,
    BinaryIO,
    Dict,
    List,
    NamedTuple,
    Optional,
    Tuple,
    TypedDict,
    Union,
)

import magic
import requests
import urllib3.exceptions
from pythonjsonlogger import jsonlogger

from ..api.opencti_api_connector import OpenCTIApiConnector
from ..api.opencti_api_work import OpenCTIApiWork
from ..entities.opencti_attack_pattern import AttackPattern
from ..entities.opencti_campaign import Campaign
from ..entities.opencti_course_of_action import CourseOfAction
from ..entities.opencti_external_reference import ExternalReference
from ..entities.opencti_identity import Identity
from ..entities.opencti_incident import Incident
from ..entities.opencti_indicator import Indicator
from ..entities.opencti_infrastructure import Infrastructure
from ..entities.opencti_intrusion_set import IntrusionSet
from ..entities.opencti_kill_chain_phase import KillChainPhase
from ..entities.opencti_label import Label
from ..entities.opencti_location import Location
from ..entities.opencti_malware import Malware
from ..entities.opencti_marking_definition import MarkingDefinition
from ..entities.opencti_note import Note
from ..entities.opencti_observed_data import ObservedData
from ..entities.opencti_opinion import Opinion
from ..entities.opencti_report import Report
from ..entities.opencti_stix import Stix
from ..entities.opencti_stix_core_object import StixCoreObject
from ..entities.opencti_stix_core_relationship import StixCoreRelationship
from ..entities.opencti_stix_cyber_observable import StixCyberObservable
from ..entities.opencti_stix_cyber_observable_relationship import (
    StixCyberObservableRelationship,
)
from ..entities.opencti_stix_domain_object import StixDomainObject
from ..entities.opencti_stix_object_or_stix_relationship import (
    StixObjectOrStixRelationship,
)
from ..entities.opencti_stix_sighting_relationship import StixSightingRelationship
from ..entities.opencti_threat_actor import ThreatActor
from ..entities.opencti_tool import Tool
from ..entities.opencti_vulnerability import Vulnerability
from ..utils.opencti_stix2 import OpenCTIStix2

__all__ = [
    "CustomJsonFormatter",
    "OpenCTIApiClient",
    "AnyDict",
    "ProxyDict",
    "ProcessedList",
    "ProcessedDict",
    "ProcessedResultsDict",
    "EmptyDict",
    "PageInfoDict",
    "MultipartFileDataDict",
    "LogsWorkerConfigDict",
    "File",
]

log = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
AnyDict = Dict[str, Any]

STIX_EXT_MITRE = "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"
STIX_EXT_OCTI = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
STIX_EXT_OCTI_SCO = "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """JSON logging formatter"""

    def add_fields(
        self,
        log_record: AnyDict,
        record: logging.LogRecord,
        message_dict: AnyDict,
    ) -> None:
        """Add additional fields to a JSON log record"""
        super().add_fields(log_record, record, message_dict)

        if not log_record.get("timestamp"):
            # This doesn't use record.created, so it is slightly off
            now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            log_record["timestamp"] = now

        if log_record.get("level"):
            log_record["level"] = log_record["level"].upper()
        else:
            log_record["level"] = record.levelname


class OpenCTIApiClient:
    """OpenCTI main API client"""

    def __init__(
        self,
        url: str,
        token: str,
        log_level: str = "info",
        ssl_verify: Union[str, bool] = False,
        proxies: ProxyDict = None,
        json_logging: bool = False,
    ):
        """
        Constructor
        :param url: OpenCTI API url
        :param token: OpenCTI API token
        :param log_level: log level for the client
        :param ssl_verify: Enable TLS certificate validation or the path to a CA bundle
        :param proxies: Dictionary mapping protocol to the proxy URL
        :param json_logging: Enable JSON log formatting
        """
        # Check configuration
        self._ssl_verify = ssl_verify
        self._proxies = proxies

        if url is None or len(url) == 0:
            raise ValueError("An URL must be set")

        if token is None or len(token) == 0 or token == "ChangeMe":
            raise ValueError("A TOKEN must be set")

        # Configure logger
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {log_level}")

        if json_logging:
            log_handler = logging.StreamHandler()
            log_handler.setLevel(log_level.upper())
            formatter = CustomJsonFormatter(
                "%(timestamp)s %(level)s %(name)s %(message)s"
            )
            log_handler.setFormatter(formatter)
            logging.basicConfig(level=numeric_level, handlers=[log_handler], force=True)
        else:
            logging.basicConfig(level=numeric_level)

        # Define API
        self.base_url = url
        self.api_url = f"{self.base_url}/graphql"
        self._headers = {"Authorization": f"Bearer {token}"}
        self._session = requests.session()

        # Define the dependencies
        self.work = OpenCTIApiWork(self)
        self.connector = OpenCTIApiConnector(self)
        self.stix2 = OpenCTIStix2(self)

        # Define the entities
        self.label = Label(self)
        self.marking_definition = MarkingDefinition(self)
        self.external_reference = ExternalReference(self, File)
        self.kill_chain_phase = KillChainPhase(self)
        self.opencti_stix_object_or_stix_relationship = StixObjectOrStixRelationship(
            self
        )
        self.stix = Stix(self)
        self.stix_domain_object = StixDomainObject(self, File)
        self.stix_core_object = StixCoreObject(self, File)
        self.stix_cyber_observable = StixCyberObservable(self, File)
        self.stix_core_relationship = StixCoreRelationship(self)
        self.stix_sighting_relationship = StixSightingRelationship(self)
        self.stix_cyber_observable_relationship = StixCyberObservableRelationship(self)
        self.identity = Identity(self)
        self.location = Location(self)
        self.threat_actor = ThreatActor(self)
        self.intrusion_set = IntrusionSet(self)
        self.infrastructure = Infrastructure(self)
        self.campaign = Campaign(self)
        self.incident = Incident(self)
        self.malware = Malware(self)
        self.tool = Tool(self)
        self.vulnerability = Vulnerability(self)
        self.attack_pattern = AttackPattern(self)
        self.course_of_action = CourseOfAction(self)
        self.report = Report(self)
        self.note = Note(self)
        self.observed_data = ObservedData(self)
        self.opinion = Opinion(self)
        self.indicator = Indicator(self)

        # Check if openCTI is available
        if not self.health_check():
            raise ValueError(
                "OpenCTI API is not reachable. "
                "Wait for the OpenCTI API to start or check your configuration"
            )

    def set_applicant_id_header(self, applicant_id: str) -> None:
        """
        Set the opencti-applicant-id header
        :param applicant_id: Header value
        :return: None
        """
        self._headers["opencti-applicant-id"] = applicant_id

    def set_retry_number(self, retry_number: Optional[int]) -> None:
        """
        Set the opencti-retry-number header
        :param retry_number: Retry count, or `None` to reset it
        :return: `None`
        """
        if retry_number is None:
            retry_number = ""

        self._headers["opencti-retry-number"] = str(retry_number)

    def query(self, query: str, variables: AnyDict = None) -> AnyDict:
        """
        Submit a query to the OpenCTI GraphQL API
        :param query: GraphQL query string
        :param variables: GraphQL query variables
        :return: The response JSON content
        """
        if variables is None:
            variables = {}

        query_var = {}
        files_vars = []

        # Implementation of spec https://github.com/jaydenseric/graphql-multipart-request-spec
        # Support for single or multiple upload
        # Batching or mixed upload or not supported
        for key, val in variables.items():
            is_file = isinstance(val, File)
            is_files = (
                isinstance(val, list)
                and len(val) > 0
                and all(isinstance(x, File) for x in val)
            )
            if is_file or is_files:
                file_var = MultipartFileDataDict(key=key, file=val, multiple=is_files)
                files_vars.append(file_var)
                query_var[key] = None if is_file else [None] * len(val)
            else:
                query_var[key] = val

        # If yes, transform variable (file to null) and create multipart query
        if len(files_vars) > 0:
            # Build the multipart map
            map_index = 0
            file_vars = {}
            for file_var in files_vars:
                var_key = file_var["key"]
                var_name = f"variables.{var_key}"
                is_multiple_files = file_var["multiple"]
                if is_multiple_files:
                    # [(var_name + "." + i)] if is_multiple_files else
                    for _ in file_var["file"]:
                        file_vars[str(map_index)] = [f"{var_name}.{map_index}"]
                        map_index += 1
                else:
                    file_vars[str(map_index)] = [var_name]
                    map_index += 1

            multipart_data = {
                "operations": json.dumps({"query": query, "variables": query_var}),
                "map": json.dumps(file_vars),
            }

            # Add the files
            file_index = 0
            multipart_files: List[Tuple[str, Tuple[str, BinaryIO, str]]] = []

            for file_var in files_vars:
                files = file_var["file"]
                is_multiple_files = file_var["multiple"]

                if not is_multiple_files:
                    files = [files]

                for file in files:  # type: File
                    if isinstance(file.data, str):
                        file.data = file.data.encode()

                    file_stream = io.BytesIO(file.data)
                    file_data = (file.name, file_stream, file.mime)
                    file_multi = (str(file_index), file_data)

                    multipart_files.append(file_multi)
                    file_index += 1

            # Send the multipart request
            resp = self._session.post(
                self.api_url,
                data=multipart_data,
                files=multipart_files,
                headers=self._headers,
                verify=self._ssl_verify,
                proxies=self._proxies,
            )

        # If no
        else:
            resp = self._session.post(
                self.api_url,
                json={"query": query, "variables": variables},
                headers=self._headers,
                verify=self._ssl_verify,
                proxies=self._proxies,
            )

        # Check for HTTP failures
        if resp.status_code != 200:
            log.error("GraphQL returned HTTP %d: %s", resp.status_code, resp.text)
            raise ValueError(
                {
                    "name": f"GraphQL HTTP {resp.status_code}",
                    "message": resp.text,
                }
            )

        result = resp.json()

        # Check for errors
        if "errors" in result:
            main_error = result["errors"][0]
            error_message = main_error["message"]

            # Use the message if the name is missing
            error_name = main_error.get("name", error_message)

            # Use the message if the reason is missing
            error_reason = main_error.get("data", {}).get("reason", error_message)

            log.error(error_reason)
            raise ValueError(
                {
                    "name": error_name,
                    "message": error_reason,
                }
            )

        return result

    def fetch_opencti_file(
        self,
        fetch_uri: str,
        binary: bool = False,
        serialize: bool = False,
    ) -> Union[str, bytes]:
        """
        Get a file from the OpenCTI API
        :param fetch_uri: The download URI to use
        :param binary: Fetch the contents as bytes
        :param serialize: Fetch the contents as UTF-8 encoded Base64
        :return: Either the file content as text or bytes based on `binary`
        """
        resp = self._session.get(fetch_uri, headers=self._headers)
        if binary:
            if serialize:
                return base64.b64encode(resp.content).decode("utf-8")
            else:
                return resp.content

        else:
            if serialize:
                text = resp.text.encode("utf-8")
                return base64.b64encode(text).decode("utf-8")
            else:
                return resp.text

    def log(self, level: str, message: str) -> None:
        """
        Log a message with defined log level
        :param level: A valid logging log level (debug, info, warning, error)
        :param message: The message to log
        :return: None
        """
        warnings.warn("Use logging.getLogger(__name__).<level>")

        if level == "debug":
            log.debug(message)
        elif level == "info":
            log.info(message)
        elif level == "warning":
            log.warning(message)
        elif level == "error":
            log.error(message)
        else:
            log.warning("Unknown log level: %s", level)

    def health_check(self) -> bool:
        """
        Submit an example request to the OpenCTI API.
        :return: `True` if the health check has been successful
        """
        try:
            test = self.threat_actor.list(first=1)
            return test is not None
        except Exception as ex:
            log.error("Health check failed", exc_info=ex)
            return False

    def get_logs_worker_config(self) -> LogsWorkerConfigDict:
        """
        Get the logsWorkerConfig
        return: The logsWorkerConfig
        """
        log.info("Getting logs worker config")
        query = """
            query LogsWorkerConfig {
                logsWorkerConfig {
                    elasticsearch_url
                    elasticsearch_proxy
                    elasticsearch_index
                    elasticsearch_username
                    elasticsearch_password
                    elasticsearch_api_key
                    elasticsearch_ssl_reject_unauthorized
                }
            }
        """
        result = self.query(query)
        return result["data"]["logsWorkerConfig"]

    def not_empty(
        self, value: Union[str, int, date, datetime, list, dict, None]
    ) -> bool:
        """
        Check if a value is empty for various types
        :param value: The value to check
        :return: `True` if the value is one of the supported types and not empty
        """
        if value is None:
            return False

        if isinstance(value, (bool, float, int, date, datetime)):
            return True

        if isinstance(value, (str, dict)):
            return bool(value)

        if isinstance(value, list):
            try:
                return any(map(self.not_empty, value))
            except RecursionError:
                log.warning("Recursion error checking not_empty")
                return True

        log.warning("Unsupported type for 'not_empty': %s", type(value).__name__)
        return False

    def process_multiple(
        self,
        data: AnyDict,
        with_pagination: bool = False,
    ) -> ProcessedResultsDict:
        """
        Processes data returned by the OpenCTI API with multiple entities
        :param data: Data to process
        :param with_pagination: Use pagination with the API
        :return: A dict if paginated otherwise a list with the processed entities
        """
        if with_pagination:
            return self.process_multiple_paginated(data)
        else:
            return self.process_multiple_flat(data)

    def process_multiple_flat(self, data: AnyDict) -> ProcessedList:
        """
        Processes data returned by the OpenCTI API with multiple entities
        :param data: Data to process
        :return: A list with the processed entities
        """
        result = []

        if data is None:
            return result

        for edge in data.get("edges", []):
            node = edge["node"]
            result.append(self.process_multiple_fields(node))

        return result

    def process_multiple_paginated(self, data: AnyDict) -> ProcessedDict:
        """
        Processes data returned by the OpenCTI API with multiple entities
        :param data: Data to process
        :return: A dict with the processed entities and pagination details
        """
        result = ProcessedDict(
            entities=[],
            pagination=EmptyDict(),
        )

        if data is None:
            return result

        for edge in data.get("edges", []):
            node = edge["node"]
            result["entities"].append(self.process_multiple_fields(node))

        if "pageInfo" in data:
            result["pagination"] = data["pageInfo"]

        return result

    def process_multiple_ids(self, data: Optional[List[AnyDict]]) -> List[str]:
        """
        Process data returned by the OpenCTI API with multiple IDs
        :param data: The data to process
        :return: A list of IDs
        """
        result = []

        if data is None:
            return result

        for entry in data:
            obj_id = entry.get("id")
            if obj_id is not None:
                result.append(obj_id)

        return result

    def process_multiple_fields(self, data: Optional[AnyDict]) -> Optional[AnyDict]:
        """
        Process data returned by the OpenCTI API with multiple fields
        :param data: data to process
        :return: The data dict with all fields processed
        """
        if data is None:
            return None

        created_by = data.get("createdBy")
        if created_by is not None:
            data["createdById"] = created_by["id"]

            object_marking = data.get("objectMarking")
            if object_marking is not None:
                created_by["objectMarking"] = self.process_multiple(object_marking)
                created_by["objectMarkingIds"] = self.process_multiple_ids(
                    object_marking
                )

            object_label = created_by.get("objectLabel")
            if object_label is not None:
                created_by["objectLabel"] = self.process_multiple(object_label)
                created_by["objectLabelIds"] = self.process_multiple_ids(object_label)

        else:
            data["createdById"] = None

        data_keys = [
            "objectMarking"
            "objectLabel"
            "reports"
            "notes"
            "opinions"
            "observedData"
            "killChainPhases"
            "externalReferences"
            "objects"
            "observables"
            "stixCoreRelationships"
            "indicators"
            "importFiles"
        ]

        for key in data_keys:
            value = data.get(key)
            if value is not None:
                data[key] = self.process_multiple(value)
                data[f"{key}Ids"] = self.process_multiple_ids(value)

        return data

    def upload_file(
        self,
        *,
        file_name: str,
        data: bytes = None,
        mime_type: str = "text/plain",
    ) -> AnyDict:
        """
        Upload a file to the OpenCTI API
        :param file_name: File name
        :param data: File data
        :param mime_type: File mime type
        :return: The query response for the file upload
        """
        log.info("Uploading a file")

        if data is None:
            data = open(file_name, "rb")
            if file_name.endswith(".json"):
                mime_type = "application/json"
            else:
                mime_type = magic.from_file(file_name, mime=True)

        query = """
            mutation UploadImport($file: Upload!) {
                uploadImport(file: $file) {
                    id
                    name
                }
            }
         """
        variables = {"file": File(file_name, data, mime_type)}
        result = self.query(query, variables)
        return result["data"]["uploadImport"]

    def upload_pending_file(
        self,
        *,
        file_name: str,
        data: bytes = None,
        mime_type: str = "text/plain",
        entity_id: str = None,
    ) -> UploadFileDataDict:
        """Upload a pending file to the OpenCTI API
        :param file_name: File name
        :param data: File data
        :param mime_type: File mime type
        :param entity_id: Pending entity ID
        :return: The query response for the file upload
        """
        log.info("Uploading a file.")

        if data is None:
            data = open(file_name, "rb")
            if file_name.endswith(".json"):
                mime_type = "application/json"
            else:
                mime_type = magic.from_file(file_name, mime=True)

        query = """
            mutation UploadPending($file: Upload!, $entityId: String) {
                uploadPending(file: $file, entityId: $entityId) {
                    id
                    name
                }
            }
         """
        variables = {
            "file": File(file_name, data, mime_type),
            "entityId": entity_id,
        }
        result = self.query(query, variables)
        return result["data"]["uploadPending"]

    def get_stix_content(self, stix_id: str) -> AnyDict:
        """
        Get the embedded STIX content of any entity
        :return: The STIX content in JSON
        """
        log.info("Entity in JSON %s", stix_id)
        query = """
            query StixQuery($id: String!) {
                stix(id: $id)
            }
        """
        variables = {"id": stix_id}
        result = self.query(query, variables)
        result = result["data"]["stix"]
        return json.loads(result)

    @staticmethod
    def get_attribute_in_extension(
        key: str,
        obj: AnyDict,
    ) -> Optional[Any]:
        """
        Try to get data from the EXT_OCTI or EXT_OCTI_SCO extensions
        :param key: Key within the extension
        :param obj: Data object
        :return: Extension key data, or the default value
        """
        extensions = obj.get("extensions")
        if extensions is None:
            return None

        octi = extensions.get(STIX_EXT_OCTI, {}).get(key)
        if octi is not None:
            return octi

        octi_sci = extensions.get(STIX_EXT_OCTI_SCO, {}).get(key)
        if octi_sci is not None:
            return octi

        return None

    @staticmethod
    def get_attribute_in_mitre_extension(
        key: str,
        obj: AnyDict,
    ) -> Optional[Any]:
        """
        Try to get data from the EXT_MITRE extension
        :param key: Key within the extension
        :param obj: Data object
        :return: Extension key data, or None
        """
        extensions = obj.get("extensions")
        if extensions is None:
            return None

        mitre = extensions.get(STIX_EXT_MITRE, {}).get(key)
        if mitre is not None:
            return mitre

        return None


class ProxyDict(TypedDict):
    """A requests compatible proxy definition"""

    http: Optional[str]
    https: Optional[str]


ProcessedList = List[AnyDict]


class ProcessedDict(TypedDict):
    """Result from `OpenCTIApiClient.process_multiple_paginated`"""

    entities: List[AnyDict]
    pagination: Union[EmptyDict, PageInfoDict]


ProcessedResultsDict = Union[ProcessedList, ProcessedDict]


class EmptyDict(TypedDict):
    """An empty dict"""


class PageInfoDict(TypedDict):
    """Pagination info"""

    startCursor: str
    endCursor: str
    hasNextPage: bool
    hasPreviousPage: bool
    globalCount: int


class MultipartFileDataDict(TypedDict):
    """Multi-part file upload data"""

    key: str
    file: Union[File, List[File]]
    multiple: bool


class UploadFileDataDict(TypedDict):
    """Spec for an uploaded file"""

    id: str
    name: str


class LogsWorkerConfigDict(TypedDict):
    """Query: logsWorkerConfig"""

    elasticsearch_url: List[str]
    elasticsearch_proxy: Optional[str]
    elasticsearch_index: str
    elasticsearch_username: Optional[str]
    elasticsearch_password: Optional[str]
    elasticsearch_api_key: Optional[str]
    elasticsearch_ssl_reject_unauthorized: Optional[bool]


class File(NamedTuple):
    """Spec for uploading a file"""

    name: str
    data: Union[str, bytes]
    mime: str = "text/plain"
