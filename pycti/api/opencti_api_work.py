"""OpenCTI job/work API"""

from __future__ import annotations

import logging
import time
from enum import Enum
from typing import List, Optional, TypedDict

from .opencti_api_client import OpenCTIApiClient

__all__ = [
    "OpenCTIApiClient",
    "OpenCTIApiWork",
    "State",
    "WorkErrorInput",
    "WorkDetails",
    "WorkUser",
    "WorkTracking",
    "WorkMessages",
    "WorkErrors",
]

log = logging.getLogger(__name__)


class OpenCTIApiWork:
    """OpenCTI job/work API"""

    def __init__(self, opencti: OpenCTIApiClient):
        """
        Constructor
        :param opencti: OpenCTI API client.
        """
        self._opencti = opencti

    def to_received(self, work_id: str, message: str) -> None:
        """
        Set a job to received
        :param work_id: Work ID
        :param message: Message
        :return: None
        """
        log.info("Reporting work update_received " + work_id)
        query = """
            mutation workToReceived($id: ID!, $message: String) {
                workEdit(id: $id) {
                    toReceived (message: $message)
                }
            }
        """
        variables = {"id": work_id, "message": message}
        self._opencti.query(query, variables)

    def to_processed(self, work_id: str, message: str, in_error: bool = False) -> None:
        """
        Set a job to processed
        :param work_id: Work ID
        :param message: Message
        :param in_error: Whether an error has occurred
        :return: None
        """
        log.info("Reporting work update_received %s", work_id)
        query = """
            mutation workToProcessed($id: ID!, $message: String, $inError: Boolean) {
                workEdit(id: $id) {
                    toProcessed (message: $message, inError: $inError)
                }
            }
        """
        variables = {"id": work_id, "message": message, "inError": in_error}
        self._opencti.query(query, variables)

    def ping(self, work_id: str) -> None:
        """
        Ping a job
        :param work_id: Work ID
        :return: None
        """
        log.info("Ping work %s", work_id)
        query = """
            mutation pingWork($id: ID!) {
                workEdit(id: $id) {
                    ping
                }
            }
        """
        variables = {"id": work_id}
        self._opencti.query(query, variables)

    def report_expectation(self, work_id: str, error: WorkErrorInput) -> None:
        """
        Report an expectation
        :param work_id: Work ID
        :param error: Work error input
        :return: None
        """
        log.info("Reporting expectation for %s", work_id)
        query = """
            mutation reportExpectation($id: ID!, $error: WorkErrorInput) {
                workEdit(id: $id) {
                    reportExpectation(error: $error)
                }
            }
        """
        try:
            variables = {"id": work_id, "error": error}
            self._opencti.query(query, variables)
        except Exception as ex:
            log.error("Cannot report expectation: %s", ex, exc_info=ex)

    def add_expectations(self, work_id: str, expectations: int) -> None:
        """
        Add expectations to a job
        :param work_id: Work ID
        :param expectations: Expectations count
        :return: None
        """
        log.info("Update action expectations %s - %d", work_id, expectations)
        query = """
            mutation addExpectations($id: ID!, $expectations: Int) {
                workEdit(id: $id) {
                    addExpectations(expectations: $expectations)
                }
            }
        """
        try:
            variables = {"id": work_id, "expectations": expectations}
            self._opencti.query(query, variables)
        except Exception as ex:
            log.error("Cannot report expectation: %s", ex, exc_info=ex)

    def initiate_work(self, connector_id: str, friendly_name: str) -> str:
        """
        Initiate a job
        :param connector_id: Connector ID
        :param friendly_name: Display name
        :return: Work ID
        """
        log.info("Initiate work for %s", connector_id)
        query = """
            mutation workAdd($connectorId: String!, $friendlyName: String) {
                workAdd(connectorId: $connectorId, friendlyName: $friendlyName) {
                  id
                }
            }
        """
        variables = {"connectorId": connector_id, "friendlyName": friendly_name}
        work = self._opencti.query(query, variables)
        return work["data"]["workAdd"]["id"]

    def delete_work(self, work_id: str):
        """
        Delete a job
        :param work_id: Work ID
        :return: Work ID
        """
        query = """
            mutation ConnectorWorksMutation($workId: ID!) {
                workEdit(id: $workId) {
                    delete
                }
            }
        """
        variables = {"workId": work_id}
        work = self._opencti.query(query, variables)
        return work["data"]["workEdit"]["delete"]

    def wait_for_work_to_finish(self, work_id: str) -> None:
        """
        Wait for a job to finish
        :param work_id: Work ID
        :return: None
        """
        status = ""
        while status != "complete":
            state = self.get_work(work_id=work_id)
            if len(state) > 0:
                status = state["status"]
                if state["errors"]:
                    log.error("Unexpected connector error %s", state["errors"])
                    return

            time.sleep(1)

    def get_work(self, work_id: str) -> WorkDetails:
        """
        Get a job
        :param work_id: Work ID
        :return: Job response data
        """
        query = """
            query WorkQuery($id: ID!) {
                work(id: $id) {
                    id
                    name
                    user {
                        name
                    }
                    timestamp
                    status
                    event_source_id
                    received_time
                    processed_time
                    completed_time
                    tracking {
                        import_expected_number
                        import_processed_number
                    }
                    messages {
                        timestamp
                        message
                        sequence
                        source
                    }
                    errors {
                        timestamp
                        message
                        sequence
                        source
                    }
                }
            }
        """
        variables = {"id": work_id}
        result = self._opencti.query(query, variables)
        return result["data"]["work"]

    def get_connector_works(self, connector_id: str) -> List[WorkDetails]:
        """
        Get all jobs by a connector
        :param connector_id: Connector ID
        :return: Connector job response data
        """
        query = """
            query ConnectorWorksQuery(
                $count: Int
                $orderBy: WorksOrdering
                $orderMode: OrderingMode
                $filters: [WorksFiltering]
            ) {
                works(
                    first: $count
                    orderBy: $orderBy
                    orderMode: $orderMode
                    filters: $filters
                ) {
                    edges {
                        node {
                            id
                            name
                            user {
                                name
                            }
                            timestamp
                            status
                            event_source_id
                            received_time
                            processed_time
                            completed_time
                            tracking {
                                import_expected_number
                                import_processed_number
                            }
                            messages {
                                timestamp
                                message
                                sequence
                                source
                            }
                            errors {
                                timestamp
                                message
                                sequence
                                source
                            }
                        }
                    }
                }
            }
        """
        variables = {
            "count": 50,
            "orderBy": "timestamp",
            "orderMode": "asc",
            "filters": [
                {
                    "key": "connector_id",
                    "values": [connector_id],
                }
            ],
        }
        result = self._opencti.query(query, variables)
        result = result["data"]["works"]["edges"]
        return [edge["node"] for edge in result]


class State(str, Enum):
    """Job state"""

    wait = "wait"
    progress = "progress"
    complete = "complete"
    timeout = "timeout"


class WorkErrorInput(TypedDict):
    """Work error expectation input"""

    error: Optional[str]
    source: Optional[str]


class WorkDetails(TypedDict):
    """Get work details"""

    id: str
    name: Optional[str]
    user: Optional[WorkUser]
    timestamp: str
    status: State
    event_source_id: Optional[str]
    received_time: Optional[str]
    processed_time: Optional[str]
    completed_time: Optional[str]
    tracking: Optional[WorkTracking]
    messages: Optional[List[Optional[WorkMessages]]]
    errors: Optional[List[Optional[WorkErrors]]]


class WorkUser(TypedDict):
    """GetWorkDetails.user"""

    name: str


class WorkTracking(TypedDict):
    """GetWorkDetails.tracking"""

    import_expected_number: Optional[int]
    import_processed_number: Optional[int]


class WorkMessages(TypedDict):
    """GetWorkDetails.messages"""

    timestamp: Optional[str]
    message: Optional[str]
    sequence: Optional[int]
    source: Optional[str]


class WorkErrors(TypedDict):
    """GetWorkDetails.errors"""

    timestamp: Optional[str]
    message: Optional[str]
    sequence: Optional[int]
    source: Optional[str]
