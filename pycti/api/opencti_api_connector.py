"""OpenCTI connector API"""

from __future__ import annotations

import json
import logging
from typing import Any, List, Optional, TypedDict

from ..connector.opencti_connector import OpenCTIConnector
from .opencti_api_client import OpenCTIApiClient

__all__ = [
    "OpenCTIApiConnector",
    "ListConnectorDetail",
    "ListConnectorConfig",
    "ListConnectorConnection",
    "PingConnectorDetail",
    "RegisterConnectorDetails",
    "RegisterConnectorConfig",
    "RegisterConnectorConnection",
    "RegisterConnectorUser",
]

log = logging.getLogger(__name__)


class OpenCTIApiConnector:
    """OpenCTI Connector API client"""

    def __init__(self, api: OpenCTIApiClient):
        """
        Constructor
        :param api: OpenCTI API client.
        """
        self._api = api

    def list(self) -> List[ListConnectorDetail]:
        """
        List available connectors
        :return: Connector details
        """
        log.info("Getting connectors")
        query = """
            query GetConnectors {
                connectors {
                    id
                    name
                    config {
                        connection {
                            host
                            vhost
                            use_ssl
                            port
                            user
                            pass
                        }
                        listen
                        push
                    }
                }
            }
        """
        result = self._api.query(query)
        result = result["data"]["connectors"]
        # return pydantic.parse_obj_as(List[ListConnectorDetail], result)
        return result

    def ping(self, connector_id: str, connector_state: Any) -> PingConnectorDetail:
        """
        Ping a connector by ID and state
        :param connector_id: The connector id
        :param connector_state: Connector state
        :return: The ping response data
        """
        query = """
            mutation PingConnector($id: ID!, $state: String) {
                pingConnector(id: $id, state: $state) {
                    id
                    connector_state
                }
            }
        """
        variables = {"id": connector_id, "state": json.dumps(connector_state)}
        result = self._api.query(query, variables)
        result = result["data"]["pingConnector"]
        # return pydantic.parse_obj_as(PingConnectorDetail, result)
        return result

    def register(self, connector: OpenCTIConnector) -> RegisterConnectorDetails:
        """
        Register a connector with OpenCTI
        :param connector: `OpenCTIConnector` connector object
        :return: The register response data
        """
        query = """
            mutation RegisterConnector($input: RegisterConnectorInput) {
                registerConnector(input: $input) {
                    id
                    connector_state
                    config {
                        connection {
                            host
                            vhost
                            use_ssl
                            port
                            user
                            pass
                        }
                        listen
                        listen_exchange
                        push
                        push_exchange
                    }
                    connector_user {
                        id
                    }
                }
            }
        """
        variables = connector.to_input()
        result = self._api.query(query, variables)
        result = result["data"]["registerConnector"]
        # return pydantic.parse_obj_as(RegisterConnectorDetails, result)
        return result

    def unregister(self, connector_id: str) -> str:
        """
        Unregister a connector with OpenCTI
        :param connector_id: Connector ID
        :return: The connector_id
        """
        query = """
            mutation ConnectorDeletionMutation($id: ID!) {
                deleteConnector(id: $id)
            }
        """
        variables = {"id": connector_id}
        result = self._api.query(query, variables)
        return result["data"]["deleteConnector"]


class ListConnectorDetail(TypedDict):
    """Result from `OpenCTIApiConnector.list(...)`"""

    id: str
    name: str
    config: Optional[ListConnectorConfig]


class ListConnectorConfig(TypedDict):
    """Result from `OpenCTIApiConnector.list(...).config`"""

    connection: ListConnectorConnection
    listen: str
    push: str


ListConnectorConnection = TypedDict(
    "ListConnectorConnection",
    {
        "host": str,
        "use_ssl": bool,
        "port": int,
        "vhost": str,
        "user": str,
        "pass": str,  # reserved
    },
)


# class ListConnectorConnection(TypedDict):
#     """Result from `OpenCTIApiConnector.list(...).config.connection`"""
#     host: str
#     use_ssl: bool
#     port: int
#     vhost: str
#     user: str
#     pass_: str = Field(alias="pass")


class PingConnectorDetail(TypedDict):
    """Result from `OpenCTIApiConnector.ping(...)`"""

    id: str
    connector_state: Optional[str]


class RegisterConnectorDetails(TypedDict):
    """Result from `OpenCTIApiConnector.register(...)`"""

    id: str
    connector_state: Optional[str]
    config: Optional[RegisterConnectorConfig]
    connector_user: Optional[RegisterConnectorUser]


class RegisterConnectorConfig(TypedDict):
    """Result from `OpenCTIApiConnector.register(...).config`"""

    connection: RegisterConnectorConnection
    listen: str
    listen_exchange: str
    push: str
    push_exchange: str


RegisterConnectorConnection = TypedDict(
    "RegisterConnectorConnection",
    {
        "host": str,
        "use_ssl": bool,
        "port": int,
        "vhost": str,
        "user": str,
        "pass": str,  # reserved
    },
)


# class RegisterConnectorConnection(TypedDict):
#     """Result from `OpenCTIApiConnector.register(...).config.connection`"""
#     host: str
#     use_ssl: bool
#     port: int
#     vhost: str
#     user: str
#     pass_: str = Field(alias="pass")


class RegisterConnectorUser(TypedDict):
    """Result from `OpenCTIApiConnector.register(...).config.connector_user`"""

    id: str
