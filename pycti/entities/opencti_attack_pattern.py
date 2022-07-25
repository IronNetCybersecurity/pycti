"""OpenCTI Attack-Pattern CRUD operations"""

import json
import logging

import stix2

from ..api.opencti_api_client import AnyDict, OpenCTIApiClient, ProcessedResultsDict
from . import OpenCTIObjectBase
from .models.opencti_attack_pattern import *

log = logging.getLogger(__name__)


class AttackPattern(OpenCTIObjectBase):
    """Attack-Pattern CRUD operations"""

    def __init__(self, opencti: OpenCTIApiClient):
        """
        Constructor
        :param opencti: OpenCTI API client.
        """
        self._opencti = opencti
        self._properties = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            createdBy {
                ... on Identity {
                id
                    standard_id
                    entity_type
                    parent_types
                    spec_version
                    identity_class
                    name
                    description
                    roles
                    contact_information
                    x_opencti_aliases
                    created
                    modified
                    objectLabel {
                        edges {
                            node {
                                id
                                value
                                color
                            }
                        }
                    }
                }
                ... on Organization {
                    x_opencti_organization_type
                    x_opencti_reliability
                }
                ... on Individual {
                    x_opencti_firstname
                    x_opencti_lastname
                }
            }
            objectMarking {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        definition_type
                        definition
                        created
                        modified
                        x_opencti_order
                        x_opencti_color
                    }
                }
            }
            objectLabel {
                edges {
                    node {
                        id
                        value
                        color
                    }
                }
            }
            externalReferences {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        source_name
                        description
                        url
                        hash
                        external_id
                        created
                        modified
                        importFiles {
                            edges {
                                node {
                                    id
                                    name
                                    size
                                    metaData {
                                        mimetype
                                        version
                                    }
                                }
                            }
                        }
                    }
                }
            }
            revoked
            confidence
            created
            modified
            name
            description
            aliases
            x_mitre_platforms
            x_mitre_permissions_required
            x_mitre_detection
            x_mitre_id
            killChainPhases {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        kill_chain_name
                        phase_name
                        x_opencti_order
                        created
                        modified
                    }
                }
            }
            importFiles {
                edges {
                    node {
                        id
                        name
                        size
                        metaData {
                            mimetype
                            version
                        }
                    }
                }
            }
        """

    @classmethod
    def generate_id(cls, name: str, x_mitre_id: str = None) -> str:
        """
        Generate a STIX2 identifier.
        :param name: Object value
        :param x_mitre_id: External ID
        :return: A STIX2 identifier
        """
        if x_mitre_id is not None:
            data = {"x_mitre_id": x_mitre_id}
        else:
            data = {"name": name.lower().strip()}

        return cls._generate_id("attack-pattern", data)

    def list(
        self,
        args: AttackPatternListInput = None,
        properties: str = None,
        get_all: bool = False,
        with_pagination: bool = False,
    ) -> ProcessedResultsDict:
        """
        List Attack-Pattern objects
        :param args: Input variables
        :param properties: Custom properties
        :param get_all: Get all results
        :param with_pagination: Paginate the results
        :return List of Attack-Pattern objects
        """
        if args is None:
            args = AttackPatternListInput()
        if properties is None:
            properties = self._properties
        if get_all:
            args.first = 500

        log.info("Listing Attack-Patterns with filters %s.", json.dumps(args.filters))
        query = """
            query AttackPatterns($filters: [AttackPatternsFiltering], $search: String, $first: Int, $after: ID, $orderBy: AttackPatternsOrdering, $orderMode: OrderingMode) {
                attackPatterns(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            %s
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }
                }
            }
        """
        query %= properties

        variables = args.dict(by_alias=True)
        result = self._opencti.query(query, variables)
        result = result["data"]["attackPatterns"]

        if get_all:
            args = args.copy(deep=True)  # Don't modify the original
            final_data = self._opencti.process_multiple_flat(result)

            while result["page_info"]["has_next_page"]:
                args.after = result["page_info"]["end_cursor"]
                log.info("Listing Attack-Patterns after %s", args.after)

                variables = args.dict(by_alias=True)
                result = self._opencti.query(query, variables)
                result = result["data"]["attackPatterns"]
                final_data += self._opencti.process_multiple_flat(result)

            return final_data

        else:
            return self._opencti.process_multiple(result, with_pagination)

    def read(
        self,
        args: AttackPatternReadInput = None,
        filters: List[AttackPatternsFilter] = None,
        properties: str = None,
    ) -> Optional[AnyDict]:
        """
        Read an Attack-Pattern object
        :param args: Input variables
        :param filters: Object filters
        :param properties: Custom properties
        :return An Attack-Pattern object
        """
        if properties is None:
            properties = self._properties

        if args is not None:
            log.info("Reading Attack-Pattern {%s}.", args.id)
            query = """
                query AttackPattern($id: String!) {
                    attackPattern(id: $id) {
                        %s
                    }
                }
             """
            query %= properties

            variables = {"id": id}
            result = self._opencti.query(query, variables)
            result = result["data"]["attackPattern"]
            return self._opencti.process_multiple_fields(result)

        elif filters is not None:
            result = self.list(AttackPatternListInput(filters=filters))
            return next(iter(result), None)

        else:
            log.error("Missing parameters: id or filters")
            return None

    def create(
        self,
        args: AttackPatternCreateInput,
    ) -> Optional[AnyDict]:
        """
        Create an Attack-Pattern object
        :param args: Input variables
        :return An Attack-Pattern object
        """
        if args.name is not None:
            log.info("Creating Attack-Pattern {%s}.", args.name)
            query = """
                mutation AttackPatternAdd($input: AttackPatternAddInput) {
                    attackPatternAdd(input: $input) {
                        id
                        standard_id
                        entity_type
                        parent_types
                    }
                }
            """

            variables = args.dict(by_alias=True)
            result = self._opencti.query(query, variables)
            result = result["data"]["attackPatternAdd"]
            return self._opencti.process_multiple_fields(result)

        else:
            log.error("Missing parameters: name")
            return None

    def import_from_stix2(
        self,
        stix_object: stix2.AttackPattern,
        extras: AnyDict = None,
        update: bool = False,
    ) -> Optional[AnyDict]:
        """
        Import an Attack-Pattern object from a STIX2 object
        :param stix_object: A `stix2.AttackPattern` object
        :param extras: Extra properties
        :param update: Update existing objects
        :return: An Attack-Pattern object
        """
        if extras is None:
            extras = {}

        if stix_object is not None:
            # Extract external ID
            x_mitre_id = stix_object.get("x_mitre_id")

            if x_mitre_id is None:
                x_mitre_id = self._opencti.get_attribute_in_mitre_extension(
                    "id", stix_object
                )

            if x_mitre_id is None:
                source_names = [
                    "mitre-attack",
                    "mitre-pre-attack",
                    "mitre-mobile-attack",
                    "mitre-ics-attack",
                    "amitt-attack",
                ]

                external_references = stix_object.get("external_references", [])
                for ext_ref in external_references:
                    if ext_ref["source_name"] in source_names:
                        x_mitre_id = ext_ref.get("external_id")

            # Search in extensions
            if "x_opencti_order" not in stix_object:
                order = self._opencti.get_attribute_in_extension("order", stix_object)
                if order is None:
                    order = 0
                stix_object["x_opencti_order"] = order

            if "x_mitre_platforms" not in stix_object:
                platforms = self._opencti.get_attribute_in_mitre_extension(
                    "platforms", stix_object
                )
                stix_object["x_mitre_platforms"] = platforms

            if "x_mitre_permissions_required" not in stix_object:
                permissions = self._opencti.get_attribute_in_mitre_extension(
                    "permissions_required", stix_object
                )
                stix_object["x_mitre_permissions_required"] = permissions

            if "x_mitre_detection" not in stix_object:
                detection = self._opencti.get_attribute_in_mitre_extension(
                    "detection", stix_object
                )
                stix_object["x_mitre_detection"] = detection

            if "x_opencti_stix_ids" not in stix_object:
                stix_ids = self._opencti.get_attribute_in_extension(
                    "stix_ids", stix_object
                )
                stix_object["x_opencti_stix_ids"] = stix_ids

            description = stix_object.get("description", "")
            description = self._opencti.stix2.convert_markdown(description)

            mitre_platforms = stix_object.get("x_mitre_platforms")
            amitt_platforms = stix_object.get("x_amitt_platforms")
            platforms = mitre_platforms or amitt_platforms

            args = AttackPatternCreateInput(
                stix_id=stix_object["id"],
                createdBy=extras.get("created_by_id"),
                objectMarking=extras.get("object_marking_ids"),
                objectLabel=extras.get("object_label_ids", []),
                externalReferences=extras.get("external_references_ids", []),
                revoked=stix_object.get("revoked"),
                confidence=stix_object.get("confidence"),
                lang=stix_object.get("lang"),
                created=stix_object.get("created"),
                modified=stix_object.get("modified"),
                name=stix_object["name"],
                description=description,
                aliases=self._opencti.stix2.pick_aliases(stix_object),
                x_mitre_platforms=platforms,
                x_mitre_permissions_required=stix_object.get(
                    "x_mitre_permissions_required"
                ),
                x_mitre_detection=stix_object.get("x_mitre_detection"),
                x_mitre_id=x_mitre_id,
                killChainPhases=extras.get("kill_chain_phases_ids"),
                x_opencti_stix_ids=stix_object.get("x_opencti_stix_ids"),
                update=update,
            )

            return self.create(args=args)

        else:
            log.error("Missing parameters: stix_object")

    def delete(self, stix_id: str) -> None:
        """
        Delete an Attack-Pattern
        :param stix_id: Object ID
        :return: None
        """

        log.info("Deleting Attack Pattern {%s}.", stix_id)
        query = """
            mutation AttackPatternEdit($id: ID!) {
                attackPatternEdit(id: $id) {
                    delete
                }
            }
        """
        self._opencti.query(query, {"id": stix_id})
