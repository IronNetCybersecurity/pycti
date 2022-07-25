"""OpenCTI Bundle splitter"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Literal, TypedDict, Union

__all__ = [
    "OpenCTIStix2Splitter",
    "Bundle",
    "EventBundle",
]


class OpenCTIStix2Splitter:
    """OpenCTI Bundle splitter"""

    def __init__(self):
        """Constructor"""
        self.cache_index = {}
        self.elements = []

    def _enlist_element(self, item_id: str, raw_data: Dict[str, Any]) -> int:
        """
        Enlist an element from a bundle and gather its dependencies
        :param item_id: Item ID
        :param raw_data: Raw object data
        :return: The nb_deps count
        """
        nb_deps = 1
        if item_id not in raw_data:
            return 0

        existing_item = self.cache_index.get(item_id)
        if existing_item is not None:
            return existing_item["nb_deps"]

        # Recursive enlist for every refs
        item = raw_data[item_id]
        for key, value in item.items():
            if key.endswith("_refs"):
                for element_ref in item[key]:
                    nb_deps += self._enlist_element(element_ref, raw_data)

            elif key.endswith("_ref"):
                # Need to handle the special case of recursive ref for created by ref
                is_created_by_ref = key == "created_by_ref"
                if is_created_by_ref:
                    is_marking = item["id"].startswith("marking-definition--")
                    if is_marking is False:
                        nb_deps += self._enlist_element(value, raw_data)
                else:
                    nb_deps += self._enlist_element(value, raw_data)

        # Get the final dep counting and add in cache
        item["nb_deps"] = nb_deps
        self.elements.append(item)
        self.cache_index[item_id] = item  # Put in cache

        return nb_deps

    def split_bundle(
        self,
        bundle: Union[Bundle, EventBundle, str],
        use_json: bool = True,
        event_version: str = None,
    ) -> List[Union[str, Dict[str, Any]]]:
        """
        Split a valid stix2 bundle into a list of bundles
        :param bundle: A valid stix2 bundle
        :param use_json: Use JSON to deserialize the bundle input
        :param event_version: OpenCTI event version
        :return: A list of bundles objects or JSON strings
        :raises Exception: if data is not valid JSON
        """
        bundle_data: Union[Bundle, EventBundle]

        if use_json:
            try:
                bundle_data = json.loads(bundle)
            except Exception as ex:
                raise Exception("Bundle data is not valid JSON") from ex
        else:
            bundle_data = bundle

        if "objects" not in bundle_data:
            raise Exception("File data is not a valid bundle")

        if "id" not in bundle_data:
            bundle_data["id"] = f"bundle--{uuid.uuid4()}"

        raw_data = {}

        # Build flat list of elements
        for item in bundle_data["objects"]:
            raw_data[item["id"]] = item

        for item in bundle_data["objects"]:
            self._enlist_element(item["id"], raw_data)

        # Build the bundles
        self.elements.sort(key=lambda e: e["nb_deps"])
        bundles = [
            self.stix2_create_bundle(
                bundle_data["id"],
                entity["nb_deps"],
                [entity],
                use_json,
                event_version,
            )
            for entity in self.elements
        ]

        return bundles

    @staticmethod
    def stix2_create_bundle(
        bundle_id: str,
        bundle_seq: int,
        items: List[Dict[str, Any]],
        use_json: bool,
        event_version: str = None,
    ) -> Union[Bundle, EventBundle, str]:
        """
        Create a stix2 bundle with items
        :param bundle_id: Bundle uuid4 ID
        :param bundle_seq: Bundle sequence number
        :param items: Valid stix2 items
        :param use_json: Serialize the bundle with JSON
        :param event_version: OpenCTI event version
        :return: Bundle JSON or object representation
        """
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "x_opencti_seq": bundle_seq,
            "objects": items,
        }

        if event_version is not None:
            bundle["x_opencti_event_version"] = event_version

        if use_json:
            return json.dumps(bundle)

        return bundle


class Bundle(TypedDict):
    """Bundle spec"""

    type: Literal["bundle"]
    id: str
    spec_version: Literal["2.1"]
    x_opencti_seq: int
    objects: List[Dict[str, Any]]


class EventBundle(Bundle):
    """Bundle with an event version spec"""

    x_opencti_event_version: str
