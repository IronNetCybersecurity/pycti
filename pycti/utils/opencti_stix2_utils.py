"""OpenCTI STIX2 Utilities"""

from typing import Optional

from stix2 import EqualityComparisonExpression, ObjectPath, ObservationExpression

STIX_CYBER_OBSERVABLE_MAPPING = {
    "autonomous-system": "Autonomous-System",
    "directory": "Directory",
    "domain-name": "Domain-Name",
    "email-addr": "Email-Addr",
    "file": "StixFile",
    "email-message": "Email-Message",
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "mac-addr": "Mac-Addr",
    "mutex": "Mutex",
    "network-traffic": "Network-Traffic",
    "process": "Process",
    "software": "Software",
    "url": "Url",
    "user-account": "User-Account",
    "windows-registry-key": "Windows-Registry-Key",
    "windows-registry-value-type": "Windows-Registry-Value-Type",
    "hostname": "Hostname",
}

PATTERN_MAPPING = {
    "Autonomous-System": ["number"],
    "Directory": ["path"],
    "Domain-Name": ["value"],
    "Email-Addr": ["value"],
    "File_md5": ["hashes", "MD5"],
    "File_sha1": ["hashes", "SHA-1"],
    "File_sha256": ["hashes", "SHA-256"],
    "File_sha512": ["hashes", "SHA-512"],
    "Email-Message_Body": ["body"],
    "Email-Message_Subject": ["subject"],
    "Email-Mime-Part-Type": ["body"],
    "IPv4-Addr": ["value"],
    "IPv6-Addr": ["value"],
    "Mac-Addr": ["value"],
    "Mutex": ["name"],
    "Network-Traffic": ["dst_port"],
    "Process": ["pid"],
    "Software": ["name"],
    "Url": ["value"],
    "User-Account": ["account_login"],
    "Windows-Registry-Key": ["key"],
    "Windows-Registry-Value-Type": ["name"],
    "Hostname": ["value"],
}

OBSERVABLES_VALUE_INT = [
    "Autonomous-System.number",
    "Network-Traffic.dst_port",
    "Process.pid",
]


class OpenCTIStix2Utils:
    """OpenCTI STIX2 Utilities"""

    @classmethod
    def stix_observable_opencti_type(cls, observable_type: str) -> str:
        """Get the OpenCTI observable type from a STIX2 type name.
        :param observable_type: STIX2 object type
        :return: The OpenCTI observable type, or "Unknown"
        """
        return STIX_CYBER_OBSERVABLE_MAPPING.get(observable_type, "Unknown")

    @classmethod
    def create_stix_pattern(
        cls,
        observable_type: str,
        observable_value: str,
    ) -> Optional[str]:
        """Create a STIX2 compliant Indicator pattern
        :param observable_type: Observable type name
        :param observable_value: Observable value
        :return: A STIX2 compliant Indicator pattern, None if the type is not recognized
        """
        if observable_type not in PATTERN_MAPPING:
            return None

        object_type = observable_type.split("_")[0].lower()
        property_path = PATTERN_MAPPING[observable_type]
        object_path = ObjectPath(object_type, property_path)

        ece = EqualityComparisonExpression(object_path, observable_value)
        oe = ObservationExpression(str(ece))
        return str(oe)

    @staticmethod
    def generate_random_stix_id(stix_type: str) -> str:
        """Obsolete"""
        raise ValueError(
            "This function should not be used anymore, "
            "please use the generate_id function for SDO or proper SCO constructor"
        )
