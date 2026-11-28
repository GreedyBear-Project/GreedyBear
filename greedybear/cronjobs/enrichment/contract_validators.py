import logging
from typing import Any

logger = logging.getLogger(__name__)


class ContractValidationError(ValueError):
    """Raised when external feed data does not conform to expected schema."""
    pass


class ThreatFoxContractValidator:
    """
    Contract validator for ThreatFox API responses.
    ThreatFox API endpoint: https://threatfox-api.abuse.ch/api/v1/
    Expected structure:
    {
        "query_status": str ("ok", "no_result", etc.),
        "data": [
            {
                "ioc": str,
                "ioc_type": str,
                "malware_printable": str (optional),
                "threat_type": str (optional),
                "confidence_level": int (optional)
            },
            ...
        ]
    }
    """

    @staticmethod
    def validate_response(response_json: Any) -> bool:
        if not isinstance(response_json, dict):
            logger.warning("ThreatFox response is not a JSON object/dict.")
            return False

        if "query_status" not in response_json:
            logger.warning("ThreatFox response missing 'query_status' field.")
            return False

        query_status = response_json.get("query_status")
        if query_status != "ok":
            return True

        data = response_json.get("data")
        if not isinstance(data, list):
            logger.warning("ThreatFox response 'data' field is not a list.")
            return False

        return True

    @staticmethod
    def validate_item(item: Any) -> bool:
        if not isinstance(item, dict):
            return False
        # 'ioc' and 'ioc_type' are essential contract keys
        if "ioc" not in item or not isinstance(item["ioc"], str):
            return False
        if "ioc_type" not in item or not isinstance(item["ioc_type"], str):
            return False
        return True


class AbuseIPDBContractValidator:
    """
    Contract validator for AbuseIPDB API responses.
    Endpoint: https://api.abuseipdb.com/api/v2/blacklist
    Expected structure:
    {
        "data": [
            {
                "ipAddress": str,
                "abuseConfidenceScore": int / float,
                ...
            },
            ...
        ]
    }
    """

    @staticmethod
    def validate_response(response_json: Any) -> bool:
        if not isinstance(response_json, dict):
            logger.warning("AbuseIPDB response is not a JSON object/dict.")
            return False

        if "data" not in response_json:
            logger.warning("AbuseIPDB response missing 'data' field.")
            return False

        data = response_json.get("data")
        if not isinstance(data, list):
            logger.warning("AbuseIPDB response 'data' field is not a list.")
            return False

        return True

    @staticmethod
    def validate_item(item: Any) -> bool:
        if not isinstance(item, dict):
            return False
        # 'ipAddress' is essential, and 'abuseConfidenceScore' should exist
        if "ipAddress" not in item or not isinstance(item["ipAddress"], str):
            return False
        score = item.get("abuseConfidenceScore")
        if score is not None and not isinstance(score, (int, float)):
            return False
        return True


class MalwareBazaarContractValidator:
    """
    Contract validator for MalwareBazaar API responses.
    Endpoint: https://mb-api.abuse.ch/api/v1/
    Expected structure:
    {
        "query_status": str,
        "data": ... (optional or status message)
    }
    """

    @staticmethod
    def validate_response(response_json: Any) -> bool:
        if not isinstance(response_json, dict):
            logger.warning("MalwareBazaar response is not a JSON object/dict.")
            return False

        if "query_status" not in response_json or not isinstance(response_json["query_status"], str):
            logger.warning("MalwareBazaar response missing or invalid 'query_status'.")
            return False

        return True
