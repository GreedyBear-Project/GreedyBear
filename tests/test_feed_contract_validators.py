import unittest
from greedybear.cronjobs.enrichment.contract_validators import (
    ThreatFoxContractValidator,
    AbuseIPDBContractValidator,
    MalwareBazaarContractValidator,
)


class TestExternalFeedContractValidators(unittest.TestCase):
    """Unit tests for external feed schema contract validators."""

    def test_threatfox_valid_response(self):
        resp = {"query_status": "ok", "data": [{"ioc": "1.1.1.1:80", "ioc_type": "ip:port"}]}
        self.assertTrue(ThreatFoxContractValidator.validate_response(resp))

    def test_threatfox_non_dict_response(self):
        self.assertFalse(ThreatFoxContractValidator.validate_response("invalid"))
        self.assertFalse(ThreatFoxContractValidator.validate_response([]))

    def test_threatfox_missing_query_status(self):
        self.assertFalse(ThreatFoxContractValidator.validate_response({"data": []}))

    def test_threatfox_invalid_data_field(self):
        self.assertFalse(ThreatFoxContractValidator.validate_response({"query_status": "ok", "data": "not_a_list"}))

    def test_threatfox_validate_item(self):
        valid = {"ioc": "1.1.1.1:80", "ioc_type": "ip:port"}
        self.assertTrue(ThreatFoxContractValidator.validate_item(valid))

        missing_ioc = {"ioc_type": "ip:port"}
        self.assertFalse(ThreatFoxContractValidator.validate_item(missing_ioc))

        missing_type = {"ioc": "1.1.1.1:80"}
        self.assertFalse(ThreatFoxContractValidator.validate_item(missing_type))

    def test_abuseipdb_valid_response(self):
        resp = {"data": [{"ipAddress": "8.8.8.8", "abuseConfidenceScore": 85}]}
        self.assertTrue(AbuseIPDBContractValidator.validate_response(resp))

    def test_abuseipdb_missing_data(self):
        self.assertFalse(AbuseIPDBContractValidator.validate_response({"errors": "unauthorized"}))

    def test_abuseipdb_validate_item(self):
        valid = {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 90}
        self.assertTrue(AbuseIPDBContractValidator.validate_item(valid))

        missing_ip = {"abuseConfidenceScore": 90}
        self.assertFalse(AbuseIPDBContractValidator.validate_item(missing_ip))

        invalid_score = {"ipAddress": "8.8.8.8", "abuseConfidenceScore": "high"}
        self.assertFalse(AbuseIPDBContractValidator.validate_item(invalid_score))

    def test_malwarebazaar_valid_response(self):
        resp = {"query_status": "inserted"}
        self.assertTrue(MalwareBazaarContractValidator.validate_response(resp))

    def test_malwarebazaar_invalid_response(self):
        self.assertFalse(MalwareBazaarContractValidator.validate_response({"other": "field"}))
        self.assertFalse(MalwareBazaarContractValidator.validate_response(None))


if __name__ == "__main__":
    unittest.main()
