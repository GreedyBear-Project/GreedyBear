import json
from pathlib import Path

from greedybear.cronjobs.scoring.random_forest import RFClassifier, RFRegressor
from greedybear.settings import ML_CONFIG_FILE
from tests import CustomTestCase


class TestRFConfig(CustomTestCase):
    def setUp(self):
        with Path(ML_CONFIG_FILE).open("rb") as f:
            self.config = json.load(f)

    def test_rf_classifier_config_loading(self):
        """
        Verify that RFClassifier correctly loads parameters from the actual configuration file.
        This ensures that the ml_config.json file is valid and its values are being respected.
        """
        params = self.config["RFClassifier"]
        # Apply the same transformation logic as the class
        if "class_weight" in params:
            params["class_weight"] = {(k.lower() == "true"): v for k, v in params["class_weight"].items() if k.lower() in ["true", "false"]}

        classifier = RFClassifier()
        model = classifier.untrained_model

        for key, value in params.items():
            actual_value = getattr(model, key)
            self.assertEqual(
                actual_value,
                value,
                f"RFClassifier parameter '{key}' mismatch. Config: {value}, Model: {actual_value}",
            )

    def test_rf_regressor_config_loading(self):
        """
        Verify that RFRegressor correctly loads parameters from the actual configuration file.
        """
        params = self.config["RFRegressor"]

        regressor = RFRegressor()
        model = regressor.untrained_model

        for key, value in params.items():
            actual_value = getattr(model, key)
            self.assertEqual(
                actual_value,
                value,
                f"RFRegressor parameter '{key}' mismatch. Config: {value}, Model: {actual_value}",
            )
