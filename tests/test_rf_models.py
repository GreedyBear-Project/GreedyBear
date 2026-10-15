from unittest.mock import Mock, patch

import numpy as np
import pandas as pd

from greedybear.cronjobs.scoring.ml_model import Classifier, Regressor
from greedybear.cronjobs.scoring.random_forest import RFModel
from greedybear.cronjobs.scoring.scoring_jobs import TrainModels

from . import CustomTestCase

FEATURES = ["feature1", "feature2", "feature3", "honeypots"]
CLASSIFIER_TARGET = [False, True, True, False, True]
REGRESSOR_TARGET = [0, 1, 2, 0, 3]
SAMPLE_DATA = pd.DataFrame(
    {
        "interactions_on_eval_day": REGRESSOR_TARGET,
        "feature1": [1, 2, 3, 4, 5],
        "feature2": [0.1, 0.2, 0.3, 0.4, 0.5],
        "feature3": [122, 12, 0, 14, 87],
        "honeypots": ["A,B", "B,C", "A", "C", "A,B,C"],
    }
)


class TestClassifier(CustomTestCase):
    class MockRFModel(RFModel):
        @property
        def features(self) -> list[str]:
            return FEATURES

    class MockRFClassifier(MockRFModel, Classifier):
        def __init__(self):
            super().__init__("Mock Random Forest Classifier", "mock_score")

        @property
        def untrained_model(self):
            mock = Mock()
            mock.feature_names_in_ = FEATURES
            mock.fit.return_value = mock
            a = np.zeros((5, 2))
            a[:, 1] = [0.9, 0.8, 0.3, 0.2, 0.1]
            mock.predict_proba.return_value = a
            return mock

    def test_rf_classifier(self):
        """Test mock Random Forest classifier"""
        classifier = self.MockRFClassifier()
        classifier.model = classifier.untrained_model
        self.assertEqual(classifier.file_name, "mock_random_forest_classifier")

        training_target = classifier.training_target(SAMPLE_DATA)
        self.assertEqual(len(training_target), len(CLASSIFIER_TARGET))
        for a, b in zip(training_target, CLASSIFIER_TARGET, strict=False):
            self.assertEqual(a, b)

        df = classifier.score(SAMPLE_DATA)
        for a, b in zip(df["mock_score"], classifier.model.predict_proba.return_value[:, 1], strict=False):
            self.assertEqual(a, b)

        auc = classifier.recall_auc(df, training_target)
        self.assertEqual(0 <= auc <= 1, True)


class TestRegressor(CustomTestCase):
    class MockRFModel(RFModel):
        @property
        def features(self) -> list[str]:
            return FEATURES

    class MockRFRegressor(MockRFModel, Regressor):
        def __init__(self):
            super().__init__("Mock Random Forest Regressor", "mock_score")

        @property
        def untrained_model(self):
            mock = Mock()
            mock.feature_names_in_ = FEATURES
            mock.fit.return_value = mock
            mock.predict.return_value = np.array([0, 3, 1, 4, 2])
            return mock

    def test_rf_regressor(self):
        """Test mock Random Forest regressor"""
        regressor = self.MockRFRegressor()
        regressor.model = regressor.untrained_model
        self.assertEqual(regressor.file_name, "mock_random_forest_regressor")

        training_target = regressor.training_target(SAMPLE_DATA)
        self.assertEqual(len(training_target), len(REGRESSOR_TARGET))
        for a, b in zip(training_target, REGRESSOR_TARGET, strict=False):
            self.assertEqual(a, b)

        x_train, x_test, y_train, y_test = regressor.split_train_test(SAMPLE_DATA, training_target)
        self.assertEqual(len(x_train), 4)
        self.assertEqual(len(x_test), 1)
        self.assertEqual(len(x_train), len(y_train))
        self.assertEqual(len(x_test), len(y_test))

        df = regressor.score(SAMPLE_DATA)
        for a, b in zip(df["mock_score"], regressor.model.predict.return_value, strict=False):
            self.assertEqual(a, b)

        auc = regressor.recall_auc(df, training_target)
        self.assertEqual(0 <= auc <= 1, True)

    def test_negative_predictions(self):
        """Test that negative predictions are clipped to 0"""
        regressor = self.MockRFRegressor()
        regressor.model = regressor.untrained_model

        # Set return value with negative numbers
        regressor.model.predict.return_value = np.array([-10, 5, 0, -1, 2])

        predictions = regressor.predict(SAMPLE_DATA)

        expected = np.array([0, 5, 0, 0, 2])
        np.testing.assert_array_equal(predictions, expected)


class TestModelUnavailable(CustomTestCase):
    """Test that scoring handles missing model files gracefully."""

    class MockRFClassifier(TestClassifier.MockRFModel, Classifier):
        def __init__(self):
            super().__init__("Mock Random Forest Classifier", "mock_score")

        @property
        def untrained_model(self):
            return Mock()

    @patch("greedybear.cronjobs.scoring.ml_model.FileSystemStorage")
    def test_score_skips_when_model_unavailable(self, mock_storage_cls):
        """When the model file does not exist, score() should return a DataFrame with the score column set to 0."""
        mock_storage_cls.return_value.exists.return_value = False
        classifier = self.MockRFClassifier()
        df = classifier.score(SAMPLE_DATA)
        self.assertIn("mock_score", df.columns)
        self.assertTrue((df["mock_score"] == 0).all())


class TestScoreMultipleMultiValueFeatures(CustomTestCase):
    """score() must encode every multi-value feature, not only the first one."""

    ENCODED_FEATURES = ["feature1", "has_A", "has_B", "has_80", "has_443"]
    DATA = pd.DataFrame(
        {
            "feature1": [1, 2, 3],
            "honeypots": [["A"], ["B"], ["A", "B"]],
            "ports": [[80], [443], [80, 443]],
        }
    )

    class MockRFClassifier(RFModel, Classifier):
        def __init__(self):
            super().__init__("Mock Random Forest Classifier", "mock_score")

        @property
        def features(self) -> list[str]:
            return ["feature1", "honeypots", "ports"]

        @property
        def untrained_model(self):
            return Mock()

    @patch("greedybear.cronjobs.scoring.ml_model.MULTI_VAL_FEATURES", ["honeypots", "ports"])
    def test_score_encodes_all_multi_value_features(self):
        classifier = self.MockRFClassifier()
        classifier.model = Mock()
        classifier.model.feature_names_in_ = self.ENCODED_FEATURES
        classifier.model.predict_proba.return_value = np.array([[0.1, 0.9], [0.2, 0.8], [0.3, 0.7]])

        df = classifier.score(self.DATA)

        scored_input = classifier.model.predict_proba.call_args.args[0]
        self.assertEqual(list(scored_input.columns), self.ENCODED_FEATURES)
        self.assertEqual(list(df["mock_score"]), [0.9, 0.8, 0.7])


class TestRecallAucZeroPositives(CustomTestCase):
    """Test that recall_auc handles zero positive samples without crashing."""

    class MockRFClassifier(TestClassifier.MockRFModel, Classifier):
        def __init__(self):
            super().__init__("Mock RF Classifier", "mock_score")

        @property
        def untrained_model(self):
            mock = Mock()
            mock.feature_names_in_ = FEATURES
            mock.fit.return_value = mock
            a = np.zeros((5, 2))
            a[:, 1] = [0.9, 0.8, 0.3, 0.2, 0.1]
            mock.predict_proba.return_value = a
            return mock

    def test_recall_auc_returns_zero_when_no_positives(self):
        """recall_auc should return 0.0 instead of raising ZeroDivisionError
        when the test set contains no positive samples."""
        classifier = self.MockRFClassifier()
        classifier.model = classifier.untrained_model

        x = SAMPLE_DATA.copy()
        y_all_negative = pd.Series([False, False, False, False, False])

        result = classifier.recall_auc(x, y_all_negative)
        self.assertEqual(result, 0.0)

    def test_recall_auc_returns_zero_for_zero_regression_targets(self):
        """recall_auc should return 0.0 when all regression targets are zero."""

        class MockRFRegressor(TestRegressor.MockRFModel, Regressor):
            def __init__(self):
                super().__init__("Mock RF Regressor", "mock_score")

            @property
            def untrained_model(self):
                mock = Mock()
                mock.feature_names_in_ = FEATURES
                mock.fit.return_value = mock
                mock.predict.return_value = np.array([0, 3, 1, 4, 2])
                return mock

        regressor = MockRFRegressor()
        regressor.model = regressor.untrained_model

        x = SAMPLE_DATA.copy()
        y_all_zero = pd.Series([0, 0, 0, 0, 0])

        result = regressor.recall_auc(x, y_all_zero)
        self.assertEqual(result, 0.0)


class TestClassifierSingleClassSplit(CustomTestCase):
    """Test that Classifier.split_train_test handles single-class targets."""

    class MockRFClassifier(TestClassifier.MockRFModel, Classifier):
        def __init__(self):
            super().__init__("Mock RF Classifier", "mock_score")

        @property
        def untrained_model(self):
            mock = Mock()
            mock.feature_names_in_ = FEATURES
            mock.fit.return_value = mock
            a = np.zeros((5, 2))
            a[:, 1] = [0.9, 0.8, 0.3, 0.2, 0.1]
            mock.predict_proba.return_value = a
            return mock

    def test_split_train_test_single_class_does_not_crash(self):
        """split_train_test should fall back to non-stratified split
        instead of raising ValueError when only one class is present."""
        classifier = self.MockRFClassifier()
        x = SAMPLE_DATA[FEATURES].copy()
        y_single_class = pd.Series([False, False, False, False, False])

        x_train, x_test, y_train, y_test = classifier.split_train_test(x, y_single_class)
        self.assertEqual(len(x_train) + len(x_test), len(x))
        self.assertEqual(len(y_train) + len(y_test), len(y_single_class))

    def test_split_train_test_all_positive_does_not_crash(self):
        """split_train_test should handle all-positive targets without crashing."""
        classifier = self.MockRFClassifier()
        x = SAMPLE_DATA[FEATURES].copy()
        y_all_positive = pd.Series([True, True, True, True, True])

        x_train, x_test, y_train, y_test = classifier.split_train_test(x, y_all_positive)
        self.assertEqual(len(x_train) + len(x_test), len(x))
        self.assertEqual(len(y_train) + len(y_test), len(y_all_positive))


class TestTrainModelsSaveOnFailure(CustomTestCase):
    """Test that TrainModels.run() always calls save_training_data() even on training failure."""

    @patch("greedybear.cronjobs.scoring.scoring_jobs.SCORERS")
    @patch("greedybear.cronjobs.scoring.scoring_jobs.get_features")
    @patch("greedybear.cronjobs.scoring.scoring_jobs.get_current_data")
    def test_save_training_data_called_on_scorer_failure(self, mock_get_data, mock_get_features, mock_scorers):
        """save_training_data must be called even when a scorer's train() raises an exception,
        otherwise the training pipeline enters a permanent failure loop."""
        mock_get_data.return_value = [
            {"value": "1.2.3.4", "last_seen": "2024-01-02", "interaction_count": 5},
        ]

        training_df = pd.DataFrame(
            {
                "value": ["1.2.3.4"],
                "interactions_on_eval_day": [3],
            }
        )
        mock_get_features.return_value = training_df

        failing_scorer = Mock()
        failing_scorer.trainable = True
        failing_scorer.name = "Failing Scorer"
        failing_scorer.train.side_effect = RuntimeError("training crashed")
        mock_scorers.__iter__ = Mock(return_value=iter([failing_scorer]))

        job = TrainModels()
        job.save_training_data = Mock()
        job.load_training_data = Mock(
            return_value=[
                {"value": "1.2.3.4", "last_seen": "2024-01-01", "interaction_count": 2, "feed_type": ["scanner"]},
            ]
        )

        with self.assertRaises(RuntimeError):
            job.run()

        # The critical assertion: save_training_data must be called despite the crash
        job.save_training_data.assert_called_once()


class TestFeatureImportanceLogging(CustomTestCase):
    """Test that RFModel logs feature importances after training."""

    IMPORTANCE_SAMPLE_DATA = pd.DataFrame(
        {
            "interactions_on_eval_day": [0, 1, 2, 0, 3, 1, 0, 2, 1, 3],
            "feature1": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            "feature2": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            "feature3": [122, 12, 0, 14, 87, 34, 56, 78, 90, 11],
            "honeypots": [
                "cowrie,dionaea",
                "dionaea,glutton",
                "cowrie",
                "glutton",
                "cowrie,dionaea,glutton",
                "cowrie",
                "dionaea",
                "glutton",
                "cowrie,dionaea",
                "dionaea,glutton",
            ],
        }
    )

    class MockRFModel(RFModel, Classifier):
        def __init__(self):
            super().__init__("Mock RF Model", "mock_score")

        @property
        def features(self):
            return FEATURES

        @property
        def untrained_model(self):
            mock = Mock()
            mock.feature_names_in_ = FEATURES
            mock.feature_importances_ = np.array([0.5, 0.3, 0.15, 0.02, 0.02, 0.01])
            mock.fit.return_value = mock

            a = np.zeros((10, 2))
            a[:, 1] = [0.9, 0.8, 0.3, 0.2, 0.1, 0.7, 0.6, 0.4, 0.5, 0.3]
            mock.predict_proba.return_value = a

            return mock

    def test_feature_importances_logged(self):
        model = self.MockRFModel()
        model.log = Mock()
        model.save = Mock()

        model.train(self.IMPORTANCE_SAMPLE_DATA)

        logged_messages = [call.args[0] for call in model.log.info.call_args_list]

        self.assertTrue(any("Feature importances for" in msg for msg in logged_messages))
