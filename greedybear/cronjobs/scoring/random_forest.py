import json
from abc import abstractmethod
from pathlib import Path

import pandas as pd
from sklearn.base import BaseEstimator
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor

from greedybear.cronjobs.scoring.consts import MULTI_VAL_FEATURES, NUM_FEATURES
from greedybear.cronjobs.scoring.ml_model import Classifier, MLModel, Regressor
from greedybear.cronjobs.scoring.utils import multi_label_encode
from greedybear.settings import ML_CONFIG_FILE


class RFModel(MLModel):
    """
    Abstract base class for Random Forest models.

    Provides common functionality for Random Forest Classifiers and Regressors,
    including feature preprocessing, model training, and evaluation.
    """

    @property
    def features(self) -> list[str]:
        """
        List of feature names required by the RandomFores models.

        Returns:
            list[str]: Names of all features needed for prediction,
                including both standard and multi-value features
        """
        return NUM_FEATURES + MULTI_VAL_FEATURES

    def train(self, df: pd.DataFrame) -> None:
        """
        Preprocesses features, splits data into train/test sets, and
        trains a Random Forest with optimized hyperparameters.
        Logs model performance using recall AUC score.

        Args:
            df: Training data containing features and
                'interactions_on_eval_day' target
        """
        self.log.info(f"start training {self.name}")

        x = df[self.features].copy()
        y = self.training_target(df).copy()

        for feature in MULTI_VAL_FEATURES:
            x = multi_label_encode(x, feature)

        x_train, x_test, y_train, y_test = self.split_train_test(x, y)

        self.model = self.untrained_model.fit(x_train, y_train)
        self.log.info(f"finished training {self.name} - recall AUC: {self.recall_auc(x_test, y_test):.4f}")

        feature_names = x_train.columns.tolist()

        importances = self.model.feature_importances_

        sorted_features = sorted(zip(feature_names, importances, strict=False), key=lambda pair: pair[1], reverse=True)
        importance_lines = "\n".join(f"  {name}: {score:.4f}" for name, score in sorted_features)

        self.log.info(f"Feature importances for {self.name}:\n{importance_lines}")
        self.save()

    @property
    @abstractmethod
    def untrained_model(self) -> BaseEstimator:
        """
        Create and configure an untrained Random Forest model.

        Returns:
            BaseEstimator: Configured but untrained scikit-learn Random Forest
                model with all hyperparameters set
        """


class RFClassifier(RFModel, Classifier):
    """
    Random Forest Classifier implementation for predicting IoC recurrence.

    Uses a Random Forest model with optimized hyperparameters.
    Predicts the probability of future interactions based on historical data.
    """

    def __init__(self):
        super().__init__("Random Forest Classifier", "recurrence_probability")

    @property
    def untrained_model(self) -> BaseEstimator:
        """
        Create and configure an untrained Random Forest Classifier.
        Hyperparameters were found by RandomSearchCV.

        Returns:
            BaseEstimator: Configured but untrained scikit-learn Random Forest
                Classifier with all hyperparameters set
        """
        with Path(ML_CONFIG_FILE).open() as f:
            config = json.load(f)

        params = config["RFClassifier"]
        # Convert class_weight keys from string to boolean
        if "class_weight" in params:
            params["class_weight"] = {(k.lower() == "true"): v for k, v in params["class_weight"].items() if k.lower() in ["true", "false"]}

        return RandomForestClassifier(**params)


class RFRegressor(RFModel, Regressor):
    """
    Random Forest Regressor implementation for predicting IoC interactions.

    Uses a Random Forest model with optimized hyperparameters.
    Predicts the number of interactions on the next day based on historical data.
    """

    def __init__(self):
        super().__init__("Random Forest Regressor", "expected_interactions")

    @property
    def untrained_model(self) -> BaseEstimator:
        """
        Create and configure an untrained Random Forest Regressor.
        Hyperparameters were found by RandomSearchCV.

        Returns:
            BaseEstimator: Configured but untrained scikit-learn Random Forest
                Regressor with all hyperparameters set
        """
        with Path(ML_CONFIG_FILE).open() as f:
            config = json.load(f)

        params = config["RFRegressor"]
        return RandomForestRegressor(**params)
