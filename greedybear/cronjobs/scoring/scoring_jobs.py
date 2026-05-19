import json
from collections import defaultdict
from datetime import date

import pandas as pd
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories import IocRepository
from greedybear.cronjobs.scoring.random_forest import RFClassifier, RFRegressor
from greedybear.cronjobs.scoring.utils import (
    correlated_features,
    get_current_data,
    get_data_by_pks,
    get_features,
)
from greedybear.models import IOC
from greedybear.settings import ML_MODEL_DIRECTORY

SCORERS = [RFClassifier(), RFRegressor()]
TRAINING_DATA_FILENAME = "training_data.json"


class TrainingDataError(Exception):
    """Raised when there are issues with training data validity."""


class TrainModels(Cronjob):
    """
    Trains scoring models using historical IoC data.

    Manages training pipeline for scoring models by comparing current IoC data against
    previously stored training data. The class persists the current data after each run
    to serve as training data for the next iteration. Training requires historical data
    to calculate interaction deltas.
    """

    def __init__(self):
        super().__init__()
        self.storage = FileSystemStorage(location=ML_MODEL_DIRECTORY)
        self.current_data = None

    def save_training_data(self) -> None:
        """
        Save current IoC data to storage for future training runs.

        Saves the current dataset as JSON, overwriting any existing training data.
        Handles date serialization using default string conversion.
        """
        self.log.info("saving current data for future training")
        try:
            if self.storage.exists(TRAINING_DATA_FILENAME):
                self.storage.delete(TRAINING_DATA_FILENAME)
            self.storage.save(
                TRAINING_DATA_FILENAME,
                ContentFile(json.dumps(self.current_data, default=str)),
            )
        except Exception:
            self.log.exception("error saving training data")
            raise

    def load_training_data(self) -> list[dict]:
        """
        Load previously saved IoC data from storage.

        Returns:
            list: Previously stored IoC data, or empty list if loading fails.
        """
        self.log.info("loading training data from file system")
        try:
            with self.storage.open(TRAINING_DATA_FILENAME, "r") as file:
                return json.load(file)
        except Exception:
            self.log.exception("error loading training data")
            return []

    def run(self):
        """
        Execute the model training pipeline.

        Workflow:
        1. Fetch current IoC data from database
        2. Load previous training data from storage
        3. Verify training data predates current data
        4. Calculate interaction count deltas between datasets
        5. Extract features and prepare training data
        6. Check for correlated features
        7. Train and save each model
        8. Store current data for next training iteration

        Raises:
            TrainingDataError: If training data is not older than current data.
        """
        self.log.info("fetching current IoC data from DB")
        self.current_data = get_current_data()
        current_date = max(row["last_seen"] for row in self.current_data)

        self.log.info(f"current IoC data is from {current_date}, contains {len(self.current_data)} IoCs")

        training_data = self.load_training_data()
        if not training_data:
            self.log.warning("no training data found, skip training")
            self.save_training_data()
            return

        if not isinstance(training_data[0]["feed_type"], list):
            self.log.warning("training data outdated, skip training")
            self.save_training_data()
            return

        training_date = max(ioc["last_seen"] for ioc in training_data)
        training_ips = {ioc["value"]: ioc["interaction_count"] for ioc in training_data}
        self.log.info(f"training data is from {training_date}, contains {len(training_data)} IoCs")

        if not training_date < current_date:
            self.log.error("training data must be older than current data")
            raise TrainingDataError()

        current_ips = defaultdict(
            int,
            {ioc["value"]: ioc["interaction_count"] - training_ips.get(ioc["value"], 0) for ioc in self.current_data if ioc["last_seen"] > training_date},
        )

        self.log.info("extracting features from training data")
        training_df = get_features(training_data, training_date)
        training_df["interactions_on_eval_day"] = training_df["value"].map(current_ips)

        high_corr_pairs = correlated_features(training_df.select_dtypes(include="number"))
        if high_corr_pairs:
            self.log.debug("found highly correlated features")
        for f1, f2, corr in high_corr_pairs:
            self.log.debug(f"{f1} & {f2}: {corr:.2f}")

        try:
            for s in SCORERS:
                if s.trainable:
                    s.train(training_df)
        finally:
            self.save_training_data()


class UpdateScores(Cronjob):
    """
    Updates IoC scores by applying multiple scorers.

    Retrieves current IoC data from the database, if they are not handed over by previous job,
    extracts relevant features, applies a series of scorers,
    and writes the updated scores back to the database.
    Designed to run as a scheduled cronjob.
    """

    def __init__(self, ioc_repo=None):
        super().__init__()
        self.data = None
        self.ioc_repo = ioc_repo if ioc_repo is not None else IocRepository()

    def update_db(self, df: pd.DataFrame, iocs: set[IOC] | None = None) -> int:
        """
        Update IOC scores in the database based on new data from a DataFrame.

        This method handles two use cases:
        1. Full update: When no iocs are provided, fetches all qualifying IoCs from the database
           and updates their scores. IoCs missing from the new data have their scores reset to 0.
        2. Targeted update: When specific iocs are provided, updates only those IoCs
           without resetting scores for missing IoCs.

        Args:
            df: DataFrame containing new score data.
                Must have a 'value' column with IOC names/IPs and columns for each score.
            iocs: Optional set of specific IOC objects to update. If None, all qualifying
                  IoCs from the database will be updated and missing ones reset.

        Returns:
            int: The number of objects updated in the database.
        """
        self.log.info("begin updating scores")
        reset_old_scores = iocs is None
        score_names = [s.score_name for s in SCORERS]
        scores_by_ip = df.set_index("value")[score_names].to_dict("index")
        # If no IoCs were passed as an argument, fetch all IoCs via repository
        iocs = self.ioc_repo.get_scanners_for_scoring(score_names) if iocs is None else iocs
        iocs_to_update = []

        self.log.info(f"checking {len(iocs)} IoCs")
        for ioc in iocs:
            updated = False
            # Update scores if IP exists in new data
            if ioc.name in scores_by_ip:
                for score_name in score_names:
                    score = scores_by_ip[ioc.name][score_name]
                    if getattr(ioc, score_name) != score:
                        setattr(ioc, score_name, score)
                        updated = True
            # Reset old scores to 0
            elif reset_old_scores:
                for score_name in score_names:
                    if getattr(ioc, score_name) > 0:
                        setattr(ioc, score_name, 0)
                        updated = True
            if updated:
                iocs_to_update.append(ioc)
        self.log.info(f"writing updated scores for {len(iocs_to_update)} IoCs to DB")
        result = self.ioc_repo.bulk_update_scores(iocs_to_update, score_names)
        self.log.info(f"{result} IoCs were updated")
        return result

    def score_only(self, iocs: list[IOC]) -> int:
        """
        Update scores for only the specific IoCs provided.

        Args:
            iocs: List of IoC objects to update scores for

        Returns:
            int: Number of objects updated
        """
        iocs = set(iocs)
        primary_keys = {ioc.pk for ioc in iocs}
        data = get_data_by_pks(primary_keys)
        current_date = str(date.today())
        self.log.info("extracting features: score_only")
        df = get_features(data, current_date)
        for s in SCORERS:
            df = s.score(df)
        return self.update_db(df, iocs)

    def run(self):
        """
        Execute the score update pipeline.

        The pipeline consists of these steps:
        1. Fetch IoC data if not handed over
        2. Determine the most recent date in the dataset
        3. Extract features from IoC data
        4. Apply each scorer in sequence
        5. Write the updated scores back to the database

        The scorers are expected to add
        their respective score columns to the dataframe.
        """
        if self.data is None:
            self.log.info("no data handed over from previous task - fetching current IoC data from DB")
            self.data = get_current_data()
        current_date = max(row["last_seen"] for row in self.data)
        self.log.info("extracting features")
        df = get_features(self.data, current_date)
        for s in SCORERS:
            df = s.score(df)
        self.update_db(df)
