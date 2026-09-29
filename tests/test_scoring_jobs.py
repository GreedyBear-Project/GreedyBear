from unittest.mock import patch

import pandas as pd

from greedybear.cronjobs.scoring.scoring_jobs import TrainModels, UpdateScores

from . import CustomTestCase

PATCH_GET_CURRENT_DATA = "greedybear.cronjobs.scoring.scoring_jobs.get_current_data"
PATCH_GET_FEATURES = "greedybear.cronjobs.scoring.scoring_jobs.get_features"


class TrainModelsEmptyDataTestCase(CustomTestCase):
    @patch(PATCH_GET_CURRENT_DATA, return_value=[])
    def test_skips_cleanly_on_empty_current_data(self, _mock_data):
        # Empty input means there is nothing worth snapshotting: the last
        # good training data must be preserved, so save must NOT run here.
        trainer = TrainModels()
        with patch.object(TrainModels, "save_training_data") as mock_save:
            try:
                trainer.run()
            except ValueError as exc:
                self.fail(f"TrainModels.run() raised on empty data: {exc}")
        mock_save.assert_not_called()

    @patch(PATCH_GET_CURRENT_DATA)
    @patch(PATCH_GET_FEATURES, return_value=pd.DataFrame())
    def test_skips_cleanly_on_empty_features(self, _mock_features, mock_data):
        mock_data.return_value = [{"value": "1.2.3.4", "last_seen": "2026-09-01", "interaction_count": 1}]
        trainer = TrainModels()
        with (
            patch.object(
                TrainModels,
                "load_training_data",
                return_value=[{"value": "9.9.9.9", "last_seen": "2026-01-01", "interaction_count": 5, "feed_type": []}],
            ),
            patch.object(TrainModels, "save_training_data") as mock_save,
        ):
            trainer.run()
        # Snapshot must advance even on skipped nights, otherwise the next
        # trainable run would compute deltas against a frozen baseline.
        mock_save.assert_called_once()


class UpdateScoresEmptyDataTestCase(CustomTestCase):
    def test_skips_cleanly_on_empty_data(self):
        updater = UpdateScores()
        updater.data = []
        try:
            updater.run()
        except ValueError as exc:
            self.fail(f"UpdateScores.run() raised on empty data: {exc}")

    @patch(PATCH_GET_FEATURES, return_value=pd.DataFrame())
    def test_skips_cleanly_on_empty_features(self, _mock_features):
        updater = UpdateScores()
        updater.data = [{"value": "1.2.3.4", "last_seen": "2026-09-01"}]
        with patch.object(UpdateScores, "update_db") as mock_update:
            updater.run()
        mock_update.assert_not_called()
