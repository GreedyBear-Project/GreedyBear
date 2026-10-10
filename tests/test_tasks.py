from unittest.mock import patch

from greedybear.cronjobs.exceptions import ElasticServerDownError

from . import CustomTestCase


class TestExtractAllTrainingTrigger(CustomTestCase):
    """Test that extract_all triggers training once the extraction has completed the previous day."""

    @patch("greedybear.tasks.extract_honeypot_payloads")
    @patch("greedybear.tasks.train_and_update")
    @patch("greedybear.cronjobs.extract.ExtractionJob")
    def test_triggers_training_when_day_completed(self, mock_job, mock_train, mock_payload):
        mock_job.return_value.pipeline.day_completed = True

        from greedybear.tasks import extract_all

        extract_all()

        mock_job.return_value.execute.assert_called_once()
        mock_train.assert_called_once()
        mock_payload.assert_called_once()

    @patch("greedybear.tasks.extract_honeypot_payloads")
    @patch("greedybear.tasks.train_and_update")
    @patch("greedybear.cronjobs.extract.ExtractionJob")
    def test_does_not_trigger_training_when_day_not_completed(self, mock_job, mock_train, mock_payload):
        mock_job.return_value.pipeline.day_completed = False

        from greedybear.tasks import extract_all

        extract_all()

        mock_job.return_value.execute.assert_called_once()
        mock_train.assert_not_called()
        mock_payload.assert_called_once()

    @patch("greedybear.tasks.extract_honeypot_payloads")
    @patch("greedybear.tasks.train_and_update")
    @patch("greedybear.cronjobs.extract.ExtractionJob")
    def test_does_not_trigger_training_when_extraction_fails(self, mock_job, mock_train, mock_payload):
        mock_job.return_value.execute.side_effect = ElasticServerDownError("elastic is down")

        from greedybear.tasks import extract_all

        with self.assertRaises(ElasticServerDownError):
            extract_all()

        mock_train.assert_not_called()


class TestTasks(CustomTestCase):
    """Test other tasks execution paths to ensure correct class instantiation and execution."""

    def test_simple_wrapper_tasks(self):
        """Use parameterized testing for simple wrappers that only call execute()."""
        tasks_to_test = [
            ("monitor_honeypots", "greedybear.cronjobs.monitor_honeypots.MonitorHoneypots"),
            ("monitor_logs", "greedybear.cronjobs.monitor_logs.MonitorLogs"),
            ("clean_up_db", "greedybear.cronjobs.cleanup.CleanUp"),
            ("clean_up_trending_buckets", "greedybear.cronjobs.bucket_cleanup.TrendingBucketCleanupCron"),
            ("get_mass_scanners", "greedybear.cronjobs.mass_scanners.MassScannersCron"),
            ("get_whatsmyip", "greedybear.cronjobs.whatsmyip.WhatsMyIPCron"),
            ("extract_firehol_lists", "greedybear.cronjobs.firehol.FireHolCron"),
            ("get_tor_exit_nodes", "greedybear.cronjobs.tor_exit_nodes.TorExitNodesCron"),
            ("enrich_threatfox", "greedybear.cronjobs.enrichment.threatfox_feed.ThreatFoxCron"),
            ("enrich_abuseipdb", "greedybear.cronjobs.enrichment.abuseipdb_feed.AbuseIPDBCron"),
            ("extract_honeypot_payloads", "greedybear.cronjobs.payload_extraction.PayloadExtractionJob"),
        ]

        from greedybear import tasks

        for task_name, class_path in tasks_to_test:
            with self.subTest(task=task_name), patch(f"{class_path}.execute") as mock_execute:
                task_func = getattr(tasks, task_name)
                task_func()
                mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.scoring.scoring_jobs.UpdateScores")
    @patch("greedybear.cronjobs.scoring.scoring_jobs.TrainModels")
    def test_train_and_update(self, mock_train_models_class, mock_update_scores_class):
        mock_trainer_instance = mock_train_models_class.return_value

        def mock_execute():
            mock_trainer_instance.current_data = "mock_data_transfer"

        mock_trainer_instance.execute.side_effect = mock_execute
        mock_updater_instance = mock_update_scores_class.return_value

        from greedybear.tasks import train_and_update

        train_and_update()

        mock_trainer_instance.execute.assert_called_once()
        self.assertEqual(mock_updater_instance.data, "mock_data_transfer")
        mock_updater_instance.execute.assert_called_once()

    @patch("greedybear.cronjobs.commands.cluster.ClusterCommandSequences.execute")
    @patch("greedybear.tasks.CLUSTER_COWRIE_COMMAND_SEQUENCES", True)
    def test_cluster_commands_enabled(self, mock_execute):
        from greedybear.tasks import cluster_commands

        cluster_commands()
        mock_execute.assert_called_once()

    @patch("greedybear.cronjobs.commands.cluster.ClusterCommandSequences.execute")
    @patch("greedybear.tasks.CLUSTER_COWRIE_COMMAND_SEQUENCES", False)
    def test_cluster_commands_disabled(self, mock_execute):
        from greedybear.tasks import cluster_commands

        cluster_commands()
        mock_execute.assert_not_called()
