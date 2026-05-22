from hashlib import sha256
from unittest.mock import patch

from greedybear.cronjobs.commands.cluster import ClusterCommandSequences, tokenize
from greedybear.models import IOC, CommandSequence, CowrieSession, IocType

from . import CustomTestCase


class TokenizeTestCase(CustomTestCase):
    def test_tokenize_basic(self):
        """Test basic tokenization of simple commands"""
        input_seq = ["ls -l", "cd /home"]
        expected = ["ls", "-l", "cd", "/home"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_empty(self):
        """Test tokenization of empty sequences and strings"""
        self.assertEqual(tokenize([]), [])
        self.assertEqual(tokenize([""]), [])
        self.assertEqual(tokenize([" "]), [])
        self.assertEqual(tokenize(["", ""]), [])

    def test_tokenize_semicolons(self):
        """Test handling of semicolons in commands"""
        input_seq = ["ls -l;cd /home", "echo hello;pwd"]
        expected = ["ls", "-l", "cd", "/home", "echo", "hello", "pwd"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_multiple_spaces(self):
        """Test handling of multiple whitespace characters"""
        input_seq = ["ls   -l", "cd    /home"]
        expected = ["ls", "-l", "cd", "/home"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_mixed_delimiters(self):
        """Test handling of mixed semicolons and spaces"""
        input_seq = ["ls -l;  cd /home;pwd", "echo   hello ; ls"]
        expected = ["ls", "-l", "cd", "/home", "pwd", "echo", "hello", "ls"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_special_characters(self):
        """Test handling of special characters and paths"""
        input_seq = ["ls /usr/bin", "cd ../home", "echo $PATH"]
        expected = ["ls", "/usr/bin", "cd", "../home", "echo", "$PATH"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_quotes(self):
        """Test behavior with quoted strings (note: quotes are not preserved)"""
        input_seq = ['echo "hello world"', "ls 'Documents'"]
        expected = ["echo", '"hello', 'world"', "ls", "'Documents'"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_edge_cases(self):
        """Test edge cases with unusual inputs"""
        input_seq = [
            ";;;;;",  # Multiple semicolons
            "  ;  ;  ",  # Semicolons with spaces
            "\t\n",  # Special whitespace
            "cmd1;;cmd2",  # Multiple semicolons between commands
        ]
        expected = ["cmd1", "cmd2"]
        self.assertEqual(tokenize(input_seq), expected)

    def test_tokenize_mixed_content(self):
        """Test mixture of various command patterns"""
        input_seq = [
            "ls -l;cd /home;pwd",
            "echo hello   world",
            ";",
            "git commit -m 'update'",
        ]
        expected = [
            "ls",
            "-l",
            "cd",
            "/home",
            "pwd",
            "echo",
            "hello",
            "world",
            "git",
            "commit",
            "-m",
            "'update'",
        ]
        self.assertEqual(tokenize(input_seq), expected)


class ClusterCommandSequencesTestCase(CustomTestCase):
    """Tests for ClusterCommandSequences.run() — covers lines 46-60."""

    def _run_job(self, labels):
        """Helper: run ClusterCommandSequences with mocked get_components()."""
        with patch("greedybear.cronjobs.commands.cluster.LSHConnectedComponents") as mock_lsh_cls:
            mock_lsh_cls.return_value.get_components.return_value = labels
            ClusterCommandSequences().run()

    def test_run_empty_db(self):
        """Early return when no CommandSequence objects exist (lines 47-49)."""
        CommandSequence.objects.all().delete()
        with patch("greedybear.cronjobs.commands.cluster.LSHConnectedComponents") as mock_lsh:
            ClusterCommandSequences().run()
            # get_components must NOT be called — we returned before reaching it
            mock_lsh.return_value.get_components.assert_not_called()

    def test_run_no_label_changes(self):
        """seqs_to_update stays empty → bulk_update skipped (line 59 else branch)."""
        seqs = list(CommandSequence.objects.order_by("id"))
        current_labels = [s.cluster for s in seqs]
        self._run_job(current_labels)
        for seq, original_label in zip(seqs, current_labels, strict=False):
            seq.refresh_from_db()
            self.assertEqual(seq.cluster, original_label)

    def test_run_partial_label_changes(self):
        """Only the sequence whose label changed is written to DB (lines 53-59)."""
        # Delete inherited fixtures and work with a single, known sequence so
        # there is no ordering ambiguity between this call and run()'s queryset.
        CommandSequence.objects.all().delete()
        seq = CommandSequence.objects.create(
            first_seen=self.current_time,
            last_seen=self.current_time,
            commands=["ls -la"],
            commands_hash="testhash_partial",
            cluster=11,
        )
        self._run_job([999])  # single sequence, label changes 11 → 999
        seq.refresh_from_db()
        self.assertEqual(seq.cluster, 999)

    def test_run_all_labels_changed(self):
        """All sequences are updated when every label differs (lines 53-59)."""
        seqs = list(CommandSequence.objects.order_by("id"))
        new_labels = [777] * len(seqs)
        self._run_job(new_labels)
        for seq in seqs:
            seq.refresh_from_db()
            self.assertEqual(seq.cluster, 777)

    def test_run_bulk_update_called_with_correct_args(self):
        """bulk_update is called with field='cluster' and batch_size=1000 (line 59)."""
        seqs = list(CommandSequence.objects.order_by("id"))
        new_labels = [888] * len(seqs)
        with patch("greedybear.cronjobs.commands.cluster.LSHConnectedComponents") as mock_lsh_cls:
            mock_lsh_cls.return_value.get_components.return_value = new_labels
            with patch("greedybear.models.CommandSequence.objects.bulk_update") as mock_bulk:
                ClusterCommandSequences().run()
                mock_bulk.assert_called_once()
                call_args = mock_bulk.call_args
                self.assertIn("cluster", call_args[0][1])
                self.assertEqual(call_args[1].get("batch_size"), 1000)

    def test_run_adds_payload_request_observables_to_clustering_input(self):
        """
        Payload URLs related to scanner IOCs are added as synthetic commands before tokenization.
        """
        CowrieSession.objects.all().delete()
        CommandSequence.objects.all().delete()

        command_lines = ["uname -a"]
        command_sequence = CommandSequence.objects.create(
            first_seen=self.current_time,
            last_seen=self.current_time,
            commands=command_lines,
            commands_hash=sha256("\n".join(command_lines).encode()).hexdigest(),
            cluster=3,
        )
        scanner_ioc = IOC.objects.create(
            name="203.0.113.10",
            type=IocType.IP.value,
            scanner=True,
        )
        payload_ioc = IOC.objects.create(
            name="payload.example.com",
            type=IocType.DOMAIN.value,
            payload_request=True,
            related_urls=["http://payload.example.com/a.sh"],
        )
        scanner_ioc.related_ioc.add(payload_ioc)
        CowrieSession.objects.create(
            session_id=int("abcabcabcabc", 16),
            start_time=self.current_time,
            duration=1.0,
            source=scanner_ioc,
            commands=command_sequence,
        )

        with patch("greedybear.cronjobs.commands.cluster.LSHConnectedComponents") as mock_lsh_cls:
            mock_lsh_cls.return_value.get_components.return_value = [42]
            ClusterCommandSequences().run()

            clustering_input = mock_lsh_cls.return_value.get_components.call_args[0][0]

        expected_tokenized = tokenize([*command_lines, "PAYLOAD_REQUEST:http://payload.example.com/a.sh"])
        self.assertEqual(clustering_input, [expected_tokenized])
        command_sequence.refresh_from_db()
        self.assertEqual(command_sequence.cluster, 42)

    def test_run_ignores_payload_request_observables_from_non_scanner_sources(self):
        """
        Payload URLs linked through non-scanner sources are ignored for clustering input.
        """
        CowrieSession.objects.all().delete()
        CommandSequence.objects.all().delete()

        command_lines = ["uname -a"]
        command_sequence = CommandSequence.objects.create(
            first_seen=self.current_time,
            last_seen=self.current_time,
            commands=command_lines,
            commands_hash=sha256("\n".join(command_lines).encode()).hexdigest(),
            cluster=5,
        )
        non_scanner_ioc = IOC.objects.create(
            name="198.51.100.15",
            type=IocType.IP.value,
            scanner=False,
        )
        payload_ioc = IOC.objects.create(
            name="payload.example.net",
            type=IocType.DOMAIN.value,
            payload_request=True,
            related_urls=["http://payload.example.net/b.sh"],
        )
        non_scanner_ioc.related_ioc.add(payload_ioc)
        CowrieSession.objects.create(
            session_id=int("defdefdefdef", 16),
            start_time=self.current_time,
            duration=1.0,
            source=non_scanner_ioc,
            commands=command_sequence,
        )

        with patch("greedybear.cronjobs.commands.cluster.LSHConnectedComponents") as mock_lsh_cls:
            mock_lsh_cls.return_value.get_components.return_value = [77]
            ClusterCommandSequences().run()

            clustering_input = mock_lsh_cls.return_value.get_components.call_args[0][0]

        self.assertEqual(clustering_input, [tokenize(command_lines)])
        command_sequence.refresh_from_db()
        self.assertEqual(command_sequence.cluster, 77)

    def test_run_ignores_scanner_payload_ioc_with_empty_related_urls(self):
        """
        Scanner-linked payload IOCs without related URLs do not affect clustering input.
        """
        CowrieSession.objects.all().delete()
        CommandSequence.objects.all().delete()

        command_lines = ["whoami"]
        command_sequence = CommandSequence.objects.create(
            first_seen=self.current_time,
            last_seen=self.current_time,
            commands=command_lines,
            commands_hash=sha256("\n".join(command_lines).encode()).hexdigest(),
            cluster=1,
        )
        scanner_ioc = IOC.objects.create(
            name="198.51.100.50",
            type=IocType.IP.value,
            scanner=True,
        )
        payload_ioc = IOC.objects.create(
            name="payload-empty.example",
            type=IocType.DOMAIN.value,
            payload_request=True,
            related_urls=[],
        )
        scanner_ioc.related_ioc.add(payload_ioc)
        CowrieSession.objects.create(
            session_id=int("111111111111", 16),
            start_time=self.current_time,
            duration=1.0,
            source=scanner_ioc,
            commands=command_sequence,
        )

        with patch("greedybear.cronjobs.commands.cluster.LSHConnectedComponents") as mock_lsh_cls:
            mock_lsh_cls.return_value.get_components.return_value = [12]
            ClusterCommandSequences().run()
            clustering_input = mock_lsh_cls.return_value.get_components.call_args[0][0]

        self.assertEqual(clustering_input, [tokenize(command_lines)])
        command_sequence.refresh_from_db()
        self.assertEqual(command_sequence.cluster, 12)

    def test_run_orders_multiple_payload_iocs_deterministically(self):
        """
        Payload URL observables from multiple related IOCs are deterministically sorted.
        """
        CowrieSession.objects.all().delete()
        CommandSequence.objects.all().delete()

        command_lines = ["echo start"]
        command_sequence = CommandSequence.objects.create(
            first_seen=self.current_time,
            last_seen=self.current_time,
            commands=command_lines,
            commands_hash=sha256("\n".join(command_lines).encode()).hexdigest(),
            cluster=2,
        )
        scanner_ioc = IOC.objects.create(
            name="203.0.113.42",
            type=IocType.IP.value,
            scanner=True,
        )
        payload_ioc_1 = IOC.objects.create(
            name="payload-1.example",
            type=IocType.DOMAIN.value,
            payload_request=True,
            related_urls=["http://z.example/p.sh", "http://a.example/p.sh"],
        )
        payload_ioc_2 = IOC.objects.create(
            name="payload-2.example",
            type=IocType.DOMAIN.value,
            payload_request=True,
            related_urls=["http://m.example/p.sh"],
        )
        scanner_ioc.related_ioc.add(payload_ioc_2, payload_ioc_1)
        CowrieSession.objects.create(
            session_id=int("222222222222", 16),
            start_time=self.current_time,
            duration=1.0,
            source=scanner_ioc,
            commands=command_sequence,
        )

        with patch("greedybear.cronjobs.commands.cluster.LSHConnectedComponents") as mock_lsh_cls:
            mock_lsh_cls.return_value.get_components.return_value = [34]
            ClusterCommandSequences().run()
            clustering_input = mock_lsh_cls.return_value.get_components.call_args[0][0]

        expected_tokenized = tokenize(
            [*command_lines, "PAYLOAD_REQUEST:http://a.example/p.sh", "PAYLOAD_REQUEST:http://m.example/p.sh", "PAYLOAD_REQUEST:http://z.example/p.sh"]
        )
        self.assertEqual(clustering_input, [expected_tokenized])
        command_sequence.refresh_from_db()
        self.assertEqual(command_sequence.cluster, 34)

    def test_run_shared_payload_url_across_sequences_can_yield_identical_labels(self):
        """
        Shared payload URL observables are present for both sequences and can drive identical labels.
        """
        CowrieSession.objects.all().delete()
        CommandSequence.objects.all().delete()

        first_sequence = CommandSequence.objects.create(
            first_seen=self.current_time,
            last_seen=self.current_time,
            commands=["uname -a"],
            commands_hash=sha256(b"uname -a").hexdigest(),
            cluster=1001,
        )
        second_sequence = CommandSequence.objects.create(
            first_seen=self.current_time,
            last_seen=self.current_time,
            commands=["id -u"],
            commands_hash=sha256(b"id -u").hexdigest(),
            cluster=1002,
        )

        shared_payload = IOC.objects.create(
            name="shared-payload.example",
            type=IocType.DOMAIN.value,
            payload_request=True,
            related_urls=["http://shared.example/payload.sh"],
        )

        first_scanner = IOC.objects.create(name="10.0.0.11", type=IocType.IP.value, scanner=True)
        second_scanner = IOC.objects.create(name="10.0.0.12", type=IocType.IP.value, scanner=True)
        first_scanner.related_ioc.add(shared_payload)
        second_scanner.related_ioc.add(shared_payload)

        CowrieSession.objects.create(
            session_id=int("333333333333", 16),
            start_time=self.current_time,
            duration=1.0,
            source=first_scanner,
            commands=first_sequence,
        )
        CowrieSession.objects.create(
            session_id=int("444444444444", 16),
            start_time=self.current_time,
            duration=1.0,
            source=second_scanner,
            commands=second_sequence,
        )

        def labels_from_payload_urls(tokenized_sequences):
            payload_signature_to_label = {}
            labels = []
            for tokens in tokenized_sequences:
                payload_urls = tuple(sorted(token.split(":", maxsplit=1)[1] for token in tokens if token.startswith("PAYLOAD_REQUEST:") and ":" in token))
                label = payload_signature_to_label.setdefault(payload_urls, len(payload_signature_to_label) + 700)
                labels.append(label)
            return labels

        with patch("greedybear.cronjobs.commands.cluster.LSHConnectedComponents") as mock_lsh_cls:
            mock_lsh_cls.return_value.get_components.side_effect = labels_from_payload_urls
            ClusterCommandSequences().run()

        first_sequence.refresh_from_db()
        second_sequence.refresh_from_db()
        self.assertEqual(first_sequence.cluster, second_sequence.cluster)

    def test_run_deduplicates_and_filters_empty_payload_urls(self):
        """
        Duplicate and empty payload URLs from related payload IOCs are normalized before clustering.
        """
        CowrieSession.objects.all().delete()
        CommandSequence.objects.all().delete()

        command_lines = ["pwd"]
        command_sequence = CommandSequence.objects.create(
            first_seen=self.current_time,
            last_seen=self.current_time,
            commands=command_lines,
            commands_hash=sha256("\n".join(command_lines).encode()).hexdigest(),
            cluster=9,
        )
        scanner_ioc = IOC.objects.create(
            name="198.51.100.60",
            type=IocType.IP.value,
            scanner=True,
        )
        payload_ioc_1 = IOC.objects.create(
            name="payload-dedup-1.example",
            type=IocType.DOMAIN.value,
            payload_request=True,
            related_urls=["http://dup.example/a.sh", "", "http://dup.example/a.sh"],
        )
        payload_ioc_2 = IOC.objects.create(
            name="payload-dedup-2.example",
            type=IocType.DOMAIN.value,
            payload_request=True,
            related_urls=["http://dup.example/a.sh", "http://dup.example/b.sh"],
        )
        scanner_ioc.related_ioc.add(payload_ioc_1, payload_ioc_2)
        CowrieSession.objects.create(
            session_id=int("555555555555", 16),
            start_time=self.current_time,
            duration=1.0,
            source=scanner_ioc,
            commands=command_sequence,
        )

        with patch("greedybear.cronjobs.commands.cluster.LSHConnectedComponents") as mock_lsh_cls:
            mock_lsh_cls.return_value.get_components.return_value = [99]
            ClusterCommandSequences().run()
            clustering_input = mock_lsh_cls.return_value.get_components.call_args[0][0]

        expected_tokenized = tokenize([*command_lines, "PAYLOAD_REQUEST:http://dup.example/a.sh", "PAYLOAD_REQUEST:http://dup.example/b.sh"])
        self.assertEqual(clustering_input, [expected_tokenized])
        command_sequence.refresh_from_db()
        self.assertEqual(command_sequence.cluster, 99)
