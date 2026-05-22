from collections import defaultdict

from django.db.models import Prefetch

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.commands.lsh import LSHConnectedComponents
from greedybear.models import IOC, CommandSequence, CowrieSession


def tokenize(sequence: list[str]) -> list[str]:
    """
    Tokenize a sequence of command strings into individual tokens.

    This function processes a list of command strings and splits them into tokens.
    It treats semicolons and whitespace as token separators.

    Args:
        sequence: A list of command strings to tokenize.
            Example: ["cd foo; ls", "ls -la"]

    Returns:
        List[str]: A list of tokens extracted from the input sequence.
            Example: ["cd", "foo", "ls", "ls", "-la"]
    """
    result = []
    for line in sequence:
        result.extend(line.replace(";", " ").split())
    return result


class ClusterCommandSequences(Cronjob):
    """
    A cronjob that clusters command sequences based on their similarity.

    This job processes all CommandSequence objects in the database, clusters them
    with locality-sensitive hashing (LSH) connected components over tokenized
    command sequences, and assigns cluster labels back to the objects. Commands
    within the same cluster represent similar execution patterns.
    """

    def _build_payload_urls_by_sequence_id(self, sequence_ids: list[int]) -> dict[int, set[str]]:
        """
        Build a mapping of command sequence IDs to payload URLs seen by related scanner IOCs.

        The relation path is:
        CommandSequence <- CowrieSession.source (scanner IOC) -> related_ioc (payload IOCs)
        """
        if not sequence_ids:
            return {}

        scanners = (
            IOC.objects.filter(cowriesession__commands_id__in=sequence_ids, scanner=True)
            .distinct()
            .only("id")
            .prefetch_related(
                Prefetch(
                    "related_ioc",
                    queryset=IOC.objects.filter(payload_request=True).only("id", "related_urls"),
                ),
                Prefetch(
                    "cowriesession_set",
                    queryset=CowrieSession.objects.filter(commands_id__in=sequence_ids).only("commands_id"),
                ),
            )
        )

        payload_urls_by_sequence_id: dict[int, set[str]] = defaultdict(set)
        for scanner in scanners:
            payload_urls = {payload_url for related_payload_ioc in scanner.related_ioc.all() for payload_url in related_payload_ioc.related_urls if payload_url}
            if not payload_urls:
                continue

            for session in scanner.cowriesession_set.all():
                if session.commands_id is not None:
                    payload_urls_by_sequence_id[session.commands_id].update(payload_urls)

        return payload_urls_by_sequence_id

    def _build_clustering_input(self, sequences: list[CommandSequence]) -> list[list[str]]:
        """
        Prepare tokenized inputs for clustering by combining commands with payload observables.
        """
        payload_urls_by_sequence_id = self._build_payload_urls_by_sequence_id([seq.id for seq in sequences if seq.id is not None])

        tokenized_sequences = []
        for seq in sequences:
            commands_for_clustering = list(seq.commands)
            sorted_payload_urls = sorted(payload_urls_by_sequence_id.get(seq.id, set()))
            commands_for_clustering.extend(f"PAYLOAD_REQUEST:{payload_url}" for payload_url in sorted_payload_urls)
            tokenized_sequences.append(tokenize(commands_for_clustering))

        return tokenized_sequences

    def run(self) -> None:
        """
        Workflow:
        1. Retrieve all command sequences with their current cluster assignments
        2. Early exit if no sequences exist
        3. Build tokenized clustering input and compute LSH connected components
        4. Identify sequences whose cluster assignment has changed
        5. Perform batched bulk updates for changed sequences only
        """
        sequences = list(CommandSequence.objects.order_by("id").only("id", "commands", "cluster"))
        if not sequences:
            self.log.info("no sequences found to cluster")
            return
        self.log.info(f"clustering {len(sequences)} command sequences")
        tokenized_seqs = self._build_clustering_input(sequences)
        cluster_labels = LSHConnectedComponents().get_components(tokenized_seqs)
        seqs_to_update = []
        for seq, label in zip(sequences, cluster_labels, strict=False):
            if seq.cluster != label:
                seq.cluster = label
                seqs_to_update.append(seq)
        self.log.info(f"writing updated clusters for {len(seqs_to_update)} command sequences to DB")
        result = CommandSequence.objects.bulk_update(seqs_to_update, ["cluster"], batch_size=1000) if seqs_to_update else 0
        self.log.info(f"{result} command sequences were updated")
