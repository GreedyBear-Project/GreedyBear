from rest_framework import serializers


class CowrieSessionRequestSerializer(serializers.Serializer):
    query = serializers.CharField(
        max_length=256,
        help_text=(
            "The search term, can be an IP address, the SHA-256 hash of a command sequence, or a password. "
            'SHA-256 hashes should match command sequences generated using Python\'s `"\n".join(sequence)` format.'
        ),
    )
    include_similar = serializers.BooleanField(
        required=False,
        default=False,
        help_text=(
            "When `true`, expands the result to include all sessions that executed command sequences "
            "belonging to the same cluster(s) as command sequences found in the initial query result. "
            "Requires CLUSTER_COWRIE_COMMAND_SEQUENCES enabled in configuration."
        ),
    )
    include_credentials = serializers.BooleanField(
        required=False, default=False, help_text="When `true`, includes all credentials used across matching Cowrie sessions."
    )
    include_session_data = serializers.BooleanField(
        required=False, default=False, help_text="When `true`, includes detailed information about matching Cowrie sessions."
    )


class SessionDetailSerializer(serializers.Serializer):
    """A single matching Cowrie session."""

    time = serializers.DateTimeField(help_text="Session start time.")
    duration = serializers.FloatField(help_text="Session duration in seconds.")
    source = serializers.IPAddressField(help_text="Source IP address.")
    interactions = serializers.IntegerField()
    credentials = serializers.ListField(child=serializers.CharField(), help_text="Credentials used in this session, as `username | password`.")
    commands = serializers.CharField(help_text="Command sequence executed, newline-delimited. Empty when the session ran no commands.")


class CowrieSessionSerializer(serializers.Serializer):
    """Aggregated view of the sessions matching a query."""

    query = serializers.CharField(max_length=256, help_text="The query this result was produced for.")
    license = serializers.CharField(required=False, help_text="Present when a feed license is configured.")
    commands = serializers.ListField(child=serializers.CharField(), help_text="Unique command sequences, each newline-delimited.")
    sources = serializers.ListField(child=serializers.IPAddressField(), help_text="Unique source IP addresses.")
    credentials = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Unique credentials across all matching sessions. Present when `include_credentials` is true.",
    )
    sessions = SessionDetailSerializer(many=True, required=False, help_text="Present when `include_session_data` is true.")
