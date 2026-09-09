from rest_framework import serializers


class CowrieSessionRequestSerializer(serializers.Serializer):
    query = serializers.CharField(
        required=False,
        max_length=256,
        help_text=(
            "The search term, can be an IP address, the SHA-256 hash of a command sequence, or a password. "
            'SHA-256 hashes should match command sequences generated using Python\'s `"\n".join(sequence)` format. '
            "Mutually exclusive with `id`."
        ),
    )
    id = serializers.CharField(
        required=False,
        max_length=32,
        help_text=("Hex session ID, in the same format the payloads API returns. Mutually exclusive with `query`."),
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

    def validate_id(self, value: str) -> str:
        """Session IDs are stored as integers, so the hex has to parse."""
        try:
            int(value, 16)
        except ValueError as exc:
            raise serializers.ValidationError(f"Not a valid hex session ID: {value}") from exc
        return value

    def validate(self, data: dict) -> dict:
        """Exactly one of query or id, they select different things."""
        if bool(data.get("query")) == bool(data.get("id")):
            raise serializers.ValidationError("Provide either `query` or `id`, not both.")
        return data


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

    query = serializers.CharField(required=False, max_length=256, help_text="The query this result was produced for. Present when searching by `query`.")
    id = serializers.CharField(required=False, max_length=32, help_text="The session ID this result was produced for. Present when searching by `id`.")
    license = serializers.CharField(required=False, help_text="Present when a feed license is configured.")
    commands = serializers.ListField(child=serializers.CharField(), help_text="Unique command sequences, each newline-delimited.")
    sources = serializers.ListField(child=serializers.IPAddressField(), help_text="Unique source IP addresses.")
    credentials = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Unique credentials across all matching sessions. Present when `include_credentials` is true.",
    )
    sessions = SessionDetailSerializer(many=True, required=False, help_text="Present when `include_session_data` is true.")
