# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from greedybear.consts import SHARE_TOKEN_SALT


def share_token_salt_for_user(user_id: int) -> str:
    """Derive a signing salt scoped to the user who created a share token."""
    return f"{SHARE_TOKEN_SALT}:{user_id}"
