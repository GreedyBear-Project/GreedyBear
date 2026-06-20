"""
This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
See the file 'LICENSE' for copying permission.

This file implements a custom QuarantineStorage backend (subclassing FileSystemStorage)
to restrict file saves to a quarantine directory and force a .vir extension.
"""

from django.conf import settings
from django.core.files.storage import FileSystemStorage


class QuarantineStorage(FileSystemStorage):
    """A file storage backend that ensures file names end with a '.vir' extension."""

    def __init__(self, *args, **kwargs):
        """Initialize the storage to QUARANTINE_DIR"""
        kwargs["location"] = settings.QUARANTINE_DIR
        super().__init__(*args, **kwargs)

    def get_available_name(self, name, max_length=None):
        """Get an available filename, ensuring it ends with '.vir'."""
        if not name.endswith(".vir"):
            name = name + ".vir"
        return super().get_available_name(name, max_length)
