"""Environment helpers for Claude seat identity."""


def seat_dir_from_env(environ):
    """Return the credential directory named by a Claude environment."""
    return (environ.get("CLAUDE_SECURESTORAGE_CONFIG_DIR")
            or environ.get("CLAUDE_CONFIG_DIR")
            or "")
