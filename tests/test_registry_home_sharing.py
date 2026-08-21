"""Two registry rows may name one folder. Two chains may not live in it.

WHY THIS FILE EXISTS. On 2026-08-21 registry.validate refused the whole config
the moment two rows shared a home string. When the dmux lane correctly
repointed the ops row onto homes/claude-mzansiedge, every consumer that loads
the registry died at once: Paul's accounts panel went empty and the model
menu's effort read n/a while he was mid ship.

Nothing was ambiguous. One folder, one chain in it. The check tested a proxy,
whether two rows share a string, rather than the property it defends, whether
two accounts could be READ FROM one directory.

The fast path assertion below is dmux's condition and is as important as the
behaviour: load() runs in many processes including the router, so the resolver
must be consulted ONLY on the path that used to raise.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from headroom import registry                                  # noqa: E402

MARKER = "auth-resident.json"
SCHEMA = "auth_resident@1"


class HomeSharing(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def _dir(self, name):
        path = os.path.join(self.temp.name, name)
        os.makedirs(path, exist_ok=True)
        return path

    def _chain(self, directory, account):
        """Record ACCOUNT's chain as resident in DIRECTORY."""
        with open(os.path.join(directory, MARKER), "w") as handle:
            json.dump({"schema": SCHEMA, "account": account}, handle)

    def _config(self, rows):
        return {"schema_version": 1, "accounts": rows}

    def _row(self, name, home):
        return {"name": name, "provider": "claude", "home": home}

    # ---- the outage --------------------------------------------------------

    def test_a_shared_home_with_one_chain_LOADS(self):
        """THE OUTAGE, as a test. Paul's panel must not die for this."""
        shared = self._dir("shared")
        self._chain(shared, "ops")
        config = self._config([self._row("ops", shared),
                               self._row("mzansiedge", shared)])
        with mock.patch.object(registry, "_estate_credloc",
                               return_value=_FakeCredloc({"ops": shared})):
            registry.validate(config)

    def test_two_chains_in_one_directory_STILL_REFUSES(self):
        """THE MUTANT THIS GUARD EXISTS FOR. The guard must still bite."""
        shared = self._dir("shared")
        config = self._config([self._row("ops", shared),
                               self._row("mzansiedge", shared)])
        with mock.patch.object(registry, "_estate_credloc",
                               return_value=_FakeCredloc({"ops": shared,
                                                          "mzansiedge": shared})):
            with self.assertRaises(registry.RegistryError) as caught:
                registry.validate(config)
        self.assertIn("more than one account", str(caught.exception))

    def test_without_the_resolver_it_refuses_exactly_as_before(self):
        """Fail closed. A registry that cannot be proved safe must not load."""
        shared = self._dir("shared")
        config = self._config([self._row("ops", shared),
                               self._row("mzansiedge", shared)])
        with mock.patch.object(registry, "_estate_credloc", return_value=None):
            with self.assertRaises(registry.RegistryError) as caught:
                registry.validate(config)
        self.assertIn("already used by another account", str(caught.exception))

    # ---- dmux's cost condition ---------------------------------------------

    def test_the_resolver_is_NOT_consulted_when_no_home_is_shared(self):
        """load() runs in many processes, the router included.

        While no two rows share a string this must cost exactly what it always
        did, so the resolver may not be touched at all. Asserting the call
        count is the only way this stays true as the file changes."""
        rows = [self._row("ops", self._dir("a")),
                self._row("mzansiedge", self._dir("b"))]
        with mock.patch.object(registry, "_estate_credloc") as loader:
            registry.validate(self._config(rows))
        loader.assert_not_called()

    # NO LIVE CONFIG TEST HERE, deliberately. The suite redirects the config
    # path to a temp directory, which is correct isolation, so a test calling
    # registry.load() would assert the harness rather than the code. That the
    # estate's real config loads again was proved directly against the live
    # path at 13:56Z and is recorded in the receipt; putting it here would
    # only make this suite flip whenever the registry changes.


class _FakeCredloc:
    """resolve() answering from a name to directory map, like credloc does."""

    def __init__(self, where):
        self._where = where

    def resolve(self, row, all_rows):
        directory = self._where.get(row.get("name"))
        return {"kind": "resident" if directory else "none", "dir": directory}


if __name__ == "__main__":
    unittest.main()
