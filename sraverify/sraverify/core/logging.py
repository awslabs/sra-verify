"""
The shared ``sraverify`` logger.

Library code logs through this one named logger and configures nothing else.
Following the standard library-logging convention, importing the package adds a
single ``NullHandler`` and leaves the level unset: no handler on the root
logger is touched, no level is forced on boto3 or botocore, and nothing is
emitted unless the host application configures logging.

Where records go is the application's decision. The CLI makes it in
``sraverify.cli.configure_logging`` (stderr, ``ERROR`` by default, ``DEBUG``
with ``--debug``); an embedding application such as the MCP server makes its
own. Either way nothing here can write to stdout.
"""
import logging

logger = logging.getLogger("sraverify")

# Suppresses Python's "last resort" stderr handler when the host has configured
# nothing, so an unconfigured library caller sees no WARNING output it did not
# ask for.
logger.addHandler(logging.NullHandler())
