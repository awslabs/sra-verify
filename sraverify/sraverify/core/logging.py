"""
Logging configuration for SRA Verify.
"""
import logging
import sys

# CRITICAL: Configure root logger FIRST to use stderr
# This prevents any logger from defaulting to stdout
root_logger = logging.getLogger()
# Remove any existing handlers from root logger
for handler in root_logger.handlers[:]:
    root_logger.removeHandler(handler)
# Add stderr handler to root logger
root_stderr_handler = logging.StreamHandler(sys.stderr)
root_stderr_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
root_logger.addHandler(root_stderr_handler)
root_logger.setLevel(logging.WARNING)  # Set root to WARNING to reduce noise

# Create sraverify logger
logger = logging.getLogger("sraverify")

# Create handlers
console_handler = logging.StreamHandler(sys.stderr)

# Create formatters
default_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
console_formatter = logging.Formatter(default_format)

# Add formatters to handlers
console_handler.setFormatter(console_formatter)

# Add handlers to logger
logger.addHandler(console_handler)

# Set default level
logger.setLevel(logging.INFO)

# Prevent sraverify logger from propagating to root (we handle it ourselves)
logger.propagate = False

# Configure boto3/botocore loggers to use stderr as well
# This prevents them from polluting stdout in MCP server context
boto_logger = logging.getLogger("boto3")
botocore_logger = logging.getLogger("botocore")
urllib3_logger = logging.getLogger("urllib3")

# Set boto loggers to WARNING to reduce noise (they're very verbose)
boto_logger.setLevel(logging.WARNING)
botocore_logger.setLevel(logging.WARNING)
urllib3_logger.setLevel(logging.WARNING)

# Let boto loggers propagate to root (which now uses stderr)
boto_logger.propagate = True
botocore_logger.propagate = True
urllib3_logger.propagate = True

def configure_logging(debug=False):
    """
    Configure logging level based on debug flag.

    Args:
        debug: If True, set logging level to DEBUG, otherwise INFO
    """
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
        # Also enable debug for boto in debug mode if needed
        # boto_logger.setLevel(logging.DEBUG)
        # botocore_logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
