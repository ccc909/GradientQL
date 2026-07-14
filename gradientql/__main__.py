"""Run the scanner as `python -m gradientql`; delegates to the CLI."""

import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="google.protobuf")
warnings.filterwarnings("ignore", category=FutureWarning, module="keras")
warnings.filterwarnings("ignore", message=r".*np\.object.*", category=FutureWarning)

from .scanner.cli import cli

cli()
