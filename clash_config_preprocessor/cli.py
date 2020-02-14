import pkg_resources

from clash_config_preprocessor.utils import process_config

try:
    __version__ = pkg_resources.get_distribution("clash_config_preprocessor").version
except pkg_resources.DistributionNotFound:
    __version__ = "dev"


def cli():
    import argparse

    parser = argparse.ArgumentParser(
        description="Process multiple clash configure files , integrate them to single clash configure file."
    )
    parser.add_argument("config")
    parser.add_argument(
        "-o", "--output", default=None, help="path to store generated config."
    )
    parser.add_argument(
        "-v", "--version", action="version", version="%(prog)s " + __version__
    )

    args = parser.parse_args()
    with open(args.config, "r", encoding="utf-8") as f:
        output = process_config(f)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
    else:
        print(output)


if __name__ == "__main__":
    cli()
