import argparse
import logging
import sys
import threading

from typing import Optional, TextIO
from concurrent.futures import ThreadPoolExecutor, as_completed

BANNER = r"""
      _       _         __ _ _ _
     | |     | |       / _(_) | |
   __| | __ _| |_ __ _| |_ _| | |_ ___ _ __
  / _` |/ _` | __/ _` |  _| | | __/ _ \ '__|
 | (_| | (_| | || (_| | | | | | ||  __/ |
  \__,_|\__,_|\__\__,_|_| |_|_|\__\___|_|

"""
class LoggingManager:
    """
    Initialize the logger instance

    Returns:
    - The logger associated with this module
    """
    def __init__(self, name: str ="ExtractUniqueDomains", level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def get_logger(self):
        return self.logger

class ExtractUniqueDomains:
    def __init__(self, input_file: str, output_file: Optional[TextIO]=None, threads: int=4):
        self.logger = LoggingManager().get_logger()
        self.input_file = input_file
        self.output_file = output_file
        self.threads = threads
    
    # Function to parallelize
    def process_line(self,line):
        if "SUCCESS" in line:
            domain = line.split()[0]
            return domain
        return 0

    def extract_unique_successful_domains(self):
        """
        Extracts unique successful domains from the input file and writes them to the output file.
        """
        # Initialize a set to store unique successful domains
        unique_domains = set()

        if not self.input_file:
            self.logger.info(f"Invalid file for index: {self.input_file}")
            return 0

        # Read the input file
        try:
            with open(self.input_file, "r") as f, ThreadPoolExecutor(self.threads) as executor:
                futures = [executor.submit(self.process_line, line) for line in f]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        unique_domains.add(result)
        except FileNotFoundError as e:
            self.logger.error(f"File Not found {self.input_file}")
            sys.exit(1)
        except IOError as e:
            self.logger.error(f"An unexpected error happend: {e}")
            sys.exit(1)

        # Write to input file
        if not self.output_file:
            return 0

        try:
            with open(self.output_file, "w") as f:
                for domain in sorted(unique_domains):  # Sorting for consistency
                    f.write(domain + "\n")
                if not self.output_file:
                    return 0
                    for domain in sorted(unique_domains):  # Sorting for consistency
                        f.write(domain + "\n")
                self.logger.info(f"Successfully written {len(unique_domains)} unique domains to {self.output_file}")
        except FileNotFoundError as e:
            self.logger.error(f"File not found error as: {e}")
        except IOError as e:
            self.logger.error(f"Unexpected error happend: {e}")

class ArgumentParser:
    def __init__(self):
        self.parser = self.create_parser()

    def create_parser(self) -> argparse.ArgumentParser:
        """
        Configures the argument parser with expected arguments

        Returns: An instance of argparse.ArgumentParser
        """
        parser = argparse.ArgumentParser(
                description="Filter unique succesful domains from a file",
                formatter_class=argparse.RawDescriptionHelpFormatter,
                epilog=BANNER
                )

        parser.add_argument('-i', '--input_file', 
                            required=True, type=str,
                            help='Path to the input file'
                            )

        parser.add_argument('-o', '--output_file',
                            help='Path to the output file'
                            )
        parser.add_argument('-t', '--threads',
                            type=int,
                            help='Number of threads to process success lines')

        return parser

    def parse_args(self) -> argparse.Namespace:
        return self.parser.parse_args()

class App:
    def __init__(self):
        """
        Initialize the application, including argument parsing and extractor
        """
        parser = ArgumentParser()
        self.args = parser.parse_args()
        self.iterator = ExtractUniqueDomains(input_file=self.args.input_file, output_file=self.args.output_file, threads=self.args.threads)

    def run(self):
        self.iterator.extract_unique_successful_domains()

def main():
    """
    The entry point of the application
    """
    try:
        app = App()
        app.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled by the user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
