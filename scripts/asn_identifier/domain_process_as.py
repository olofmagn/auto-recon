import argparse
import sys
import os 
import logging
import socket

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipwhois import IPWhois
from typing import List, Optional, TextIO

BANNER = r"""
            _____ _   _   _     _            _   _  __ _           
     /\    / ____| \ | | (_)   | |          | | (_)/ _(_)          
    /  \  | (___ |  \| |  _  __| | ___ _ __ | |_ _| |_ _  ___ _ __ 
   / /\ \  \___ \| . ` | | |/ _` |/ _ \ '_ \| __| |  _| |/ _ \ '__|
  / ____ \ ____) | |\  | | | (_| |  __/ | | | |_| | | | |  __/ |   
 /_/    \_\_____/|_| \_| |_|\__,_|\___|_| |_|\__|_|_| |_|\___|_|   
                                                                   
"""
class LoggingManager:
    """
    Initialize the logger instance

    Returns:
    - The logger associated with this module
    """
    def __init__(self, name: str ="ASNIdentifier", level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def get_logger(self):
        return self.logger

class ASDataProcessor:
    def __init__(self, domain:str=None, domain_file: Optional[str]=None, output_file: Optional[str]=None, asn_list: str=None, threads: int=4, retries: int=4):
        """
        Initialize all objects for reading, writing and domain iteration

        Args:
        - domain (str): domains to process
        - domain_file (str): domain file to process
        - output_file (str): output file to write
        - asn_list (list[str]) list of asns
        - threads (int): number of threads
        - retries (int): number of tries before assigning N/A to the domain
        - logger (obj): logger object
        """
        self.domain = domain
        self.domain_file= domain_file
        self.output_file = output_file
        self.asn_list = asn_list
        self.threads = threads
        self.retries = retries
        self.logger = LoggingManager().get_logger()

    def load_domains_from_a_file(self) -> int:
        """
        Helper method that loads a file to iterate domains
        """
        try:
            with open(self.domain_file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError as e:
            self.logger.info(f"File not found. Please check file_path: {self.domain_file}")
            sys.exit(1)
        except IOError as e:
            self.logger.info(f"Unexpected error happened when reading the file")
            sys.exit(1)

    def count_and_save_asns(self, asn_list_count: List[str], output_file: Optional[str]) -> int:
        """
        Count and save the asns in a output_file specified by the user
        """
        if not asn_list_count:
            return 0

        normalized_asns = [''.join(asn) if isinstance(asn, list) else asn for asn in asn_list_count]
        asn_counter = Counter(normalized_asns)
        sorted_asns = sorted(asn_counter.items(),key=lambda x: x[1], reverse=True)

        try:
            with open(output_file, "w") as f:
                lines = [f"ASN: {asn} count: {count}\n" for asn, count in sorted_asns]
                f.writelines(lines)
                self.logger.info(f"Results saved to {output_file}")
        except IOError as e:
            self.logger.error(f"Unexpected error happended when writing to the file: {e}")

    def get_as_info(self, domain) -> str:
        """
         Fetch information about the ASN and associated information

         Args:
         - domain (str): the domain to query for asn info

         Return:
         - asn (List[str]): the asn of the domain
         """
        attempt = 0
        while attempt < self.retries:
            try:
                # IPWhois requries an initial IP-address for lookup
                ip_address = socket.gethostbyname(domain)
                obj = IPWhois(ip_address)
                # Retrieving and parsing whois information for an IP-address via HTTP
                as_info = obj.lookup_rdap()
                asn = as_info.get('asn')
                return asn
            except socket.gaierror as e:
                self.logger.error(f"DNS resolution error for domain {domain}: {e}")
            except Exception as e:
                self.logger.error(f"Error processing domain {domain}: {e}")

            attempt += 1
            self.logger.info(f"Retrying domain {domain}, attempt {attempt}/{self.retries}")
        return 'N/A'

    def process_domain(self, domain:str) -> str:
        """
        Processes a single domain and return AS information.

        Args:
        - domain (str): domain to process
        - num_threads (int): the number of threads
        """
        as_info = self.get_as_info(domain)

        if as_info == 'N/A':
            self.logger.warning(f"Skipping domain {domain} since no valid ASN found")
            return 0

        self.logger.info(f"Domain: {domain}, AS Number: {as_info}")
        return as_info

    def process_domains(self, domains:List[str]) -> List[str]:
        """
        Processes a list of domains and retrieves the AS number for each.
        Uses multi-threading to speed up the process. Skips domains with 'N/A' ASNs.

        Args:
        - domains (List[str]): A list of domains

        Returns:
        - ans_list (List[str]): A list of asns of the domains in the list
        """
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.process_domain, domain): domain for domain in domains}
            self.asn_list = []
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    asn = future.result()
                    # Make sure that we only get unique values
                    if asn is not None:
                        self.asn_list.append(str(asn))
                except Exception as e:
                    self.logger.error(f"Domain {domain} generated an exception: {e}")

            return self.asn_list

    def execute(self):
        """
        Execute logic based on file or string arguments from the user
        """
        results = []
        try:
            if self.domain:
                results.append(self.process_domain(self.domain))

            if self.domain_file:
                file_domains = self.load_domains_from_a_file()
                results.extend(self.process_domains(file_domains))

            if self.output_file and results:
                self.count_and_save_asns(results, self.output_file)

        except Exception as e:
            self.logger.critical(f"Critical failure in main execution: {e}")
            sys.exit(1)

class ArgumentParser:
    """
    Handles argument parsing
    """
    def __init__(self):
        self.parser = self.create_parser()

    def create_parser(self) -> argparse.ArgumentParser:
        """
        Configures the argument parser with expected arguments

        Returns: An instance of argparse.ArgumentParser
        """
        parser = argparse.ArgumentParser(
                description="Process domain data and/or a file list to identify AS numbers.",
                formatter_class=argparse.RawDescriptionHelpFormatter,
                epilog=BANNER
                )

        parser.add_argument('-d', '--domain',
                            type=str, 
                            help="Specify one domain to process."
                            )

        parser.add_argument('-l', '--list', 
                            type=str, 
                            help="Specify a file containing a list of domains to process."
                            )

        parser.add_argument('-o', '--output', 
                            type=str, 
                            help="Specify the output file to save the results.")

        parser.add_argument('-t', '--threads', 
                            type=int, default=5,
                            help="Specify the number of threads for parallel processing (default: 5)."
                            )

        parser.add_argument('-r', '--retries',
                            type=int,
                            help="The number of retries before proceed to next host"
                            )

        parser.add_argument('-v', '--verbose', 
                            action='store_true', 
                            help="Enable verbose output."
                            )
        return parser

    def parse_args(self) -> argparse.Namespace:
        return self.parser.parse_args()

class AsnApp:
    def __init__(self):
        """
        Initialize the application, including argument parsing and searcher
        """
        parser = ArgumentParser()
        self.args = parser.parse_args()
        
        if not self.args.domain and not self.args.list:
            print("Please use a string -d or -l for file domain iteration. Use -h to see available options")
            sys.exit(1)

        self.iterator = ASDataProcessor(domain=self.args.domain, domain_file=self.args.list,output_file=self.args.output,asn_list=None,threads=self.args.threads,retries=3)

    def run(self):
        """
        Runs the main application
        """
        self.iterator.execute()

def main():
    """
    The entry point of the application
    """
    try:
        app = AsnApp()
        app.run()
    except KeyboardInterrupt: 
        print("\nOperation cancelled by the user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
