import argparse
import re
import logging
import sys
import json
import csv
from faker import Faker
import random

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DataPatternReplacer:
    """
    Identifies and replaces sensitive data patterns using regular expressions.
    Supports configurable replacement strings and Faker for realistic anonymization.
    """

    def __init__(self, patterns=None, replacements=None, use_faker=False, faker_locale='en_US'):
        """
        Initializes the DataPatternReplacer.

        Args:
            patterns (dict): A dictionary of regular expression patterns to identify sensitive data.
                             Keys are pattern names (e.g., "credit_card") and values are the regex strings.
            replacements (dict): A dictionary of replacement strings for each pattern.
                               Keys correspond to the pattern names in the 'patterns' dictionary,
                               and values are the replacement strings.  If use_faker is True, this can
                               contain Faker provider names.
            use_faker (bool): Whether to use Faker to generate realistic replacement data.
            faker_locale (str): The locale to use for Faker.
        """
        self.patterns = patterns or {}
        self.replacements = replacements or {}
        self.use_faker = use_faker
        self.faker = Faker(faker_locale) if use_faker else None

    def replace_patterns(self, data):
        """
        Replaces sensitive data patterns in the input data.

        Args:
            data (str): The input data to sanitize.

        Returns:
            str: The sanitized data.
        """
        try:
            for pattern_name, pattern in self.patterns.items():
                replacement = self.replacements.get(pattern_name)
                if replacement is None:
                    logging.warning(f"No replacement found for pattern: {pattern_name}. Skipping.")
                    continue

                if self.use_faker:
                    # Use Faker provider if specified in replacement string
                    if hasattr(self.faker, replacement):
                        data = re.sub(pattern, lambda x: str(getattr(self.faker, replacement)()), data)
                    else:
                        logging.warning(f"Faker provider '{replacement}' not found. Using default replacement string.")
                        data = re.sub(pattern, replacement, data)
                else:
                    data = re.sub(pattern, replacement, data)

            return data
        except Exception as e:
            logging.error(f"Error during pattern replacement: {e}")
            raise

def setup_argparse():
    """
    Sets up the argparse command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description='Sanitize data by replacing sensitive patterns.')
    parser.add_argument('input_file', type=str, help='Path to the input file.')
    parser.add_argument('output_file', type=str, help='Path to the output file.')
    parser.add_argument('--patterns_file', type=str, help='Path to the JSON file containing regex patterns and replacements.', required=True)
    parser.add_argument('--use_faker', action='store_true', help='Use Faker to generate realistic replacement data.')
    parser.add_argument('--faker_locale', type=str, default='en_US', help='Locale to use for Faker (default: en_US).')
    parser.add_argument('--input_format', type=str, choices=['text', 'json', 'csv'], default='text', help='Format of the input file (default: text).')
    parser.add_argument('--output_format', type=str, choices=['text', 'json', 'csv'], default='text', help='Format of the output file (default: text).')

    return parser


def load_patterns_from_json(patterns_file):
    """
    Loads patterns and replacements from a JSON file.

    Args:
        patterns_file (str): Path to the JSON file.

    Returns:
        tuple: A tuple containing patterns (dict) and replacements (dict).
    """
    try:
        with open(patterns_file, 'r') as f:
            data = json.load(f)
            patterns = data.get('patterns', {})
            replacements = data.get('replacements', {})
            return patterns, replacements
    except FileNotFoundError:
        logging.error(f"Patterns file not found: {patterns_file}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in patterns file: {patterns_file}")
        raise
    except Exception as e:
        logging.error(f"Error loading patterns from JSON: {e}")
        raise

def process_csv_file(input_file, output_file, replacer):
    """
    Processes a CSV file, sanitizing each field.

    Args:
        input_file (str): Path to the input CSV file.
        output_file (str): Path to the output CSV file.
        replacer (DataPatternReplacer): The DataPatternReplacer instance.
    """
    try:
        with open(input_file, 'r', newline='') as infile, open(output_file, 'w', newline='') as outfile:
            reader = csv.reader(infile)
            writer = csv.writer(outfile)
            for row in reader:
                sanitized_row = [replacer.replace_patterns(field) for field in row]
                writer.writerow(sanitized_row)
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
        raise
    except Exception as e:
        logging.error(f"Error processing CSV file: {e}")
        raise

def process_json_file(input_file, output_file, replacer):
    """
    Processes a JSON file, sanitizing string values.

    Args:
        input_file (str): Path to the input JSON file.
        output_file (str): Path to the output JSON file.
        replacer (DataPatternReplacer): The DataPatternReplacer instance.
    """
    try:
        with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
            data = json.load(infile)
            def sanitize_json(obj):
                if isinstance(obj, str):
                    return replacer.replace_patterns(obj)
                elif isinstance(obj, dict):
                    return {k: sanitize_json(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [sanitize_json(elem) for elem in obj]
                else:
                    return obj

            sanitized_data = sanitize_json(data)
            json.dump(sanitized_data, outfile, indent=4)  # Add indent for readability
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in input file: {input_file}")
        raise
    except Exception as e:
        logging.error(f"Error processing JSON file: {e}")
        raise


def main():
    """
    Main function to execute the data sanitization process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        patterns, replacements = load_patterns_from_json(args.patterns_file)
        replacer = DataPatternReplacer(patterns, replacements, args.use_faker, args.faker_locale)

        if args.input_format == 'text':
            try:
                with open(args.input_file, 'r') as infile, open(args.output_file, 'w') as outfile:
                    for line in infile:
                        sanitized_line = replacer.replace_patterns(line)
                        outfile.write(sanitized_line)
            except FileNotFoundError:
                logging.error(f"Input file not found: {args.input_file}")
                sys.exit(1)
            except Exception as e:
                logging.error(f"Error processing text file: {e}")
                sys.exit(1)

        elif args.input_format == 'csv':
            process_csv_file(args.input_file, args.output_file, replacer)

        elif args.input_format == 'json':
            process_json_file(args.input_file, args.output_file, replacer)
        else:
            logging.error(f"Invalid input format: {args.input_format}")
            sys.exit(1)

        logging.info(f"Data sanitization complete. Sanitized data written to: {args.output_file}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()