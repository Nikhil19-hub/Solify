import json
import csv
import subprocess
import sys


def csvConversion(input_file, output_file):
    # Run Slither and get the output
    slitherCommand = f"slither {input_file} --json -"
    result = subprocess.run(slitherCommand, shell=True,
                            capture_output=True, text=True)
    data = json.loads(result.stdout)

    detectors = data["results"]["detectors"]

    # Write the output to a CSV file
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['id', 'check', 'impact', 'confidence',
                      'description', 'first_markdown_element']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for detector in detectors:
            writer.writerow({
                'id': detector['id'],
                'check': detector['check'],
                'impact': detector['impact'],
                'confidence': detector['confidence'],
                'description': detector['description'].strip(),
                'first_markdown_element': detector['first_markdown_element']
            })


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python slither_to_csv.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    csvConversion(input_file, output_file)
