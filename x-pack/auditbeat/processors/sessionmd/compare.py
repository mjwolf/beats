import json
import os
from deepdiff import DeepDiff

# Load JSON data from file
def load_json(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

# Compare two JSON files and return the differences
def compare_json(file1, file2):
    json1 = load_json(file1)
    json2 = load_json(file2)

    diff = DeepDiff(json1, json2, ignore_order=True).pretty()
    return diff

# Main function
if __name__ == "__main__":
    file1 = os.getenv("FILE1") if "FILE1" in os.environ else "process.json"
    file2 = os.getenv("FILE2") if "FILE2" in os.environ else "reference.json"
    
    # Get differences
    differences = compare_json(file1, file2)
    
    if differences:
        print(f"{file1} is ORIGINAL\n{file2} is CHANGED")
        print("Differences found:")
        print(differences)
    else:
        print("The JSON files are identical.")

