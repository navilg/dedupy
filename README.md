# Dedupy - A lightweight python script to deduplicate files

A Python script for deduplicating files across multiple directories with priority-based retention. 

## Features

* **Cross-directory deduplication:** Scan and remove duplicate files across multiple target directories
* **Priority-based retention:** Keep files from higher priority directories while removing duplicates from lower priority ones
* **Multiple hash methods:** Uses MD5, SHA256, and perceptual hashing (phash) for accurate duplicate detection
* **Partial hash calculation:** Efficient scanning by calculating partial file hashes (first and last chunks)
* **Configurable exclusions:** Automatically excludes system and metadata files (XMP, AAE, DB, etc.)

## Installation

```bash
# Clone the repository
git clone https://github.com/navilg/dedupy.git
cd dedupy

# Install dependencies
pip install -r requirements.txt
```

Required dependencies:
* Python 3.12+
* Pillow (PIL) for image processing
* imagehash for perceptual hashing

## Usage

**Scan directories for duplicate files**

Create a file called `directories.txt` listing directories to scan, one per line. List them in priority order: the first directory has highest priority, the last has lowest.

```bash
python main.py directories.txt --action scan
```

This will scan the directories and creates 3 files:

1. **deduplication_report.json:** Contains a detailed report of all duplicate files, their signature, file to be kept, duplicate files marked for deletion and total size saved after deletion in JSON format.
2. **deduplication_summary.txt:** Contains a detailed report of all duplicate files, their signature, file to be kept, duplicate files marked for deletion and total size saved after deletion in human-readable format.
3. **duplicates_to_delete.txt:** Contains list of duplicate files which are marked for deletion.

**Delete duplicate files**

Review the above 3 files which are generated after scan.

```bash
python main.py --action delete
```

This will generate file `deletion_report.json` which contains report of files deleted in JSON format.

### Advanced Options (inferred from context)

* `--phash`: Enable perceptual hashing for image comparison based on similarity during scan. It's slow.
* `--verbose`: Enable verbosity

## How It Works

1. **File Scanning**: Recursively scans all provided directories
2. **Hash Calculation**: Computes partial MD5, SHA256, and perceptual hashes
3. **Signature Generation**: Creates unique signatures for comparison
4. **Duplicate Detection**: Groups files with identical signatures
5. **Priority Sorting**: Sorts duplicates by directory priority
6. **Cleanup**: Deletes duplicates from lower priority directories

## File Priority

Directories are processed with priority-based retention. Files in directories with lower priority numbers are kept, while duplicates in higher-numbered directories are removed.

## Supported File Types

The tool handles various file formats through perceptual hashing and standard hash methods. System files and metadata files are automatically excluded.