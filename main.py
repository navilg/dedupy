#!/usr/bin/env python3
"""
Deduplicate media files across multiple directories with priority-based retention.
"""

import os
import sys
import hashlib
import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
from dataclasses import dataclass
import imagehash
from PIL import Image, UnidentifiedImageError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class FileInfo:
    """Information about a file for deduplication."""
    path: Path
    size: int
    dir_priority: int
    md5_first: Optional[str] = None
    md5_last: Optional[str] = None
    sha256_first: Optional[str] = None
    sha256_last: Optional[str] = None
    phash: Optional[str] = None

class MediaDeduplicator:
    def __init__(self, directories_file: str, use_phash: bool = False):
        self.directories = self._load_directories(directories_file)
        self.use_phash = use_phash
        self.file_info_map: Dict[str, FileInfo] = {}
        self.duplicates_to_delete: List[Path] = []
        self.duplicate_groups: List[Dict[str, Any]] = []
        self.total_size_to_clean = 0
        
    def _load_directories(self, directories_file: str) -> List[Path]:
        """Load and validate directories from file."""
        if not os.path.exists(directories_file):
            raise FileNotFoundError(f"Directories file '{directories_file}' not found")
            
        directories = []
        with open(directories_file, 'r') as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    dir_path = Path(line)
                    if not dir_path.exists():
                        logger.warning(f"Directory {i} '{line}' does not exist, skipping")
                        continue
                    if not dir_path.is_dir():
                        logger.warning(f"Path {i} '{line}' is not a directory, skipping")
                        continue
                    directories.append(dir_path.resolve())
        
        if not directories:
            raise ValueError("No valid directories found in the input file")
            
        logger.info(f"Loaded {len(directories)} directories with priorities")
        return directories
    
    def _calculate_partial_hash(self, file_path: Path, start: int, size: int, hash_func) -> str:
        """Calculate hash of a portion of a file."""
        try:
            with open(file_path, 'rb') as f:
                f.seek(start)
                data = f.read(size)
                return hash_func(data).hexdigest()
        except (IOError, OSError) as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return ""
    
    def _calculate_phash(self, file_path: Path) -> Optional[str]:
        """Calculate perceptual hash for media files."""
        try:
            if file_path.suffix.lower() in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']:
                img = Image.open(file_path)
                return str(imagehash.average_hash(img))
            # For video files, you might want to extract a frame and hash it
            # This is a simplified version
            return None
        except (IOError, OSError, UnidentifiedImageError) as e:
            logger.warning(f"Could not calculate phash for {file_path}: {e}")
            return None
    
    def _get_file_info(self, file_path: Path, dir_priority: int) -> FileInfo:
        """Get file information including hashes."""
        size = file_path.stat().st_size
        file_info = FileInfo(file_path, size, dir_priority)
        
        chunk_size = 5 * 1024 * 1024  # 5MB
        
        # Calculate first 5MB hashes
        if size > 0:
            file_info.md5_first = self._calculate_partial_hash(
                file_path, 0, min(chunk_size, size), hashlib.md5
            )
            file_info.sha256_first = self._calculate_partial_hash(
                file_path, 0, min(chunk_size, size), hashlib.sha256
            )
        
        # Calculate last 5MB hashes
        if size > chunk_size:
            file_info.md5_last = self._calculate_partial_hash(
                file_path, max(0, size - chunk_size), chunk_size, hashlib.md5
            )
            file_info.sha256_last = self._calculate_partial_hash(
                file_path, max(0, size - chunk_size), chunk_size, hashlib.sha256
            )
        
        # Calculate perceptual hash if enabled
        if self.use_phash:
            file_info.phash = self._calculate_phash(file_path)
        
        return file_info
    
    def _get_file_signature(self, file_info: FileInfo) -> str:
        """Generate a unique signature for file comparison."""
        if self.use_phash and file_info.phash:
            return f"phash:{file_info.phash}"
        else:
            return (
                f"size:{file_info.size}:"
                f"md5_first:{file_info.md5_first}:"
                f"md5_last:{file_info.md5_last}:"
                f"sha256_first:{file_info.sha256_first}:"
                f"sha256_last:{file_info.sha256_last}"
            )
    
    def scan_files(self):
        """Scan all files in directories and identify duplicates."""
        logger.info("Starting file scan...")
        
        # First pass: collect all file information
        for dir_priority, directory in enumerate(self.directories):
            logger.info(f"Scanning directory {directory} (priority {dir_priority})")
            
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = Path(root) / file
                    try:
                        file_info = self._get_file_info(file_path, dir_priority)
                        signature = self._get_file_signature(file_info)
                        self.file_info_map[str(file_path)] = file_info
                    except (IOError, OSError) as e:
                        logger.error(f"Error processing file {file_path}: {e}")
        
        logger.info(f"Scanned {len(self.file_info_map)} files")
        
        # Second pass: identify duplicates and group them
        signature_groups: Dict[str, List[FileInfo]] = {}
        for file_info in self.file_info_map.values():
            signature = self._get_file_signature(file_info)
            if signature not in signature_groups:
                signature_groups[signature] = []
            signature_groups[signature].append(file_info)
        
        # Process each group of duplicates
        for signature, files in signature_groups.items():
            if len(files) > 1:
                # Sort by priority (lowest priority number = highest priority)
                files_sorted = sorted(files, key=lambda x: x.dir_priority)
                
                # Keep the highest priority file, mark others for deletion
                kept_file = files_sorted[0]
                duplicates_to_delete = files_sorted[1:]
                
                # Add to deletion list
                for file_to_delete in duplicates_to_delete:
                    self.duplicates_to_delete.append(file_to_delete.path)
                    self.total_size_to_clean += file_to_delete.size
                
                # Store group information for detailed reporting
                group_info = {
                    "signature": signature,
                    "kept_file": {
                        "path": str(kept_file.path),
                        "size": kept_file.size,
                        "dir_priority": kept_file.dir_priority,
                        "directory": str(kept_file.path.parent)
                    },
                    "duplicates": [
                        {
                            "path": str(dup.path),
                            "size": dup.size,
                            "dir_priority": dup.dir_priority,
                            "directory": str(dup.path.parent)
                        }
                        for dup in duplicates_to_delete
                    ],
                    "total_duplicates": len(duplicates_to_delete),
                    "total_duplicate_size": sum(dup.size for dup in duplicates_to_delete)
                }
                self.duplicate_groups.append(group_info)
                
                logger.info(f"Found {len(files)} duplicates")
                logger.info(f"  Keeping: {kept_file.path}")
                for dup in duplicates_to_delete:
                    logger.info(f"  Marking for deletion: {dup.path}")
        
        logger.info(f"Found {len(self.duplicates_to_delete)} files to delete")
        logger.info(f"Total size to clean: {self._format_size(self.total_size_to_clean)}")
        logger.info(f"Found {len(self.duplicate_groups)} duplicate groups")
    
    def _format_size(self, size_bytes: float) -> str:
        """Format file size in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def save_scan_results(self):
        """Save scan results to files."""
        # Save list of files to delete
        with open('duplicates_to_delete.txt', 'w') as f:
            for file_path in self.duplicates_to_delete:
                f.write(f"{file_path}\n")
        
        # Save detailed report with kept files and their duplicates
        report = {
            "summary": {
                "total_files_scanned": len(self.file_info_map),
                "duplicates_found": len(self.duplicates_to_delete),
                "duplicate_groups": len(self.duplicate_groups),
                "total_size_to_clean": self.total_size_to_clean,
                "size_formatted": self._format_size(self.total_size_to_clean),
                "directories_processed": [str(path) for path in self.directories]
            },
            "duplicate_groups": self.duplicate_groups,
            "files_to_delete": [str(path) for path in self.duplicates_to_delete],
            "scan_settings": {
                "use_phash": self.use_phash,
                "hash_method": "perceptual_hash" if self.use_phash else "md5_sha256_partial",
                "directories_priority": [
                    {"path": str(path), "priority": i} 
                    for i, path in enumerate(self.directories)
                ]
            }
        }
        
        with open('deduplication_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also create a human-readable summary
        self._create_human_readable_summary(report)
        
        logger.info("Scan results saved to duplicates_to_delete.txt and deduplication_report.json")
    
    def _create_human_readable_summary(self, report: Dict[str, Any]):
        """Create a human-readable summary file."""
        with open('deduplication_summary.txt', 'w') as f:
            f.write("MEDIA DEDUPLICATION REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            f.write("SUMMARY:\n")
            f.write(f"Total files scanned: {report['summary']['total_files_scanned']}\n")
            f.write(f"Duplicate files found: {report['summary']['duplicates_found']}\n")
            f.write(f"Duplicate groups: {report['summary']['duplicate_groups']}\n")
            f.write(f"Total space to reclaim: {report['summary']['size_formatted']}\n\n")
            
            f.write("DIRECTORIES (in priority order):\n")
            for i, dir_info in enumerate(report['scan_settings']['directories_priority']):
                f.write(f"  {i+1}. {dir_info['path']} (Priority: {dir_info['priority']})\n")
            f.write("\n")
            
            f.write("DUPLICATE GROUPS DETAILS:\n")
            f.write("-" * 50 + "\n")
            
            for i, group in enumerate(report['duplicate_groups'], 1):
                f.write(f"\nGROUP {i}:\n")
                f.write(f"Signature: {group['signature'][:100]}...\n")
                f.write(f"Kept file: {group['kept_file']['path']}\n")
                f.write(f"  Size: {self._format_size(group['kept_file']['size'])}\n")
                f.write(f"  Directory priority: {group['kept_file']['dir_priority']}\n")
                
                f.write(f"Duplicates to delete ({group['total_duplicates']} files):\n")
                for j, dup in enumerate(group['duplicates'], 1):
                    f.write(f"  {j}. {dup['path']}\n")
                    f.write(f"     Size: {self._format_size(dup['size'])}\n")
                    f.write(f"     Directory priority: {dup['dir_priority']}\n")
                
                f.write(f"Total duplicate size in group: {self._format_size(group['total_duplicate_size'])}\n")
            
            f.write(f"\nTOTAL FILES TO DELETE: {len(report['files_to_delete'])}\n")
            f.write(f"TOTAL SPACE TO RECLAIM: {report['summary']['size_formatted']}\n")
    
    def delete_files(self):
        """Delete files identified during scan."""
        if not os.path.exists('duplicates_to_delete.txt'):
            raise FileNotFoundError("Scan results not found. Run scan action first.")
        
        # Load files to delete
        files_to_delete = []
        with open('duplicates_to_delete.txt', 'r') as f:
            for line in f:
                path = Path(line.strip())
                if path.exists():
                    files_to_delete.append(path)
        
        logger.info(f"Loaded {len(files_to_delete)} files to delete")
        
        # Delete files
        deleted_count = 0
        deleted_size = 0
        
        for file_path in files_to_delete:
            try:
                file_size = file_path.stat().st_size
                file_path.unlink()
                deleted_count += 1
                deleted_size += file_size
                logger.info(f"Deleted: {file_path}")
            except (IOError, OSError) as e:
                logger.error(f"Error deleting {file_path}: {e}")
        
        # Create deletion report
        deletion_report = {
            "deleted_files_count": deleted_count,
            "deleted_files_size": deleted_size,
            "deleted_size_formatted": self._format_size(deleted_size),
            "failed_to_delete": len(files_to_delete) - deleted_count,
            "deleted_files": [str(path) for path in files_to_delete if not path.exists()]
        }
        
        with open('deletion_report.json', 'w') as f:
            json.dump(deletion_report, f, indent=2)
        
        logger.info(f"Successfully deleted {deleted_count} files")
        logger.info(f"Freed space: {self._format_size(deleted_size)}")
        logger.info("Deletion report saved to deletion_report.json")

def main():
    parser = argparse.ArgumentParser(description="Deduplicate media files across directories")
    parser.add_argument("directories_file", help="File containing list of directories (one per line)")
    parser.add_argument("--action", choices=['scan', 'delete'], required=True,
                       help="Action to perform: scan or delete")
    parser.add_argument("--phash", action='store_true', default=False,
                       help="Use perceptual hash instead of MD5/SHA256")
    parser.add_argument("--verbose", action='store_true', help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        dedup = MediaDeduplicator(args.directories_file, args.phash)
        
        if args.action == 'scan':
            dedup.scan_files()
            dedup.save_scan_results()
        elif args.action == 'delete':
            dedup.delete_files()
    
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()