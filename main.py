#!/usr/bin/env python3
"""
Advanced TTCN-3 Parser for PRINT_UC Analysis

This parser analyzes TTCN-3 files to identify functions and altsteps based on
their PRINT_UC usage patterns:

Part 1: Functions/altsteps WITHOUT any PRINT_UC statements
Part 2: Functions/altsteps WITH multiple objects in PRINT_UC OR multiple PRINT_UC statements

Version: 1.0
"""

import re
import sys
import os
import argparse
import json
from typing import List, Dict, Set, Tuple, NamedTuple
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum


class FunctionType(Enum):
    """Enumeration for different types of TTCN-3 callable entities."""
    FUNCTION = "function"
    ALTSTEP = "altstep"
    TESTCASE = "testcase"


@dataclass
class PrintUCOccurrence:
    """Represents a single PRINT_UC occurrence with its object count."""
    line_number: int
    object_count: int
    full_statement: str


@dataclass
class FunctionInfo:
    """Information about a function or altstep."""
    name: str
    function_type: FunctionType
    start_line: int
    end_line: int
    print_uc_occurrences: List[PrintUCOccurrence]
    
    @property
    def has_print_uc(self) -> bool:
        """Check if function has any PRINT_UC statements."""
        return len(self.print_uc_occurrences) > 0
    
    @property
    def has_multiple_print_uc(self) -> bool:
        """Check if function has multiple PRINT_UC statements."""
        return len(self.print_uc_occurrences) > 1
    
    @property
    def has_print_uc_with_multiple_objects(self) -> bool:
        """Check if function has PRINT_UC with multiple objects."""
        return any(occurrence.object_count > 1 for occurrence in self.print_uc_occurrences)
    
    @property
    def qualifies_for_part2(self) -> bool:
        """Check if function qualifies for Part 2 (multiple objects OR multiple PRINT_UC)."""
        return self.has_multiple_print_uc or self.has_print_uc_with_multiple_objects


class TTCN3Parser:
    """Advanced TTCN-3 parser for analyzing PRINT_UC usage patterns."""
    
    def __init__(self):
        # Regex patterns for parsing
        self.function_pattern = re.compile(
            r'^\s*(function|altstep|testcase)\s+(\w+)\s*\([^)]*\)(?:\s+runs\s+on\s+\w+)?\s*\{',
            re.MULTILINE
        )
        self.print_uc_pattern = re.compile(
            r'PRINT_UC\s*\([^)]*\)',
            re.DOTALL
        )
        
        # Patterns for filtering out comments and strings
        self.single_line_comment_pattern = re.compile(r'//.*$', re.MULTILINE)
        self.multi_line_comment_pattern = re.compile(r'/\*.*?\*/', re.DOTALL)
        self.string_literal_pattern = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
        
    def remove_comments_and_strings(self, content: str) -> Tuple[str, Dict[int, str]]:
        """
        Remove comments and string literals from content for accurate parsing.
        Returns cleaned content and a mapping of original positions.
        """
        # Store original lines for reference
        original_lines = content.split('\n')
        
        # Remove multi-line comments first
        content = self.multi_line_comment_pattern.sub(lambda m: ' ' * len(m.group(0)), content)
        
        # Remove single-line comments
        content = self.single_line_comment_pattern.sub(lambda m: ' ' * len(m.group(0)), content)
        
        # Replace string literals with spaces (preserve structure)
        content = self.string_literal_pattern.sub(lambda m: ' ' * len(m.group(0)), content)
        
        return content, {i + 1: line for i, line in enumerate(original_lines)}
    
    def find_matching_brace(self, content: str, start_pos: int) -> int:
        """Find the matching closing brace for a function/altstep."""
        brace_count = 0
        i = start_pos
        
        while i < len(content):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    return i
            i += 1
        
        return -1  # No matching brace found
    
    def count_print_uc_objects(self, print_uc_statement: str) -> int:
        """
        Count the number of objects in a PRINT_UC statement.
        Handles complex expressions, nested parentheses, and function calls.
        """
        # Extract content between PRINT_UC parentheses
        match = re.search(r'PRINT_UC\s*\((.*)\)', print_uc_statement, re.DOTALL)
        if not match:
            return 0
        
        content = match.group(1).strip()
        if not content:
            return 0
        
        # Split by commas, but respect parentheses nesting
        objects = []
        current_object = ""
        paren_depth = 0
        quote_depth = 0
        
        i = 0
        while i < len(content):
            char = content[i]
            
            if char == '"' and (i == 0 or content[i-1] != '\\'):
                quote_depth = 1 - quote_depth
            elif quote_depth == 0:
                if char == '(':
                    paren_depth += 1
                elif char == ')':
                    paren_depth -= 1
                elif char == ',' and paren_depth == 0:
                    objects.append(current_object.strip())
                    current_object = ""
                    i += 1
                    continue
            
            current_object += char
            i += 1
        
        # Add the last object
        if current_object.strip():
            objects.append(current_object.strip())
        
        return len(objects)
    
    def extract_print_uc_occurrences(self, function_body: str, function_start_line: int, 
                                   original_lines: Dict[int, str]) -> List[PrintUCOccurrence]:
        """Extract all PRINT_UC occurrences from a function body."""
        occurrences = []
        
        for match in self.print_uc_pattern.finditer(function_body):
            # Find line number by counting newlines up to match position
            lines_before = function_body[:match.start()].count('\n')
            line_number = function_start_line + lines_before
            
            full_statement = match.group(0)
            object_count = self.count_print_uc_objects(full_statement)
            
            occurrences.append(PrintUCOccurrence(
                line_number=line_number,
                object_count=object_count,
                full_statement=full_statement.replace('\n', ' ').strip()
            ))
        
        return occurrences
    
    def parse_functions(self, content: str) -> List[FunctionInfo]:
        """Parse all functions and altsteps from TTCN-3 content."""
        # Remove comments and strings for accurate parsing
        cleaned_content, original_lines = self.remove_comments_and_strings(content)
        
        functions = []
        
        for match in self.function_pattern.finditer(cleaned_content):
            function_type_str = match.group(1)
            function_name = match.group(2)
            
            # Determine function type
            if function_type_str == "function":
                function_type = FunctionType.FUNCTION
            elif function_type_str == "altstep":
                function_type = FunctionType.ALTSTEP
            elif function_type_str == "testcase":
                function_type = FunctionType.TESTCASE
            else:
                continue  # Skip unknown types
            
            # Find function body boundaries
            start_pos = match.end() - 1  # Position of opening brace
            end_pos = self.find_matching_brace(cleaned_content, start_pos)
            
            if end_pos == -1:
                continue  # Skip if no matching brace found
            
            # Extract function body
            function_body = cleaned_content[start_pos:end_pos + 1]
            
            # Calculate line numbers
            start_line = cleaned_content[:match.start()].count('\n') + 1
            end_line = cleaned_content[:end_pos].count('\n') + 1
            
            # Find PRINT_UC occurrences in the function body
            print_uc_occurrences = self.extract_print_uc_occurrences(
                function_body, start_line, original_lines
            )
            
            functions.append(FunctionInfo(
                name=function_name,
                function_type=function_type,
                start_line=start_line,
                end_line=end_line,
                print_uc_occurrences=print_uc_occurrences
            ))
        
        return functions
    
    def parse_file(self, file_path: str) -> List[FunctionInfo]:
        """Parse a single TTCN-3 file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            return self.parse_functions(content)
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return []
        except Exception as e:
            print(f"Error parsing file '{file_path}': {e}")
            return []
    
    def parse_directory(self, directory_path: str, recursive: bool = False) -> Dict[str, List[FunctionInfo]]:
        """Parse all TTCN-3 files in a directory."""
        results = {}
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Error: Directory '{directory_path}' does not exist.")
            return results
        
        # Use recursive globbing if requested
        if recursive:
            ttcn_files = list(directory.rglob("*.ttcn")) + list(directory.rglob("*.ttcn3"))
        else:
            ttcn_files = list(directory.glob("*.ttcn")) + list(directory.glob("*.ttcn3"))
        
        if not ttcn_files:
            search_type = "recursively" if recursive else ""
            print(f"No TTCN-3 files found {search_type} in '{directory_path}'.")
            return results
        
        print(f"Found {len(ttcn_files)} TTCN-3 files {'(recursive search)' if recursive else ''}")
        
        for file_path in ttcn_files:
            functions = self.parse_file(str(file_path))
            if functions:
                results[str(file_path)] = functions
        
        return results


class ResultFormatter:
    """Formats and displays parser results in a professional manner."""
    
    @staticmethod
    def format_function_info(func_info: FunctionInfo) -> str:
        """Format function information for display."""
        type_str = func_info.function_type.value
        print_uc_info = ""
        
        if func_info.print_uc_occurrences:
            print_uc_details = []
            for occurrence in func_info.print_uc_occurrences:
                print_uc_details.append(f"Line {occurrence.line_number}: {occurrence.object_count} objects")
            print_uc_info = f" (PRINT_UC: {', '.join(print_uc_details)})"
        
        return f"  {type_str} {func_info.name} [Lines {func_info.start_line}-{func_info.end_line}]{print_uc_info}"
    
    @staticmethod
    def print_results(results: Dict[str, List[FunctionInfo]]):
        """Print formatted results for both parts."""
        if not results:
            print("No TTCN-3 files found or parsed.")
            return
        
        print("=" * 80)
        print("TTCN-3 PARSER RESULTS")
        print("=" * 80)
        
        # Collect all functions from all files
        all_functions = []
        for file_path, functions in results.items():
            all_functions.extend(functions)
        
        if not all_functions:
            print("No functions or altsteps found.")
            return
        
        # Part 1: Functions/altsteps WITHOUT PRINT_UC
        part1_functions = [f for f in all_functions if not f.has_print_uc]
        
        print(f"\nPART 1: Functions/Altsteps WITHOUT PRINT_UC ({len(part1_functions)} found)")
        print("-" * 60)
        
        if part1_functions:
            # Group by file for better organization
            part1_by_file = {}
            for func in part1_functions:
                # Find which file this function belongs to
                for file_path, file_functions in results.items():
                    if func in file_functions:
                        if file_path not in part1_by_file:
                            part1_by_file[file_path] = []
                        part1_by_file[file_path].append(func)
                        break
            
            for file_path, functions in part1_by_file.items():
                print(f"\nFile: {os.path.basename(file_path)}")
                for func in sorted(functions, key=lambda x: x.start_line):
                    print(ResultFormatter.format_function_info(func))
        else:
            print("  None found.")
        
        # Part 2: Functions/altsteps WITH multiple PRINT_UC or multiple objects
        part2_functions = [f for f in all_functions if f.qualifies_for_part2]
        
        print(f"\nPART 2: Functions/Altsteps WITH multiple PRINT_UC objects or statements ({len(part2_functions)} found)")
        print("-" * 80)
        
        if part2_functions:
            # Group by file for better organization
            part2_by_file = {}
            for func in part2_functions:
                # Find which file this function belongs to
                for file_path, file_functions in results.items():
                    if func in file_functions:
                        if file_path not in part2_by_file:
                            part2_by_file[file_path] = []
                        part2_by_file[file_path].append(func)
                        break
            
            for file_path, functions in part2_by_file.items():
                print(f"\nFile: {os.path.basename(file_path)}")
                for func in sorted(functions, key=lambda x: x.start_line):
                    print(ResultFormatter.format_function_info(func))
                    
                    # Add detailed PRINT_UC analysis
                    if func.has_multiple_print_uc:
                        print(f"    → Reason: Multiple PRINT_UC statements ({len(func.print_uc_occurrences)})")
                    if func.has_print_uc_with_multiple_objects:
                        multi_obj_occurrences = [occ for occ in func.print_uc_occurrences if occ.object_count > 1]
                        print(f"    → Reason: PRINT_UC with multiple objects ({len(multi_obj_occurrences)} occurrences)")
                    
                    # Show detailed PRINT_UC statements
                    for occurrence in func.print_uc_occurrences:
                        print(f"    → {occurrence.full_statement}")
        else:
            print("  None found.")
        
        # Summary statistics
        print(f"\n" + "=" * 80)
        print("SUMMARY STATISTICS")
        print("=" * 80)
        total_functions = len(all_functions)
        functions_with_print = len([f for f in all_functions if f.has_print_uc])
        functions_without_print = len(part1_functions)
        functions_part2 = len(part2_functions)
        
        print(f"Total functions/altsteps analyzed: {total_functions}")
        print(f"Functions WITH PRINT_UC: {functions_with_print}")
        print(f"Functions WITHOUT PRINT_UC (Part 1): {functions_without_print}")
        print(f"Functions qualifying for Part 2: {functions_part2}")
        print(f"Files processed: {len(results)}")
    
    @staticmethod
    def export_results(results: Dict[str, List[FunctionInfo]], output_file: str):
        """Export results to a file in JSON format."""
        if not results:
            print("No results to export.")
            return
        
        # Collect all functions from all files
        all_functions = []
        for file_path, functions in results.items():
            all_functions.extend(functions)
        
        if not all_functions:
            print("No functions or altsteps found to export.")
            return
        
        # Part 1: Functions/altsteps WITHOUT PRINT_UC
        part1_functions = [f for f in all_functions if not f.has_print_uc]
        
        # Part 2: Functions/altsteps WITH multiple PRINT_UC or multiple objects
        part2_functions = [f for f in all_functions if f.qualifies_for_part2]
        
        # Prepare export data
        export_data = {
            "summary": {
                "total_functions": len(all_functions),
                "functions_with_print_uc": len([f for f in all_functions if f.has_print_uc]),
                "functions_without_print_uc_part1": len(part1_functions),
                "functions_qualifying_part2": len(part2_functions),
                "files_processed": len(results)
            },
            "part1_functions": [],
            "part2_functions": [],
            "all_functions_details": []
        }
        
        # Group Part 1 functions by file
        part1_by_file = {}
        for func in part1_functions:
            for file_path, file_functions in results.items():
                if func in file_functions:
                    if file_path not in part1_by_file:
                        part1_by_file[file_path] = []
                    part1_by_file[file_path].append({
                        "name": func.name,
                        "type": func.function_type.value,
                        "start_line": func.start_line,
                        "end_line": func.end_line,
                        "file": os.path.basename(file_path)
                    })
                    break
        
        export_data["part1_functions"] = part1_by_file
        
        # Group Part 2 functions by file
        part2_by_file = {}
        for func in part2_functions:
            for file_path, file_functions in results.items():
                if func in file_functions:
                    if file_path not in part2_by_file:
                        part2_by_file[file_path] = []
                    
                    func_data = {
                        "name": func.name,
                        "type": func.function_type.value,
                        "start_line": func.start_line,
                        "end_line": func.end_line,
                        "file": os.path.basename(file_path),
                        "reasons": [],
                        "print_uc_occurrences": []
                    }
                    
                    # Add reasons
                    if func.has_multiple_print_uc:
                        func_data["reasons"].append(f"Multiple PRINT_UC statements ({len(func.print_uc_occurrences)})")
                    if func.has_print_uc_with_multiple_objects:
                        multi_obj_occurrences = [occ for occ in func.print_uc_occurrences if occ.object_count > 1]
                        func_data["reasons"].append(f"PRINT_UC with multiple objects ({len(multi_obj_occurrences)} occurrences)")
                    
                    # Add PRINT_UC details
                    for occurrence in func.print_uc_occurrences:
                        func_data["print_uc_occurrences"].append({
                            "line_number": occurrence.line_number,
                            "object_count": occurrence.object_count,
                            "statement": occurrence.full_statement
                        })
                    
                    part2_by_file[file_path].append(func_data)
                    break
        
        export_data["part2_functions"] = part2_by_file
        
        # Add all functions details for reference
        for file_path, functions in results.items():
            for func in functions:
                func_detail = {
                    "name": func.name,
                    "type": func.function_type.value,
                    "file": file_path,
                    "start_line": func.start_line,
                    "end_line": func.end_line,
                    "has_print_uc": func.has_print_uc,
                    "qualifies_part1": not func.has_print_uc,
                    "qualifies_part2": func.qualifies_for_part2,
                    "print_uc_count": len(func.print_uc_occurrences)
                }
                export_data["all_functions_details"].append(func_detail)
        
        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            print(f"Results exported to '{output_file}'")
        except Exception as e:
            print(f"Error exporting results to '{output_file}': {e}")


def main():
    """Main function to run the TTCN-3 parser."""
    # Set up command line argument parsing
    arg_parser = argparse.ArgumentParser(
        description="Advanced TTCN-3 Parser for PRINT_UC Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/ttcn3/code                     # Parse directory
  %(prog)s -r /path/to/ttcn3/code                  # Parse directory recursively
  %(prog)s -o results.json /path/to/ttcn3/code     # Parse and export to JSON
  %(prog)s -r -o results.json .                    # Parse current dir recursively and export
  %(prog)s single_file.ttcn                        # Parse single file
        """
    )
    
    arg_parser.add_argument(
        'path', 
        nargs='?', 
        default='.', 
        help='Path to TTCN-3 file or directory to analyze (default: current directory)'
    )
    arg_parser.add_argument(
        '-r', '--recursive', 
        action='store_true', 
        help='Search for TTCN-3 files recursively in subdirectories'
    )
    arg_parser.add_argument(
        '-o', '--output', 
        help='Output file to export results in JSON format'
    )
    
    args = arg_parser.parse_args()
    
    # Initialize parser and formatter
    ttcn_parser = TTCN3Parser()
    formatter = ResultFormatter()
    
    print("Advanced TTCN-3 Parser for PRINT_UC Analysis")
    print("=" * 50)
    print(f"Analyzing: {args.path}")
    if args.recursive:
        print("Mode: Recursive search enabled")
    if args.output:
        print(f"Output file: {args.output}")
    print()
    
    # Determine if target is a file or directory
    if os.path.isfile(args.path):
        if args.path.endswith(('.ttcn', '.ttcn3')):
            functions = ttcn_parser.parse_file(args.path)
            results = {args.path: functions} if functions else {}
        else:
            print(f"Error: '{args.path}' is not a TTCN-3 file.")
            return 1
    elif os.path.isdir(args.path):
        results = ttcn_parser.parse_directory(args.path, recursive=args.recursive)
    else:
        print(f"Error: '{args.path}' does not exist.")
        return 1
    
    # Display results
    formatter.print_results(results)
    
    # Export results if output file specified
    if args.output:
        print()  # Add spacing before export message
        formatter.export_results(results, args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
