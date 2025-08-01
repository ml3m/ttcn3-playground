#!/usr/bin/env python3
"""
Advanced TTCN-3 Parser for log(PRINT_UC, ...) Analysis

This parser analyzes TTCN-3 files to identify functions and altsteps based on
their log(PRINT_UC, ...) usage patterns:

Part 1: Functions/altsteps WITHOUT any log(PRINT_UC, ...) statements
Part 2: Functions/altsteps WITH multiple objects in log(PRINT_UC, ...) OR multiple log(PRINT_UC, ...) statements (at least 2 objects are present in the function/altstep)

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
    """Represents a single log(PRINT_UC, ...) occurrence with its object count."""
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
        """Check if function has any log(PRINT_UC, ...) statements."""
        return len(self.print_uc_occurrences) > 0
    
    @property
    def has_multiple_print_uc(self) -> bool:
        """Check if function has multiple log(PRINT_UC, ...) statements."""
        return len(self.print_uc_occurrences) > 1
    
    @property
    def has_print_uc_with_multiple_objects(self) -> bool:
        """Check if function has log(PRINT_UC, ...) with multiple objects."""
        return any(occurrence.object_count > 1 for occurrence in self.print_uc_occurrences)
    
    @property
    def qualifies_for_part2(self) -> bool:
        """Check if function qualifies for Part 2 (multiple objects OR multiple log(PRINT_UC, ...))."""
        return self.has_multiple_print_uc or self.has_print_uc_with_multiple_objects


class TTCN3Parser:
    """Advanced TTCN-3 parser for analyzing PRINT_UC usage patterns."""
    
    def __init__(self):
        # Regex patterns for parsing - comprehensive pattern for all TTCN-3 function styles
        # This pattern handles:
        # - Multi-line parameter lists
        # - Braces on same line or next line
        # - Optional 'runs on' clause
        # - Various whitespace and formatting styles
        self.function_pattern = re.compile(
            r'^\s*(function|altstep|testcase)\s+(\w+)\s*\([^)]*\)(?:\s+runs\s+on\s+\w+)?\s*\n?\s*\{',
            re.MULTILINE | re.DOTALL
        )
        
        # Alternative pattern for multi-line parameter lists
        self.function_pattern_multiline = re.compile(
            r'^\s*(function|altstep|testcase)\s+(\w+)\s*\([^)]*\)(?:\s+runs\s+on\s+\w+)?\s*\{',
            re.MULTILINE | re.DOTALL
        )
        
        # More flexible pattern that handles any parameter list format
        self.function_pattern_flexible = re.compile(
            r'^\s*(function|altstep|testcase)\s+(\w+)\s*\([^)]*\)(?:\s+runs\s+on\s+\w+)?\s*\{',
            re.MULTILINE | re.DOTALL
        )
        
        self.print_uc_pattern = re.compile(
            r'log\s*\(\s*PRINT_UC\s*[,)][^)]*\)',
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
        
        # For PRINT_UC analysis, we need to preserve string literals to count objects correctly
        # So we'll only remove comments, not string literals
        # This ensures that log(PRINT_UC, "string1", "string2") remains intact
        
        return content, {i + 1: line for i, line in enumerate(original_lines)}
    
    def find_function_declarations(self, content: str) -> List[Tuple[str, str, int, int]]:
        """
        Find all function/altstep/testcase declarations in content.
        Returns list of (function_type, function_name, start_pos, end_pos) tuples.
        Handles all TTCN-3 function declaration styles including multi-line parameters.
        """
        functions = []
        lines = content.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Check if this line starts a function declaration
            # Handle modifiers: public, private, friend, etc.
            function_match = re.match(r'^\s*(?:public\s+|private\s+|friend\s+)?(function|altstep|testcase)\s+(\w+)\s*\(', line)
            if function_match:
                function_type = function_match.group(1)
                function_name = function_match.group(2)
                
                # Find the complete function declaration (handle multi-line parameters)
                start_pos = content.find(lines[i])
                end_pos = self.find_function_declaration_end(content, start_pos, lines, i)
                
                if end_pos != -1:
                    functions.append((function_type, function_name, start_pos, end_pos))
                
                # Skip to the line after the function declaration
                i = self.get_line_number(content, end_pos) if end_pos != -1 else i + 1
            else:
                i += 1
        
        return functions
    
    def find_function_declaration_end(self, content: str, start_pos: int, lines: List[str], start_line: int) -> int:
        """
        Find the end of a function declaration (the opening brace).
        Handles multi-line parameter lists and 'runs on' clauses.
        """
        # Start from the opening parenthesis
        paren_start = content.find('(', start_pos)
        if paren_start == -1:
            return -1
        
        # Find the matching closing parenthesis
        paren_end = self.find_matching_paren(content, paren_start)
        if paren_end == -1:
            return -1
        
        # Look for 'runs on' clause after the closing parenthesis
        after_paren = content[paren_end + 1:].strip()
        runs_on_match = re.match(r'^\s*runs\s+on\s+\w+', after_paren)
        
        if runs_on_match:
            # Find the end of the 'runs on' clause
            runs_on_end = paren_end + 1 + len(runs_on_match.group(0))
            after_runs_on = content[runs_on_end:].strip()
        else:
            after_runs_on = after_paren
        
        # Find the opening brace
        brace_pos = after_runs_on.find('{')
        if brace_pos == -1:
            return -1
        
        return paren_end + 1 + (len(runs_on_match.group(0)) if runs_on_match else 0) + brace_pos
    
    def find_matching_paren(self, content: str, start_pos: int) -> int:
        """Find the matching closing parenthesis for an opening parenthesis."""
        paren_count = 0
        i = start_pos
        
        while i < len(content):
            if content[i] == '(':
                paren_count += 1
            elif content[i] == ')':
                paren_count -= 1
                if paren_count == 0:
                    return i
            i += 1
        
        return -1
    
    def get_line_number(self, content: str, pos: int) -> int:
        """Get the line number for a given position in content."""
        return content[:pos].count('\n') + 1
    
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
        Count the number of objects in a log(PRINT_UC, ...) statement.
        Handles complex expressions, nested parentheses, and function calls.
        The PRINT_UC identifier itself is not counted as an object.
        """
        # Extract content after log(PRINT_UC, - looking for objects after PRINT_UC
        match = re.search(r'log\s*\(\s*PRINT_UC\s*(?:,\s*(.*))?\)', print_uc_statement, re.DOTALL)
        if not match:
            return 0
        
        content = match.group(1)
        if content is None or not content.strip():
            return 0  # log(PRINT_UC) with no additional objects
        
        content = content.strip()
        
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
        """Extract all log(PRINT_UC, ...) occurrences from a function body."""
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
        
        # Use the new comprehensive function detection
        function_declarations = self.find_function_declarations(cleaned_content)
        
        for function_type_str, function_name, start_pos, decl_end_pos in function_declarations:
            # Determine function type
            if function_type_str == "function":
                function_type = FunctionType.FUNCTION
            elif function_type_str == "altstep":
                function_type = FunctionType.ALTSTEP
            elif function_type_str == "testcase":
                function_type = FunctionType.TESTCASE
            else:
                continue  # Skip unknown types
            
            # Find function body boundaries (from opening brace to closing brace)
            body_start_pos = decl_end_pos  # Position of opening brace
            body_end_pos = self.find_matching_brace(cleaned_content, body_start_pos)
            
            if body_end_pos == -1:
                continue  # Skip if no matching brace found
            
            # Extract function body
            function_body = cleaned_content[body_start_pos:body_end_pos + 1]
            
            # Calculate line numbers
            start_line = cleaned_content[:start_pos].count('\n') + 1
            end_line = cleaned_content[:body_end_pos].count('\n') + 1
            
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
    
    def parse_file(self, file_path: str, debug: bool = False) -> List[FunctionInfo]:
        """Parse a single TTCN-3 file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            if debug:
                print(f"  Parsing {os.path.basename(file_path)} ({len(content)} characters)")
            
            functions = self.parse_functions(content)
            
            if debug:
                if functions:
                    print(f"    → Found {len(functions)} functions/altsteps")
                    for func in functions:
                        print_uc_info = ""
                        if func.print_uc_occurrences:
                            print_uc_info = f" (PRINT_UC: {len(func.print_uc_occurrences)} occurrences)"
                            # Debug: Show object counts
                            for i, occ in enumerate(func.print_uc_occurrences):
                                print_uc_info += f" [Occurrence {i+1}: {occ.object_count} objects]"
                        print(f"      - {func.function_type.value} {func.name}{print_uc_info}")
                        
                        # Debug: Show qualification details
                        if func.print_uc_occurrences:
                            print(f"        → has_multiple_print_uc: {func.has_multiple_print_uc}")
                            print(f"        → has_print_uc_with_multiple_objects: {func.has_print_uc_with_multiple_objects}")
                            print(f"        → qualifies_for_part2: {func.qualifies_for_part2}")
                else:
                    print(f"    → No functions/altsteps found")
            
            return functions
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return []
        except Exception as e:
            print(f"Error parsing file '{file_path}': {e}")
            return []
    
    def parse_directory(self, directory_path: str, recursive: bool = False, debug: bool = False) -> Dict[str, List[FunctionInfo]]:
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
        
        if debug:
            print(f"\nDetailed parsing information:")
        
        # Track processing statistics
        files_with_functions = 0
        files_without_functions = 0
        files_with_errors = 0
        
        for file_path in ttcn_files:
            try:
                functions = self.parse_file(str(file_path), debug)
                # ALWAYS add file to results, even if no functions found
                results[str(file_path)] = functions
                
                if functions:
                    files_with_functions += 1
                else:
                    files_without_functions += 1
                    
            except Exception as e:
                print(f"Error processing file '{file_path}': {e}")
                results[str(file_path)] = []  # Still add to results with empty list
                files_with_errors += 1
        
        # Print detailed processing statistics
        print(f"\nProcessing Summary:")
        print(f"  Total files examined: {len(ttcn_files)}")
        print(f"  Files with functions/altsteps: {files_with_functions}")
        print(f"  Files without functions/altsteps: {files_without_functions}")
        if files_with_errors > 0:
            print(f"  Files with parsing errors: {files_with_errors}")
        
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
        files_with_functions = 0
        files_without_functions = 0
        
        for file_path, functions in results.items():
            all_functions.extend(functions)
            if functions:
                files_with_functions += 1
            else:
                files_without_functions += 1
        
        if not all_functions:
            print("No functions or altsteps found in any files.")
            print(f"\nFiles examined: {len(results)}")
            print(f"Files without functions/altsteps: {files_without_functions}")
            
            if files_without_functions > 0:
                print("\nFiles without functions/altsteps:")
                for file_path, functions in results.items():
                    if not functions:
                        print(f"  {os.path.basename(file_path)}")
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
        
        # Summary statistics - improved to show all file information
        print(f"\n" + "=" * 80)
        print("SUMMARY STATISTICS")
        print("=" * 80)
        total_functions = len(all_functions)
        functions_with_print = len([f for f in all_functions if f.has_print_uc])
        functions_without_print = len(part1_functions)
        functions_part2 = len(part2_functions)
        
        print(f"Total files examined: {len(results)}")
        print(f"Files with functions/altsteps: {files_with_functions}")
        print(f"Files without functions/altsteps: {files_without_functions}")
        print(f"Total functions/altsteps analyzed: {total_functions}")
        print(f"Functions WITH PRINT_UC: {functions_with_print}")
        print(f"Functions WITHOUT PRINT_UC (Part 1): {functions_without_print}")
        print(f"Functions qualifying for Part 2: {functions_part2}")
        
        # Show files without functions if any
        if files_without_functions > 0:
            print(f"\nFiles without functions/altsteps:")
            for file_path, functions in results.items():
                if not functions:
                    print(f"  {os.path.basename(file_path)}")
        
        # Show files with candidates (functions/altsteps)
        print(f"\nFiles with candidates (functions/altsteps):")
        for file_path, functions in results.items():
            if functions:
                print(f"  {os.path.basename(file_path)} ({len(functions)} candidates)")
        
        # Final summary message
        print(f"\n" + "=" * 80)
        print("EXECUTION COMPLETE")
        print("=" * 80)
        print(f"✅ Successfully processed {len(results)} TTCN-3 files")
        print(f"📁 Files with candidates: {files_with_functions}")
        print(f"📄 Files without candidates: {files_without_functions}")
        print(f"🔍 Total candidates analyzed: {total_functions}")
        if functions_part2 > 0:
            print(f"🎯 Part 2 candidates found: {functions_part2}")
        if functions_without_print > 0:
            print(f"📋 Part 1 candidates found: {functions_without_print}")
        print("=" * 80)
    
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
    
    @staticmethod
    def export_part1_results(results: Dict[str, List[FunctionInfo]], output_file: str):
        """Export Part 1 results (functions/altsteps WITHOUT PRINT_UC) to JSON file."""
        if not results:
            print("No results to export for Part 1.")
            return
        
        # Collect all functions from all files
        all_functions = []
        for file_path, functions in results.items():
            all_functions.extend(functions)
        
        # Part 1: Functions/altsteps WITHOUT PRINT_UC
        part1_functions = [f for f in all_functions if not f.has_print_uc]
        
        if not part1_functions:
            print("No Part 1 functions (without PRINT_UC) found to export.")
            return
        
        # Prepare export data
        export_data = {
            "summary": {
                "total_part1_functions": len(part1_functions),
                "files_processed": len(results),
                "description": "Functions and altsteps WITHOUT PRINT_UC statements"
            },
            "part1_functions": {}
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
                        "file": os.path.basename(file_path),
                        "full_path": file_path
                    })
                    break
        
        export_data["part1_functions"] = part1_by_file
        
        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            print(f"Part 1 results (no PRINT_UC) exported to '{output_file}' ({len(part1_functions)} functions)")
        except Exception as e:
            print(f"Error exporting Part 1 results to '{output_file}': {e}")
    
    @staticmethod
    def export_part2_results(results: Dict[str, List[FunctionInfo]], output_file: str):
        """Export Part 2 results (functions/altsteps WITH multiple PRINT_UC objects or statements) to JSON file."""
        if not results:
            print("No results to export for Part 2.")
            return
        
        # Collect all functions from all files
        all_functions = []
        for file_path, functions in results.items():
            all_functions.extend(functions)
        
        # Part 2: Functions/altsteps WITH multiple PRINT_UC or multiple objects
        part2_functions = [f for f in all_functions if f.qualifies_for_part2]
        
        if not part2_functions:
            print("No Part 2 functions (with multiple PRINT_UC objects/statements) found to export.")
            return
        
        # Prepare export data
        export_data = {
            "summary": {
                "total_part2_functions": len(part2_functions),
                "files_processed": len(results),
                "description": "Functions and altsteps WITH multiple objects in PRINT_UC OR multiple PRINT_UC statements"
            },
            "part2_functions": {}
        }
        
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
                        "full_path": file_path,
                        "reasons": [],
                        "print_uc_count": len(func.print_uc_occurrences),
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
        
        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            print(f"Part 2 results (with PRINT_UC rules) exported to '{output_file}' ({len(part2_functions)} functions)")
        except Exception as e:
            print(f"Error exporting Part 2 results to '{output_file}': {e}")


def main():
    """Main function to run the TTCN-3 parser."""
    # Set up command line argument parsing
    arg_parser = argparse.ArgumentParser(
        description="Advanced TTCN-3 Parser for log(PRINT_UC, ...) Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/ttcn3/code                     # Parse directory
  %(prog)s -r /path/to/ttcn3/code                  # Parse directory recursively
  %(prog)s -o results.json /path/to/ttcn3/code     # Parse and export complete results
  %(prog)s --out_no_pfs part1.json .               # Export only Part 1 (no log(PRINT_UC, ...))
  %(prog)s --out_pfs part2.json .                  # Export only Part 2 (log(PRINT_UC, ...) rules)
  %(prog)s --out_no_pfs part1.json --out_pfs part2.json .  # Export both parts separately
  %(prog)s -r -o full.json --out_no_pfs p1.json .  # Recursive with multiple exports
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
    arg_parser.add_argument(
        '--out_no_pfs',
        metavar='filename.json',
        help='Export Part 1 results (functions/altsteps WITHOUT log(PRINT_UC, ...)) to JSON file'
    )
    arg_parser.add_argument(
        '--out_pfs',
        metavar='filename.json', 
        help='Export Part 2 results (functions/altsteps WITH multiple log(PRINT_UC, ...) objects or statements) to JSON file'
    )
    arg_parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode to print detailed parsing information'
    )
    
    # Show help if no arguments provided
    if len(sys.argv) == 1:
        arg_parser.print_help()
        return 0
    
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
        print(f"Complete results output: {args.output}")
    if args.out_no_pfs:
        print(f"Part 1 output (no PRINT_UC): {args.out_no_pfs}")
    if args.out_pfs:
        print(f"Part 2 output (PRINT_UC rules): {args.out_pfs}")
    if args.debug:
        print("Debug mode enabled: Detailed parsing information will be printed.")
    print()
    
    # Determine if target is a file or directory
    if os.path.isfile(args.path):
        if args.path.endswith(('.ttcn', '.ttcn3')):
            functions = ttcn_parser.parse_file(args.path, args.debug)
            results = {args.path: functions} if functions else {}
        else:
            print(f"Error: '{args.path}' is not a TTCN-3 file.")
            return 1
    elif os.path.isdir(args.path):
        results = ttcn_parser.parse_directory(args.path, recursive=args.recursive, debug=args.debug)
    else:
        print(f"Error: '{args.path}' does not exist.")
        return 1
    
    # Display results
    formatter.print_results(results)
    
    # Export results if output files specified
    export_performed = False
    if args.output:
        print()  # Add spacing before export message
        formatter.export_results(results, args.output)
        export_performed = True
    
    if args.out_no_pfs:
        if not export_performed:
            print()  # Add spacing before export message
        formatter.export_part1_results(results, args.out_no_pfs)
        export_performed = True
    
    if args.out_pfs:
        if not export_performed:
            print()  # Add spacing before export message
        formatter.export_part2_results(results, args.out_pfs)
        export_performed = True
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
