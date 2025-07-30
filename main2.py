#!/usr/bin/env python3
"""
Advanced TTCN-3 Parser for log(PRINT_UC, ...) Analysis - FIXED VERSION

This parser analyzes TTCN-3 files to identify functions and altsteps based on
their log(PRINT_UC, ...) usage patterns:

Part 1: Functions/altsteps WITHOUT any log(PRINT_UC, ...) statements
Part 2: Functions/altsteps WITH multiple objects in log(PRINT_UC, ...) OR multiple log(PRINT_UC, ...) statements (at least 2 objects are present in the function/altstep)

FIXES APPLIED:
1. More robust function detection patterns
2. Better handling of multi-line function declarations
3. Improved comment removal that preserves line numbers
4. Enhanced brace matching algorithm
5. More comprehensive PRINT_UC detection
6. Better error handling and debugging
7. FIXED: Proper handling of both forms:
   - log(PRINT_UC, "obj1, obj2, obj3") - counts as 1 object
   - log(PRINT_UC, "obj1", "obj2", "obj3") - counts as 3 objects

Version: 1.2 - PRINT_UC Object Counting FIXED
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
    """Advanced TTCN-3 parser for analyzing PRINT_UC usage patterns - FIXED VERSION."""
    
    def __init__(self):
        # FIXED: More comprehensive and robust regex patterns
        # This pattern handles all possible TTCN-3 function declaration styles
        self.function_patterns = [
            # Pattern 1: Standard function declaration (single line or multi-line)
            re.compile(
                r'^\s*(?:public\s+|private\s+|friend\s+)?(function|altstep|testcase)\s+(\w+)\s*\(',
                re.MULTILINE
            ),
            # Pattern 2: Function with template parameters
            re.compile(
                r'^\s*(?:public\s+|private\s+|friend\s+)?(function|altstep|testcase)\s+(\w+)\s*<[^>]*>\s*\(',
                re.MULTILINE
            ),
            # Pattern 3: External functions
            re.compile(
                r'^\s*external\s+(function|altstep|testcase)\s+(\w+)\s*\(',
                re.MULTILINE
            )
        ]
        
        # FIXED: More robust PRINT_UC pattern that handles various formatting
        self.print_uc_patterns = [
            # Standard log(PRINT_UC, ...)
            re.compile(r'log\s*\(\s*PRINT_UC\s*[,)]', re.IGNORECASE | re.DOTALL),
            # With whitespace variations
            re.compile(r'log\s*\(\s*PRINT_UC\s*[,)]', re.MULTILINE | re.DOTALL),
            # Case insensitive variant
            re.compile(r'log\s*\(\s*print_uc\s*[,)]', re.IGNORECASE | re.DOTALL)
        ]
        
        # FIXED: Better comment removal patterns that preserve structure
        self.single_line_comment_pattern = re.compile(r'//.*$', re.MULTILINE)
        self.multi_line_comment_pattern = re.compile(r'/\*.*?\*/', re.DOTALL)
        self.string_literal_pattern = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
    
    def remove_comments_preserve_structure(self, content: str) -> Tuple[str, List[str]]:
        """
        FIXED: Remove comments while preserving line structure and numbers.
        This ensures accurate line number reporting.
        """
        lines = content.split('\n')
        cleaned_lines = []
        
        in_multiline_comment = False
        
        for line_num, line in enumerate(lines):
            cleaned_line = line
            
            # Handle multi-line comments
            if in_multiline_comment:
                end_comment = line.find('*/')
                if end_comment != -1:
                    # Replace comment part with spaces to preserve positions
                    cleaned_line = ' ' * (end_comment + 2) + line[end_comment + 2:]
                    in_multiline_comment = False
                else:
                    # Entire line is in comment, replace with spaces
                    cleaned_line = ' ' * len(line)
            else:
                # Look for start of multi-line comment
                start_comment = line.find('/*')
                if start_comment != -1:
                    end_comment = line.find('*/', start_comment + 2)
                    if end_comment != -1:
                        # Comment starts and ends on same line
                        comment_part = ' ' * (end_comment - start_comment + 2)
                        cleaned_line = line[:start_comment] + comment_part + line[end_comment + 2:]
                    else:
                        # Comment starts but doesn't end on this line
                        cleaned_line = line[:start_comment] + ' ' * (len(line) - start_comment)
                        in_multiline_comment = True
            
            # Remove single-line comments if not in multi-line comment
            if not in_multiline_comment:
                comment_pos = cleaned_line.find('//')
                if comment_pos != -1:
                    cleaned_line = cleaned_line[:comment_pos] + ' ' * (len(cleaned_line) - comment_pos)
            
            cleaned_lines.append(cleaned_line)
        
        return '\n'.join(cleaned_lines), lines
    
    def find_all_function_declarations(self, content: str, original_lines: List[str]) -> List[Tuple[str, str, int, int, int]]:
        """
        FIXED: Find ALL function/altstep/testcase declarations with comprehensive pattern matching.
        Returns list of (function_type, function_name, start_line, declaration_end_line, body_start_pos) tuples.
        """
        functions = []
        lines = content.split('\n')
        
        # FIXED: Check every line for function declarations
        for line_num in range(len(lines)):
            line = lines[line_num].strip()
            
            if not line:
                continue
            
            # Try all function patterns
            for pattern in self.function_patterns:
                match = pattern.search(lines[line_num])
                if match:
                    function_type = match.group(1).lower()
                    function_name = match.group(2)
                    
                    # Find the complete declaration including parameters and opening brace
                    decl_start_pos = content.find(lines[line_num])
                    if decl_start_pos == -1:
                        continue
                    
                    # FIXED: More robust brace finding
                    brace_pos = self.find_function_opening_brace(content, decl_start_pos, line_num, lines)
                    if brace_pos == -1:
                        print(f"Warning: Could not find opening brace for {function_type} {function_name} at line {line_num + 1}")
                        continue
                    
                    # Calculate actual line numbers
                    start_line = line_num + 1
                    brace_line = content[:brace_pos].count('\n') + 1
                    
                    functions.append((function_type, function_name, start_line, brace_line, brace_pos))
                    break  # Found a match, no need to try other patterns
        
        return functions
    
    def find_function_opening_brace(self, content: str, start_pos: int, start_line_num: int, lines: List[str]) -> int:
        """
        FIXED: More robust method to find the opening brace of a function.
        Handles multi-line parameter lists, 'runs on' clauses, and various formatting styles.
        """
        # Start searching from the function declaration
        search_start = start_pos
        max_search_lines = 10  # Don't search more than 10 lines ahead
        
        # First, find the opening parenthesis
        paren_start = content.find('(', search_start)
        if paren_start == -1:
            return -1
        
        # Find the matching closing parenthesis
        paren_end = self.find_matching_paren(content, paren_start)
        if paren_end == -1:
            return -1
        
        # Look for opening brace after the closing parenthesis
        search_pos = paren_end + 1
        brace_search_limit = min(len(content), search_pos + 1000)  # Search within reasonable limit
        
        # Skip whitespace, newlines, and potential 'runs on' clause
        while search_pos < brace_search_limit:
            char = content[search_pos]
            
            if char == '{':
                return search_pos
            elif char.isspace():
                search_pos += 1
            elif content[search_pos:].startswith('runs'):
                # Skip 'runs on ComponentType' clause
                runs_match = re.match(r'runs\s+on\s+\w+', content[search_pos:])
                if runs_match:
                    search_pos += len(runs_match.group(0))
                else:
                    search_pos += 1
            elif char == ';':
                # This might be a function declaration without body (external function)
                return -1
            else:
                search_pos += 1
        
        return -1
    
    def find_matching_paren(self, content: str, start_pos: int) -> int:
        """FIXED: Find the matching closing parenthesis, handling nested parentheses correctly."""
        paren_count = 0
        i = start_pos
        in_string = False
        
        while i < len(content):
            char = content[i]
            
            # Handle string literals
            if char == '"' and (i == 0 or content[i-1] != '\\'):
                in_string = not in_string
            elif not in_string:
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
                    if paren_count == 0:
                        return i
            
            i += 1
        
        return -1
    
    def find_matching_brace(self, content: str, start_pos: int) -> int:
        """FIXED: Find the matching closing brace, handling nested braces and strings correctly."""
        brace_count = 0
        i = start_pos
        in_string = False
        
        while i < len(content):
            char = content[i]
            
            # Handle string literals
            if char == '"' and (i == 0 or content[i-1] != '\\'):
                in_string = not in_string
            elif not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        return i
            
            i += 1
        
        return -1
    
    def extract_all_print_uc_occurrences(self, function_body: str, function_start_line: int) -> List[PrintUCOccurrence]:
        """
        FIXED: Extract ALL log(PRINT_UC, ...) occurrences from a function body.
        Uses multiple patterns to ensure nothing is missed.
        """
        occurrences = []
        body_lines = function_body.split('\n')
        
        # FIXED: Check each line individually to avoid missing occurrences
        for line_offset, line in enumerate(body_lines):
            line_number = function_start_line + line_offset
            
            # Try all PRINT_UC patterns
            for pattern in self.print_uc_patterns:
                matches = list(pattern.finditer(line))
                for match in matches:
                    # Extract the complete log statement
                    full_statement = self.extract_complete_log_statement(line, match.start())
                    if full_statement:
                        object_count = self.count_print_uc_objects_fixed(full_statement)
                        
                        # Avoid duplicates by checking if we already found this statement
                        statement_key = full_statement.replace(' ', '').replace('\t', '').replace('\n', '')
                        if not any(occ.full_statement.replace(' ', '').replace('\t', '').replace('\n', '') == statement_key 
                                 for occ in occurrences):
                            occurrences.append(PrintUCOccurrence(
                                line_number=line_number,
                                object_count=object_count,
                                full_statement=full_statement.strip()
                            ))
        
        return occurrences
    
    def extract_complete_log_statement(self, line: str, start_pos: int) -> str:
        """
        FIXED: Extract the complete log(...) statement, handling multi-line statements.
        """
        # Find the start of 'log'
        log_start = line.rfind('log', 0, start_pos + 10)
        if log_start == -1:
            log_start = start_pos
        
        # Find the opening parenthesis
        paren_start = line.find('(', log_start)
        if paren_start == -1:
            return line[log_start:].strip()
        
        # Find the matching closing parenthesis
        paren_end = self.find_matching_paren(line, paren_start)
        if paren_end == -1:
            # Statement might continue on next line, for now just return what we have
            return line[log_start:].strip()
        
        return line[log_start:paren_end + 1].strip()
    
    def count_print_uc_objects_fixed(self, print_uc_statement: str) -> int:
        """
        FIXED: Count the number of objects in a log(PRINT_UC, ...) statement.
        
        Properly handles both forms:
        1. log(PRINT_UC, "obj1, obj2, obj3") - counts as 1 object (single string)
        2. log(PRINT_UC, "obj1", "obj2", "obj3") - counts as 3 objects (separate parameters)
        
        The key insight is that we need to count the comma-separated PARAMETERS to the log function,
        not commas within string literals.
        """
        # Extract content after log(PRINT_UC,
        match = re.search(r'log\s*\(\s*PRINT_UC\s*(?:,\s*(.*))?\)', print_uc_statement, re.IGNORECASE | re.DOTALL)
        if not match:
            return 0
        
        content = match.group(1)
        if content is None or not content.strip():
            return 0  # log(PRINT_UC) with no additional objects
        
        content = content.strip()
        
        # FIXED: Enhanced object counting that properly handles string literals
        # This counts actual parameters to the log function, not content within strings
        objects = []
        current_object = ""
        paren_depth = 0
        bracket_depth = 0
        brace_depth = 0
        in_string = False
        escape_next = False
        
        i = 0
        while i < len(content):
            char = content[i]
            
            # Handle escape sequences in strings
            if escape_next:
                current_object += char
                escape_next = False
                i += 1
                continue
            
            if char == '\\' and in_string:
                escape_next = True
                current_object += char
                i += 1
                continue
            
            # Handle string boundaries
            if char == '"':
                in_string = not in_string
                current_object += char
            elif not in_string:
                # Only count structural elements when not inside a string
                if char == '(':
                    paren_depth += 1
                    current_object += char
                elif char == ')':
                    paren_depth -= 1
                    current_object += char
                elif char == '[':
                    bracket_depth += 1
                    current_object += char
                elif char == ']':
                    bracket_depth -= 1
                    current_object += char
                elif char == '{':
                    brace_depth += 1
                    current_object += char
                elif char == '}':
                    brace_depth -= 1
                    current_object += char
                elif char == ',' and paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
                    # Found a top-level comma (parameter separator)
                    obj = current_object.strip()
                    if obj:
                        objects.append(obj)
                    current_object = ""
                    i += 1
                    continue
                else:
                    current_object += char
            else:
                # Inside a string, just add the character
                current_object += char
            
            i += 1
        
        # Add the last object
        obj = current_object.strip()
        if obj:
            objects.append(obj)
        
        # Debug output for verification (can be removed in production)
        if len(objects) > 1:
            print(f"DEBUG: Found {len(objects)} objects in: {print_uc_statement}")
            for i, obj in enumerate(objects):
                print(f"  Object {i+1}: {obj}")
        
        return len(objects)
    
    def parse_functions(self, content: str) -> List[FunctionInfo]:
        """FIXED: Parse all functions and altsteps from TTCN-3 content with comprehensive detection."""
        # Remove comments while preserving line structure
        cleaned_content, original_lines = self.remove_comments_preserve_structure(content)
        
        functions = []
        
        # FIXED: Use the improved function detection
        function_declarations = self.find_all_function_declarations(cleaned_content, original_lines)
        
        for function_type_str, function_name, start_line, brace_line, brace_pos in function_declarations:
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
            body_end_pos = self.find_matching_brace(cleaned_content, brace_pos)
            
            if body_end_pos == -1:
                print(f"Warning: Could not find closing brace for {function_type_str} {function_name}")
                continue
            
            # Extract function body (including braces)
            function_body = cleaned_content[brace_pos:body_end_pos + 1]
            
            # Calculate end line
            end_line = cleaned_content[:body_end_pos].count('\n') + 1
            
            # FIXED: Find ALL PRINT_UC occurrences in the function body
            print_uc_occurrences = self.extract_all_print_uc_occurrences(
                function_body, brace_line
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
        """FIXED: Parse a single TTCN-3 file with enhanced error handling."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
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
                            for i, occ in enumerate(func.print_uc_occurrences):
                                print_uc_info += f" [Occurrence {i+1}: {occ.object_count} objects]"
                        print(f"      - {func.function_type.value} {func.name}{print_uc_info}")
                        
                        if func.print_uc_occurrences:
                            print(f"        → has_multiple_print_uc: {func.has_multiple_print_uc}")
                            print(f"        → has_print_uc_with_multiple_objects: {func.has_print_uc_with_multiple_objects}")
                            print(f"        → qualifies_for_part2: {func.qualifies_for_part2}")
                else:
                    print(f"    → No functions/altsteps found")
            
            return functions
        except Exception as e:
            print(f"Error parsing file '{file_path}': {e}")
            if debug:
                import traceback
                traceback.print_exc()
            return []
    
    def parse_directory(self, directory_path: str, recursive: bool = False, debug: bool = False) -> Dict[str, List[FunctionInfo]]:
        """FIXED: Parse all TTCN-3 files in a directory with comprehensive file detection."""
        results = {}
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Error: Directory '{directory_path}' does not exist.")
            return results
        
        # FIXED: More comprehensive file detection
        file_extensions = ['*.ttcn', '*.ttcn3', '*.TTCN', '*.TTCN3']
        ttcn_files = []
        
        for ext in file_extensions:
            if recursive:
                ttcn_files.extend(list(directory.rglob(ext)))
            else:
                ttcn_files.extend(list(directory.glob(ext)))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_files = []
        for f in ttcn_files:
            if f not in seen:
                seen.add(f)
                unique_files.append(f)
        ttcn_files = unique_files
        
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
    def export_results(results: Dict[str, List[FunctionInfo]], output_file: str, only_names: bool = False):
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
        
        if only_names:
            # Export only function names
            export_data = {
                "summary": {
                    "total_functions": len(all_functions),
                    "functions_with_print_uc": len([f for f in all_functions if f.has_print_uc]),
                    "functions_without_print_uc_part1": len(part1_functions),
                    "functions_qualifying_part2": len(part2_functions),
                    "files_processed": len(results)
                },
                "all_function_names": [func.name for func in all_functions],
                "part1_function_names": [func.name for func in part1_functions],
                "part2_function_names": [func.name for func in part2_functions]
            }
        else:
            # Prepare detailed export data
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
            if only_names:
                print(f"Function names exported to '{output_file}' ({len(all_functions)} total functions)")
            else:
                print(f"Results exported to '{output_file}'")
        except Exception as e:
            print(f"Error exporting results to '{output_file}': {e}")
    
    @staticmethod
    def export_part1_results(results: Dict[str, List[FunctionInfo]], output_file: str, only_names: bool = False):
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
        
        if only_names:
            # Export only function names
            export_data = {
                "summary": {
                    "total_part1_functions": len(part1_functions),
                    "description": "Functions and altsteps WITHOUT PRINT_UC statements"
                },
                "function_names": [func.name for func in part1_functions]
            }
        else:
            # Prepare detailed export data
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
            if only_names:
                print(f"Part 1 function names exported to '{output_file}' ({len(part1_functions)} functions)")
            else:
                print(f"Part 1 results (no PRINT_UC) exported to '{output_file}' ({len(part1_functions)} functions)")
        except Exception as e:
            print(f"Error exporting Part 1 results to '{output_file}': {e}")
    
    @staticmethod
    def export_part2_results(results: Dict[str, List[FunctionInfo]], output_file: str, only_names: bool = False):
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
        
        if only_names:
            # Export only function names
            export_data = {
                "summary": {
                    "total_part2_functions": len(part2_functions),
                    "description": "Functions and altsteps WITH multiple objects in PRINT_UC OR multiple PRINT_UC statements"
                },
                "function_names": [func.name for func in part2_functions]
            }
        else:
            # Prepare detailed export data
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
            if only_names:
                print(f"Part 2 function names exported to '{output_file}' ({len(part2_functions)} functions)")
            else:
                print(f"Part 2 results (with PRINT_UC rules) exported to '{output_file}' ({len(part2_functions)} functions)")
        except Exception as e:
            print(f"Error exporting Part 2 results to '{output_file}': {e}")


def main():
    """Main function to run the TTCN-3 parser."""
    # Set up command line argument parsing
    arg_parser = argparse.ArgumentParser(
        description="Advanced TTCN-3 Parser for log(PRINT_UC, ...) Analysis - FIXED VERSION",
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
  %(prog)s --debug /path/to/ttcn3/code              # Enable detailed debug output
  %(prog)s --only_names -o names.json .             # Export only function names
  %(prog)s --only_names --out_pfs part2_names.json . # Export only Part 2 function names

PRINT_UC Object Counting Rules:
  log(PRINT_UC, "obj1, obj2, obj3")     → 1 object  (single string parameter)
  log(PRINT_UC, "obj1", "obj2", "obj3") → 3 objects (three separate parameters)
        """,
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
    arg_parser.add_argument(
        '--only_names',
        action='store_true',
        help='Output only function names instead of detailed JSON format'
    )
    
    # Show help if no arguments provided
    if len(sys.argv) == 1:
        arg_parser.print_help()
        return 0
    
    args = arg_parser.parse_args()
    
    # Initialize parser and formatter
    ttcn_parser = TTCN3Parser()
    formatter = ResultFormatter()
    
    print("Advanced TTCN-3 Parser for PRINT_UC Analysis - FIXED VERSION v1.2")
    print("=" * 70)
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
    if args.only_names:
        print("Only names mode enabled: Will output only function names.")
    
    print("\nPRINT_UC Object Counting Rules:")
    print('  log(PRINT_UC, "obj1, obj2, obj3")     → 1 object  (single string parameter)')
    print('  log(PRINT_UC, "obj1", "obj2", "obj3") → 3 objects (three separate parameters)')
    print()
    
    # Determine if target is a file or directory
    if os.path.isfile(args.path):
        if args.path.lower().endswith(('.ttcn', '.ttcn3')):
            functions = ttcn_parser.parse_file(args.path, args.debug)
            results = {args.path: functions}
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
        formatter.export_results(results, args.output, args.only_names)
        export_performed = True
    
    if args.out_no_pfs:
        if not export_performed:
            print()  # Add spacing before export message
        formatter.export_part1_results(results, args.out_no_pfs, args.only_names)
        export_performed = True
    
    if args.out_pfs:
        if not export_performed:
            print()  # Add spacing before export message
        formatter.export_part2_results(results, args.out_pfs, args.only_names)
        export_performed = True
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
