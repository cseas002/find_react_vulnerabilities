import os
import json
import re
import argparse
from packaging.version import parse
from packaging.specifiers import SpecifierSet

class SecurityScanner:
    def __init__(self, project_path, scan_modules=False):
        self.project_path = os.path.abspath(project_path)
        self.base_path_to_remove = self.project_path  # Use project directory itself as base
        self.dependencies = {}
        self.vulnerabilities = []
        self.risky_patterns = []
        self.scan_modules = scan_modules

        # Known dangerous code patterns
        self.DANGEROUS_PATTERNS = {
            'eval': r'\beval\s*\(',
            'innerHTML': r'\.innerHTML\s*=',
            'dangerouslySetInnerHTML': r'dangerouslySetInnerHTML\s*=\s*{',
            'shell_command': r'child_process\.exec\s*\(',
            'function_constructor': r'new\s+Function\s*\(',
            'unescaped_output': r'ReactDOM\.renderToString\s*\(',
            'link_vulnerable_MITM': r'\bhttp://(?!s://)'
        }

    def parse_dependencies(self):
        #Extract dependencies from package.json files
        package_jsons = []
        for root, dirs, files in os.walk(self.project_path):
            if 'node_modules' in dirs:
                dirs.remove('node_modules')
            if 'package.json' in files:
                package_jsons.append(os.path.join(root, 'package.json'))

        for pkg_json in package_jsons:
            try:
                with open(pkg_json, 'r') as f:
                    data = json.load(f)
                    for dep_type in ['dependencies', 'devDependencies']:
                        if dep_type in data:
                            for name, ver in data[dep_type].items():
                                self.dependencies[name] = {
                                    'version': self.clean_version(ver),
                                    'file': pkg_json
                                }
            except Exception as e:
                print(f"Error reading {pkg_json}: {e}")


    def analyze_code_patterns(self):
        if self.scan_modules:
            #Search for dangerous code patterns in node_modules
            node_modules_path = os.path.join(self.project_path, 'node_modules')
            if not os.path.exists(node_modules_path):
                return
                
            for root, dirs, files in os.walk(node_modules_path):
                for file in files:
                    if file.endswith(('.js', '.jsx', '.ts', '.tsx', '.html', '.vue')):
                        self.scan_file(os.path.join(root, file))
        else:
            # Search for dangerous code patterns in project source files
            for root, dirs, files in os.walk(self.project_path):
                # Exclude node_modules and hidden directories
                dirs[:] = [d for d in dirs if d not in ('node_modules',) and not d.startswith('.')]
                
                for file in files:
                    if file.endswith(('.js', '.jsx', '.ts', '.tsx', '.html', '.vue')):
                        self.scan_file(os.path.join(root, file))


    def scan_file(self, file_path):
        #Check files for dangerous patterns outside comments
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                
                # Find all comments in the file
                comment_spans = self.find_comments(content)
                
                # Check for dangerous patterns
                for pattern_name, regex in self.DANGEROUS_PATTERNS.items():
                    for match in re.finditer(regex, content):
                        if not self.is_in_comment(match.start(), comment_spans):
                            self.risky_patterns.append({
                                'file': self.shorten_path(file_path),
                                'pattern': pattern_name,
                                'context': self.get_context(content, match.start())
                            })
        except Exception as e:
            pass

    #Change made after seeing that most of the dangerous patterns were called inside comments
    def find_comments(self, content):
        #Identify all comment spans in the content
        comment_spans = []
        
        # Match single-line comments (//...) and multi-line comments (/*...*/)
        comment_pattern = re.compile(
            r'(//.*?$|/\*.*?\*/)',
            re.DOTALL | re.MULTILINE
        )
        
        for match in comment_pattern.finditer(content):
            start, end = match.span()
            comment_spans.append((start, end))
            
        return comment_spans

    def is_in_comment(self, position, comment_spans):
        #Check if a position is within any comment span
        for start, end in comment_spans:
            if start <= position <= end:
                return True
        return False

    def get_context(self, content, position, context=50):
        #Extract context around a matched pattern
        start = max(0, position - context)
        end = min(len(content), position + context)
        return content[start:end].strip()

    def generate_report(self, sort_by='type'):
        """Generate formatted security report with sorting options"""
        report = []
        
        # Sort vulnerabilities
        if sort_by == 'type':
            vulns_sorted = sorted(self.vulnerabilities, 
                                key=lambda x: (x['severity'], x['package']))
        else:
            vulns_sorted = sorted(self.vulnerabilities, 
                                key=lambda x: x['location'])

        # Sort risky patterns
        if sort_by == 'type':
            risks_sorted = sorted(self.risky_patterns,
                                key=lambda x: (x['pattern'], x['file']))
        else:
            risks_sorted = sorted(self.risky_patterns,
                                key=lambda x: x['file'])

        # Build vulnerabilities section
        if vulns_sorted:
            report.append("\n🔴 Known Vulnerabilities:")
            current_group = None
            for vuln in vulns_sorted:
                if sort_by == 'type' and vuln['severity'] != current_group:
                    current_group = vuln['severity']
                    report.append(f"\n=== {current_group.upper()} ===")
                report.append(
                    f"- {vuln['package']}@{vuln['version']} "
                    f"(CVE: {vuln['cve']})\n"
                    f"  Description: {vuln['description']}\n"
                    f"  Location: {vuln['location']}"
                )

        # Build risky patterns section
        if risks_sorted:
            report.append("\n🚨  Dangerous Code Patterns Detected:")
            current_group = None
            for pattern in risks_sorted:
                # Determine grouping key based on sort type
                if sort_by == 'type':
                    group_key = pattern['pattern']
                    item_text = f"  - File: {pattern['file']}\n  Context: {pattern['context']}"
                else:
                    group_key = pattern['file']
                    item_text = f"- {pattern['pattern']}\n  Context: {pattern['context']}"

                # Add group header if needed
                if group_key != current_group:
                    current_group = group_key
                    report.append(f"\n=== {current_group} ===")
                
                report.append(item_text)

        return "\n".join(report)

    
    def clean_version(self, version_str):
        #Normalize version strings
        return re.sub(r'[^0-9.]', '', version_str.split('-')[0])

    def shorten_path(self, full_path):
        #Remove the base path from file paths in output
        try:
            return os.path.relpath(full_path, self.base_path_to_remove)
        except ValueError:
            return full_path

def main():
    # Set up command line arguments
    parser = argparse.ArgumentParser(
        description='Security Auditor for React Projects',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        'project_path', 
        nargs='?', 
        default=os.getcwd(),
        help='Path to React project directory'
    )
    parser.add_argument(
        '--sort-by', 
        choices=['type', 'file'], 
        default='type',
        help='Sort report by vulnerability type or file location'
    )
    parser.add_argument(
        '--scan-modules',
        action='store_true',
        help='Scan dependencies code instead of application\'s code'
    )
    args = parser.parse_args()
    
    # Initialize scanner and process
    scanner = SecurityScanner(args.project_path, scan_modules=args.scan_modules)
    scanner.parse_dependencies()
    scanner.analyze_code_patterns()
    
    # Generate and display report
    report = scanner.generate_report(sort_by=args.sort_by)
    
    if not report:
        print("✅ No security issues found!")
    else:
        print(report)
    
    # Save SBOM if needed (optional)
    # with open('sbom.json', 'w') as f:
    #     json.dump(scanner.generate_sbom(), f, indent=2)

if __name__ == '__main__':
    main()