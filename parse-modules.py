import os
import json
import re
import argparse
import requests
from cvss import CVSS3
from packaging.version import parse
from packaging.specifiers import SpecifierSet

#built-in vulnerability database
VULN_DB = {
    "lodash": {
        "CVE-2021-23337": {
            "affected_versions": "<4.17.12",
            "severity": "high",
            "description": "Command Injection vulnerability in template"
        },
        "CVE-2020-8203": {
            "affected_versions": "<4.17.19",
            "severity": "medium",
            "description": "Prototype pollution in zipObjectDeep"
        }
    },
    "express": {
        "CVE-2022-24999": {
            "affected_versions": "<4.17.3",
            "severity": "critical",
            "description": "Prototype pollution via mergeParams"
        }
    }#this DB can be expanded without any issues
}

def clean_version(version_str):
    #Normalize version strings (remove non-numeric characters and ranges)
    if not version_str:
        return "unknown"
    #we split on hyphen to remove prerelease versions (such as 1.2.3-beta)
    version = version_str.split('-')[0]
    #finally we remove non-numeric/version characters
    return re.sub(r'[^0-9.]', '', version)

def find_package_jsons(project_path):
    #find all package.json files excluding those in node_modules directories
    package_json_files = []
    
    for root, dirs, files in os.walk(project_path):
        if 'node_modules' in dirs:
            dirs.remove('node_modules')
        if 'package.json' in files:
            package_json_files.append(os.path.join(root, 'package.json'))
    return package_json_files

def get_dependencies_from_package_json(file_path):
    #extract dependencies with versions from package.json file
    dependencies = {}

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for name, ver in data[dep_type].items():
                        dependencies[name] = clean_version(ver)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return dependencies

def get_packages_from_node_modules(node_modules_path):
    #extract package names and versions from a node_modules directory
    packages = {}

    if not os.path.exists(node_modules_path):
        return packages
    
    try:
        entries = os.listdir(node_modules_path)
    except PermissionError:
        print(f"Permission denied accessing {node_modules_path}")
        return packages

    for entry in entries:
        entry_path = os.path.join(node_modules_path, entry)
        if not os.path.isdir(entry_path):
            continue

        if entry.startswith('@'):
            try:
                scoped_packages = os.listdir(entry_path)
                for pkg in scoped_packages:
                    pkg_path = os.path.join(entry_path, pkg)
                    pkg_json = os.path.join(pkg_path, 'package.json')
                    if os.path.exists(pkg_json):
                        try:
                            with open(pkg_json, 'r') as f:
                                data = json.load(f)
                                name = data.get('name')
                                version = clean_version(data.get('version', 'unknown'))
                                if name:
                                    packages[name] = version
                        except Exception as e:
                            print(f"Error reading {pkg_json}: {e}")
            except Exception as e:
                print(f"Error reading scoped package {entry_path}: {e}")
        else:
            pkg_json = os.path.join(entry_path, 'package.json')
            if os.path.exists(pkg_json):
                try:
                    with open(pkg_json, 'r') as f:
                        data = json.load(f)
                        name = data.get('name')
                        version = clean_version(data.get('version', 'unknown'))
                        if name:
                            packages[name] = version
                except Exception as e:
                    print(f"Error reading {pkg_json}: {e}")
    return packages

def query_osv(package_name, package_version):
    #query OSV database for vulnerabilities in a specific package version
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "npm"
        },
        "version": package_version
    }
    
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response.json().get('vulns', [])
    except Exception as e:
        print(f"Error querying OSV for {package_name}@{package_version}: {e}")
        return []

def normalize_osv_vulnerability(vuln):
    #convert OSV vulnerability format to our standard format
    vuln_id = vuln.get('id', 'OSV-UNKNOWN')
    aliases = vuln.get('aliases', [])
    cves = [a for a in aliases if a.startswith('CVE-')]
    
    return {
        'id': cves[0] if cves else vuln_id,
        'severity': get_severity_from_cvss(vuln.get('severity', [])),
        'description': vuln.get('summary', 'No description available')
    }

def get_severity_from_cvss(severity_data):
    #get severity from CVSS scores using both numerical scores and vectors
    for score in severity_data:
        if score['type'] == 'CVSS_V3':
            score_value = score['score']
            
            #handle CVSS vector strings
            if score_value.startswith('CVSS'):
                try:
                    cvss = CVSS3(score_value)
                    cvss_score = cvss.base_score
                except Exception as e:
                    print(f"Error parsing CVSS vector: {e}")
                    continue
                    
                if cvss_score >= 9.0:
                    return 'critical'
                elif cvss_score >= 7.0:
                    return 'high'
                elif cvss_score >= 4.0:
                    return 'medium'
                else:
                    return 'low'
            
            #haandle numerical scores
            try:
                cvss_score = float(score_value)
                if cvss_score >= 9.0:
                    return 'critical'
                elif cvss_score >= 7.0:
                    return 'high'
                elif cvss_score >= 4.0:
                    return 'medium'
                else:
                    return 'low'
            except ValueError:
                continue
                
    return 'medium'  #if no valid scores found we set medium as default

def check_vulnerabilities(dependencies):
    #check dependencies against both built-in DB and OSV
    vulnerabilities = []
    
    for package, version in dependencies.items():
        #check built-in vulnerability database
        if package in VULN_DB:
            for cve_id, details in VULN_DB[package].items():
                try:
                    if parse(version) in SpecifierSet(details['affected_versions']):
                        vulnerabilities.append({
                            'package': package,
                            'version': version,
                            'cve': cve_id,
                            'severity': details['severity'],
                            'description': details['description']
                        })
                except Exception as e:
                    print(f"Error checking {package} version {version}: {e}")
        
        #check OSV database
        try:
            osv_vulns = query_osv(package, version)
            for vuln in osv_vulns:
                norm_vuln = normalize_osv_vulnerability(vuln)
                #avoid duplicate entries
                if not any(v['cve'] == norm_vuln['id'] for v in vulnerabilities):
                    vulnerabilities.append({
                        'package': package,
                        'version': version,
                        'cve': norm_vuln['id'],
                        'severity': norm_vuln['severity'],
                        'description': norm_vuln['description']
                    })
        except Exception as e:
            print(f"Error processing OSV data for {package}: {e}")
    
    return vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Find all packages and vulnerabilities in a React app.')
    parser.add_argument('project_path', type=str, nargs='?', default=os.getcwd(),
                       help='Path to the React project directory (default: current directory)')
    args = parser.parse_args()
    project_path = os.path.abspath(args.project_path)
    
    #collect declared dependencies from package.json files
    declared_deps = {}
    package_json_files = find_package_jsons(project_path)
    for pkg_json in package_json_files:
        declared_deps.update(get_dependencies_from_package_json(pkg_json))

    #collect installed dependencies from node_modules
    installed_deps = {}
    node_modules_dirs = [os.path.join(project_path, 'node_modules')]  # Check primary node_modules
    for nm_dir in node_modules_dirs:
        installed_deps.update(get_packages_from_node_modules(nm_dir))

    #combine dependencies with installed versions taking precedence
    all_dependencies = {**declared_deps, **installed_deps}

    #check for vulnerabilities
    vulnerabilities = check_vulnerabilities(all_dependencies)

    #results
    print(f"\nFound {len(all_dependencies)} packages:")
    print("=" * 50)
    for pkg, ver in sorted(all_dependencies.items()):
        print(f"{pkg}@{ver}")

    print("\nVulnerabilities Found:")
    print("=" * 50)
    if not vulnerabilities:
        print("✅ No vulnerabilities found!")
    else:
        #group by severity
        vuln_by_severity = {}
        for vuln in vulnerabilities:
            vuln_by_severity.setdefault(vuln['severity'], []).append(vuln)
        
        #print in order (severity)
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in vuln_by_severity:
                print(f"\n🔴 {severity.upper()} SEVERITY:")
                for vuln in vuln_by_severity[severity]:
                    print(f"\nPackage: {vuln['package']}@{vuln['version']}")
                    print(f"CVE: {vuln['cve']}")
                    print(f"Description: {vuln['description']}")
                    print(f"Learn More: https://osv.dev/vulnerability/{vuln['cve']}")
                    print("-" * 50)

if __name__ == '__main__':
    main()