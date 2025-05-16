import os
import json
import argparse


def find_package_jsons(project_path):
    #Find all package.json files excluding those in node_modules directories.
    package_json_files = []
    for root, dirs, files in os.walk(project_path):
        if 'node_modules' in dirs:
            dirs.remove('node_modules')  # Skip node_modules directories
        if 'package.json' in files:
            package_json_files.append(os.path.join(root, 'package.json'))
    return package_json_files

def get_dependencies_from_package_json(file_path):
    #Extract dependencies and devDependencies from a package.json file.
    dependencies = set()
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    dependencies.update(data[dep_type].keys())
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return dependencies

def find_node_modules_dirs(project_path):
    #Find all node_modules directories in the project.
    node_modules_dirs = []
    for root, dirs, files in os.walk(project_path):
        if 'node_modules' in dirs:
            node_modules_path = os.path.join(root, 'node_modules')
            node_modules_dirs.append(node_modules_path)
            dirs.remove('node_modules')  # Prevent walking into node_modules
    return node_modules_dirs

def get_packages_from_node_modules(node_modules_path):
    #Extract package names from a node_modules directory.
    packages = set()
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
            # Handle scoped packages
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
                                if name:
                                    packages.add(name)
                        except Exception as e:
                            print(f"Error reading {pkg_json}: {e}")
            except Exception as e:
                print(f"Error reading scoped package {entry_path}: {e}")
        else:
            # Handle normal packages
            pkg_json = os.path.join(entry_path, 'package.json')
            if os.path.exists(pkg_json):
                try:
                    with open(pkg_json, 'r') as f:
                        data = json.load(f)
                        name = data.get('name')
                        if name:
                            packages.add(name)
                except Exception as e:
                    print(f"Error reading {pkg_json}: {e}")
    return packages

def main():
    parser = argparse.ArgumentParser(description='Find all packages used in a React app.')
    parser.add_argument('project_path', type=str, nargs='?', default=os.getcwd(),
                       help='Path to the React project directory (default: current directory)')
    args = parser.parse_args()

    project_path = os.path.abspath(args.project_path)
    
    # Get declared dependencies from package.json files
    declared_deps = set()
    package_json_files = find_package_jsons(project_path)
    for pkg_json in package_json_files:
        declared_deps.update(get_dependencies_from_package_json(pkg_json))

    # Get installed packages from node_modules
    installed_deps = set()
    node_modules_dirs = find_node_modules_dirs(project_path)
    for nm_dir in node_modules_dirs:
        installed_deps.update(get_packages_from_node_modules(nm_dir))

    # Combine both sets of dependencies
    all_dependencies = declared_deps.union(installed_deps)

    print(f"\nFound {len(all_dependencies)} packages:")
    print("=" * 30)
    for pkg in sorted(all_dependencies):
        print(pkg)

if __name__ == '__main__':
    main()