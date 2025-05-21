# find_react_vulnerabilities
## parse-modules.py
usage: parse-modules.py [-h] [project_path]

Find all packages used in a React app.

positional arguments:
  project_path  Path to the React project directory (default: current directory)

options:
  -h, --help    show this help message and exit
## security-eval.py
usage: security-eval.py [-h] [--sort-by {type,file}] [project_path]

Security Auditor for React Projects

positional arguments:
  project_path          Path to React project directory (default: /mnt/c/Users/trill/Documents/master/Year1/p4/Language base/project/Personal-
                        Website-Template)

options:
  -h, --help            show this help message and exit
  --sort-by {type,file}
                        Sort report by vulnerability type or file location (default: type)
  --scan-modules        Scan dependencies code instead of application's code (default: False)
  Take into account that this last option will make the runtime exceptionally greater! (unless you have few modules in your app)