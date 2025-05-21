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

## generate_csp.py
usage: generate_csp.py [-h] [--add-csp] [--index-path INDEX_PATH] [--production | --development] project_path

Generate a Content Security Policy for a React project and optionally add it to an HTML file.

This script analyzes your React project (prioritizing the 'build/' or 'dist/' directory if present, otherwise source files) to identify resources like scripts, styles, images, fonts, and connection endpoints. Based on this analysis, it generates two Content Security Policies (CSPs):
1.  **Production-focused CSP**: A stricter policy intended for deployment.
2.  **Development-focused CSP**: A more permissive policy that includes settings often required for local development servers and Hot Module Replacement (HMR), such as WebSocket connections (`ws:`, `wss:`) and 'unsafe-eval' for scripts.

The script will print both CSPs to the console and save a detailed explanation of the production-focused CSP, including justifications for each directive and links to MDN documentation, into a `CSP_Explanation.md` file in the project's root. It will also attempt to add `CSP_Explanation.md` to your `.gitignore` file.

**Important:**
*   For the most accurate production CSP, ensure you have built your project (e.g., `npm run build` or `yarn build`) before running this script, so it can analyze the final bundled assets. If a build directory is not found, the script will warn you and proceed by analyzing source files, which may result in a less precise CSP for production.
*   The generated CSPs are starting points. **Always test your application thoroughly** after applying any CSP, especially the production one.
*   Review the `CSP_Explanation.md` file carefully.

positional arguments:
  project_path          Path to the root of the React project (e.g., ./my-react-app)

options:
  -h, --help            show this help message and exit
  --add-csp             Add the generated CSP as a <meta> tag to an HTML file.
                        If this is used, either --production or --development must be specified.
  --index-path INDEX_PATH
                        Path to the HTML file to add the CSP to.
                        If not absolute, path is relative to project_path.
                        Defaults to 'public/index.html', then 'build/index.html', then 'dist/index.html'
                        (checked in that order if --add-csp is set and this is not provided).
                        Only applicable if --add-csp is specified.
  --production          Use the production-focused CSP when adding to HTML (requires --add-csp).
  --development         Use the development-focused CSP when adding to HTML (requires --add-csp).

Example Usage:

1.  **Generate CSP and explanations (recommended for review first):**
    ```bash
    python generate_csp.py ./my-react-app
    ```
    (Ensure `./my-react-app/build` or `./my-react-app/dist` exists for best results)

2.  **Generate CSP and automatically add the production CSP to `build/index.html`:**
    ```bash
    python generate_csp.py ./my-react-app --add-csp --production --index-path build/index.html
    ```

3.  **Generate CSP and automatically add the development CSP to `public/index.html`:**
    ```bash
    python generate_csp.py ./my-react-app --add-csp --development --index-path public/index.html
    ```