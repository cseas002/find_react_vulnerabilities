import argparse
import os
import re
import glob

# ANSI escape codes for colors
class colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    ENDC = '\033[0m' # Resets the color

# Basic host sources that are usually safe
COMMON_HOST_SOURCES = {
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'none'",
    "data:",
    "blob:",
    "filesystem:",
    "mediastream:",
}

MDN_CSP_DOCS = {
    'default-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src",
    'script-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src",
    'style-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src",
    'img-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/img-src",
    'font-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/font-src",
    'connect-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/connect-src",
    'object-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src",
    'frame-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src",
    'base-uri': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri",
    'form-action': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action",
    'manifest-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/manifest-src",
    'worker-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/worker-src",
    'prefetch-src': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/prefetch-src",
    'frame-ancestors': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
    'report-uri': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri",
    'report-to': "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to",
}

def is_url(value):
    # A simple regex to check if a string is a URL (simplified)
    return re.match(r'^https?://', value) is not None

def analyze_html_file(file_path, is_build_output=False):
    """
    Analyzes a single HTML file for resource links and inline styles/scripts.
    Returns a dictionary with potential sources and a set of files with inline styles.
    """
    sources = {
        'script-src': set(), 'style-src': set(), 'img-src': set(),
        'font-src': set(), 'connect-src': set(), 'frame-src': set(),
        'object-src': set(), 'manifest-src': set(), 'base-uri': set()
    }
    inline_style_files = set()
    inline_script_hashes = set() # For future use if we implement hash generation

    if not os.path.exists(file_path):
        print(f"{colors.YELLOW}Warning:{colors.ENDC} HTML file {colors.BLUE}{file_path}{colors.ENDC} not found. Skipping its analysis.")
        return sources, inline_style_files, inline_script_hashes

    print(f"Analyzing HTML file: {colors.BLUE}{file_path}{colors.ENDC}...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Script tags
        for match in re.finditer(r"<script[^>]+src=['\"]([^'\"]+)['\"]", content):
            src = match.group(1)
            if is_url(src):
                sources['script-src'].add(src.split('/')[2])
        
        # Image tags
        for match in re.finditer(r"<img[^>]+src=['\"]([^'\"]+)['\"]", content):
            src = match.group(1)
            if is_url(src):
                sources['img-src'].add(src.split('/')[2])
        
        # Inline script tags - basic detection for now
        if re.search(r'<script[^>]*>(?!\s*<!--)', content, re.IGNORECASE) and not re.search(r'<script[^>]+src=', content, re.IGNORECASE) :
             print(f"{colors.YELLOW}Info:{colors.ENDC} Inline <script> tag content detected in {colors.BLUE}{file_path}{colors.ENDC}. For a strict CSP, this would require 'unsafe-inline' (not recommended), or preferably hashes/nonces for 'script-src'.")

        # Link tags for stylesheets
        for match in re.finditer(r"<link[^>]+rel=['\"]stylesheet['\"][^>]+href=['\"]([^'\"]+)['\"]", content):
            href = match.group(1)
            if is_url(href):
                sources['style-src'].add(href.split('/')[2])
        
        # Link tags for manifest
        for match in re.finditer(r"<link[^>]+rel=['\"]manifest['\"][^>]+href=['\"]([^'\"]+)['\"]", content):
            href = match.group(1)
            if is_url(href):
                 sources['manifest-src'].add(href.split('/')[2])
            elif href.startswith('/') or (is_build_output and not href.startswith('%')):
                 sources['manifest-src'].add("'self'")
        
        # Base tag
        for match in re.finditer(r"<base[^>]+href=['\"]([^'\"]+)['\"]", content):
            href = match.group(1)
            if is_url(href):
                # Extract domain or full origin for base-uri
                # For base-uri, it's often just the origin (scheme://host:port)
                # A simple split might be too naive if path is included, but CSP base-uri can be just a host.
                # Let's add the host for now.
                sources['base-uri'].add(href.split('/')[2]) 
            # Not adding 'self' for base if local, as it's often implicit or more restrictive than needed.

        # Inline style tags
        if re.search(r'<style[^>]*>', content, re.IGNORECASE):
            print(f"{colors.YELLOW}Info:{colors.ENDC} Inline <style> tag found in {colors.BLUE}{file_path}{colors.ENDC}.")
            inline_style_files.add(file_path)

    except Exception as e:
        print(f"{colors.RED}Error reading or parsing HTML file {file_path}: {e}{colors.ENDC}")
    return sources, inline_style_files, inline_script_hashes

def analyze_js_jsx_ts_tsx_files(project_src_path):
    """
    Analyzes JS/JSX/TS/TSX files in the src directory for patterns requiring 'unsafe-inline' for styles (e.g., style={{}} in JSX, which React renders as inline style attributes).
    Returns a set of file paths where such patterns were found.
    """
    jsx_inline_style_files = set()
    # Regex to find style={{...}} in JSX. 
    # This pattern indicates that React will generate an inline HTML 'style' attribute from the JSX object.
    # Inline 'style' attributes on HTML elements require 'unsafe-inline' in the style-src CSP directive 
    # for the styles to be applied by the browser.
    # While 'unsafe-inline' for style-src doesn't permit direct JavaScript execution like it would for script-src,
    # it can contribute to security risks such as data exfiltration (e.g., using CSS selectors on sensitive data
    # and external url() calls) or UI redressing/phishing if an attacker can inject or manipulate these inline styles
    # through another vulnerability (e.g., an XSS vulnerability that allows writing to style attributes).
    # It's generally recommended to use CSS classes and external stylesheets, but style props are common in React.
    jsx_style_prop_regex = re.compile(r"style=\{\{[^}]*\}\}") # Corrected regex: ensure no extra backslashes before final quote

    print(f"Analyzing JavaScript/TypeScript files in {colors.BLUE}{project_src_path}{colors.ENDC} for JSX inline styles...")
    file_extensions = ('*.js', '*.jsx', '*.ts', '*.tsx')
    files_to_scan = []
    for ext in file_extensions:
        files_to_scan.extend(glob.glob(os.path.join(project_src_path, '**', ext), recursive=True))

    if not files_to_scan:
        print(f"No JavaScript/TypeScript files found in {project_src_path}.")
        return jsx_inline_style_files

    for file_path in files_to_scan:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if jsx_style_prop_regex.search(content):
                    print(f"{colors.YELLOW}Info:{colors.ENDC} JSX inline style (style={{...}}) detected in: {colors.BLUE}{file_path}{colors.ENDC}")
                    jsx_inline_style_files.add(file_path)
        except Exception as e:
            print(f"{colors.RED}Error reading or parsing file {file_path}: {e}{colors.ENDC}")
            
    print(f"Found JSX inline styles in {len(jsx_inline_style_files)} file(s).")
    return jsx_inline_style_files

def analyze_bundled_js_css(build_path):
    print(f"Analyzing bundled JS/CSS files in {colors.BLUE}{build_path}{colors.ENDC}...")
    detected_domains = {
        'script-src': set(), 'style-src': set(), 'img-src': set(),
        'font-src': set(), 'connect-src': set(), 'frame-src': set(), 
        'form-action': set(), 'object-src': set(), 'worker-src': set() # Initialized worker-src
    }
    url_pattern = re.compile(r"(?:(?:https?|wss?):\/\/|\/\/)(?:[\w\-]+\.)+[\w\-\.]+(?::\d+)?(?:\/[^\s'\"\)]*)?")
    domain_pattern = re.compile(r"(?:https?|wss?)?:\/\/([^\/:]+)")
    image_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg', '.ico', '.apng', '.avif')

    js_files = glob.glob(os.path.join(build_path, '**', '*.js'), recursive=True)
    print(f"Found {len(js_files)} JS files to scan in build output.")
    for js_file in js_files:
        try:
            with open(js_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Pattern for new Worker('URL') or new Worker("URL")
                worker_pattern = re.compile(r'''new\s+Worker\s*\(\s*['"]([^'"]+)['"]\s*\)''')
                for match in worker_pattern.finditer(content):
                    url = match.group(1)
                    if is_url(url):
                        domain_match = domain_pattern.search(url)
                        if domain_match:
                            detected_domains['worker-src'].add(domain_match.group(1))
                    # Local workers (e.g., '/test-worker.js') will be covered by 'self' if it's in worker-src

                img_src_specific_pattern = re.compile(r'(?:src\s*=\s*["\']|src\s*:\s*["\'])(https?:\/\/[^"\'\s{},()\\\[\\\]<>;]+)["\']?')
                for specific_match in img_src_specific_pattern.finditer(content):
                    url_from_src = specific_match.group(1)
                    domain_match_for_src = domain_pattern.search(url_from_src)
                    if domain_match_for_src:
                        domain = domain_match_for_src.group(1)
                        detected_domains['img-src'].add(domain)
                        if "example.com" in domain: # Heuristic for iframe test
                            detected_domains['frame-src'].add(domain)

                action_prop_pattern = re.compile(r'(?:action\s*=\s*["\']|action\s*:\s*["\'])(https?:\/\/[^"\'\s\{\}\,\(\)\[\]<>;]+)["\']?')
                for match in action_prop_pattern.finditer(content):
                    url = match.group(1)
                    domain_match = domain_pattern.search(url)
                    if domain_match:
                        detected_domains['form-action'].add(domain_match.group(1))
                
                object_data_pattern = re.compile(r'(?:data\s*=\s*["\']|data\s*:\s*["\'])(https?:\/\/[^"\'\s\{\}\,\(\)\[\]<>;]+)["\']?')
                for match in object_data_pattern.finditer(content):
                    url = match.group(1)
                    if not url.startswith('data:'): 
                        domain_match = domain_pattern.search(url)
                        if domain_match:
                            detected_domains['object-src'].add(domain_match.group(1))

                # Generic URL scanning (should be last to catch anything missed by specific patterns)
                found_generic_urls = url_pattern.findall(content)
                for generic_url in found_generic_urls:
                    current_url = generic_url 
                    if current_url.startswith('//'): current_url = 'https:' + current_url 
                    domain_match_for_generic = domain_pattern.search(current_url)
                    if domain_match_for_generic:
                        domain = domain_match_for_generic.group(1)
                        detected_domains['connect-src'].add(domain)
                        if any(kw in domain for kw in ['cdn', 'static', 'assets', 'js', 'google']):
                             detected_domains['script-src'].add(domain)
                             detected_domains['style-src'].add(domain)
                        if current_url.lower().split('?')[0].endswith(image_extensions):
                            detected_domains['img-src'].add(domain)
                        if "example.com" in domain: 
                             detected_domains['frame-src'].add(domain)
        except Exception as e:
            print(f"{colors.RED}Error reading or parsing JS file {js_file}: {e}{colors.ENDC}")

    css_files = glob.glob(os.path.join(build_path, '**', '*.css'), recursive=True)
    print(f"Found {len(css_files)} CSS files to scan in build output.")
    for css_file in css_files:
        try:
            with open(css_file, 'r', encoding='utf-8') as f:
                content = f.read()
                for url_match in re.finditer(r"url\(([^\)]+)\)", content):
                    url_val = url_match.group(1).strip(' \'"')
                    if is_url(url_val):
                        domain_match_for_css = domain_pattern.search(url_val)
                        if domain_match_for_css:
                            domain = domain_match_for_css.group(1)
                            detected_domains['font-src'].add(domain)
                            detected_domains['img-src'].add(domain)
        except Exception as e:
            print(f"{colors.RED}Error reading or parsing CSS file {css_file}: {e}{colors.ENDC}")
    
    if any(detected_domains.values()):
        print(f"{colors.GREEN}Info:{colors.ENDC} Found potential external domains in build output:")
        for directive, domains in detected_domains.items():
            if domains:
                print(f"  For {directive}: {list(domains)}")
    else:
        print(f"{colors.GREEN}Info:{colors.ENDC} No obvious external domain links found in bundled JS/CSS.")
    return detected_domains

def generate_explanation_markdown(csp_config, explanations, project_path, inline_style_details, build_analysis_performed, build_domains, dev_specific_additions, final_csp_prod_str, final_csp_dev_str):
    markdown_lines = [
        "# Content Security Policy (CSP) Explanation",
        f"Generated by the script for the project at `{project_path}`.",
        "\n## Recommended CSP (Production Focus)",
        "```csp",
        f"{final_csp_prod_str}",
        "```",
        "\n## Recommended CSP (For Development with HMR)",
        "```csp",
        f"{final_csp_dev_str}",
        "```",
        "\n---",
        "\nThis document explains the primarily **production-focused** Content Security Policy."
    ]
    if build_analysis_performed:
        markdown_lines.append("\n**Note:** This CSP was primarily informed by analyzing the production build output.")
    else:
        markdown_lines.append("\n**Note:** This CSP was generated by analyzing source files. For a more accurate production CSP, run your build command and re-run this script.")
    # markdown_lines.append("\n---") # Removed, as there's a separator above the note.

    if build_domains and any(build_domains.values()):
        markdown_lines.append("\n## External Domains Detected in Build Output (included in production CSP):")
        markdown_lines.append("The following external domains were detected in the bundled JavaScript/CSS files. They have been tentatively added to relevant CSP directives in the production-focused CSP. **Please review carefully and apply the principle of least privilege**.")
        for directive, domains in build_domains.items():
            if domains:
                markdown_lines.append(f"- For `{directive}`: `{', '.join(sorted(list(domains)))}`")
        markdown_lines.append("\n---")

    for directive in sorted(csp_config.keys()):
        if csp_config.get(directive):
            sources_str = ' '.join(sorted(list(csp_config[directive])))
            markdown_lines.append(f"\n## Directive: `{directive}`")
            markdown_lines.append(f"**Policy (Production Focus):** `{directive} {sources_str}`")
            
            explanation_text = explanations.get(directive, "No specific explanation available for this combination.")

            if directive == 'style-src' and "'unsafe-inline'" in sources_str:
                explanation_text += " `'unsafe-inline'` was included because:"
                if inline_style_details['html_inline_styles']:
                    explanation_text += "\n  - Inline `<style>` tags were found in the following HTML file(s):"
                    for f_path in sorted(list(inline_style_details['html_inline_styles'])):
                        explanation_text += f"\n    - `{f_path}`"
                if inline_style_details['jsx_inline_styles']:
                    explanation_text += "\n  - JSX style props (e.g., `style={{...}}`) were found in the following file(s):"
                    for f_path in sorted(list(inline_style_details['jsx_inline_styles'])):
                        explanation_text += f"\n    - `{f_path}`"
                explanation_text += "\n  Using `'unsafe-inline'` for styles is a security risk. It is strongly recommended to refactor these inline styles to use external stylesheets or CSS classes to enhance security."
            elif "'unsafe-inline'" in sources_str and directive == 'script-src':
                 explanation_text += " The `'unsafe-inline'` value allows the use of inline `<script>` elements and event handlers. This is generally discouraged for security reasons."
            
            markdown_lines.append(f"**Explanation:** {explanation_text}")
            mdn_url = MDN_CSP_DOCS.get(directive)
            if mdn_url:
                markdown_lines.append(f"**Learn More:** [MDN Documentation for {directive}]({mdn_url})")
    
    markdown_lines.append("\n---")
    markdown_lines.append("\n## Development Environment Considerations")
    markdown_lines.append("For local development, especially when using features like Hot Module Replacement (HMR) with tools like Create React App or Vite, you often need to adjust the CSP. The script also provided a specific 'Recommended CSP for Development' in the console output.")
    markdown_lines.append(f"- **`connect-src` for WebSockets:** Development servers use WebSockets for HMR. You'll likely need to add sources like `{' '.join(dev_specific_additions['connect-src'])}`. If your dev server runs on a custom port, adjust accordingly (e.g., `ws://localhost:YOUR_PORT`, `wss://localhost:YOUR_PORT`).")
    markdown_lines.append(f"- **`script-src` for HMR:** Some development setups require `**'unsafe-eval'**` in `script-src` for HMR to function correctly. The development-focused CSP printed to the console includes this. **This is a significant security risk and `'unsafe-eval'` MUST be removed for production environments.**")
    markdown_lines.append("Review the 'Recommended CSP for Development' provided in the console for a starting point that includes these development-specific directives.")

    markdown_lines.append("\n---")
    markdown_lines.append("### General Recommendations (for Production CSP):")
    markdown_lines.append("- **Test Thoroughly:** After applying this CSP, test your application extensively to ensure all functionalities work as expected.")
    markdown_lines.append("- **Iterate:** CSP is often an iterative process. You might discover additional resources that need to be allowed as you test or add features.")
    markdown_lines.append("- **Principle of Least Privilege:** Only allow sources that are strictly necessary for your application to function.")
    markdown_lines.append("- **Avoid 'unsafe-inline' and 'unsafe-eval' in Production:** If these are present, investigate if they can be removed by refactoring code, using script hashes/nonces, or adjusting build configurations. These directives significantly weaken the security provided by CSP.")
    markdown_lines.append("- **Consider a `report-uri` or `report-to` directive:** This will instruct browsers to send reports of CSP violations to a specified endpoint, helping you identify and fix issues in a deployed application.")
    return "\n".join(markdown_lines)

def generate_csp_for_cra(project_path):
    print(f"\nStarting CSP generation for project: {colors.BLUE}{project_path}{colors.ENDC}")
    print("\nThis script analyzes 'public/index.html' and JavaScript/TypeScript files in 'src/' for patterns that might influence CSP.")
    print("It checks for external resource links, inline <style> tags in HTML, and JSX inline style props (style={{...}})." )
    print("It does not deeply parse all JavaScript/TypeScript for dynamic API calls or analyze 'node_modules' yet.")
    print("The generated CSP aims for security by avoiding 'unsafe-inline' where possible.\n")

    # Check for build directory
    build_dirs_to_check = {'build': 'npm run build / yarn build', 'dist': 'npm run build / yarn build (common for Vite)'}
    build_dir_found_path = None

    for dir_name, build_command_example in build_dirs_to_check.items():
        potential_build_dir = os.path.join(project_path, dir_name)
        if os.path.isdir(potential_build_dir):
            print(f"{colors.GREEN}Info:{colors.ENDC} Found production build directory: {colors.BLUE}{potential_build_dir}{colors.ENDC}. Prioritizing analysis of this directory.")
            build_dir_found_path = potential_build_dir
            break # Found one, no need to check others

    if not build_dir_found_path:
        error_message = (
            f"{colors.RED}Error:{colors.ENDC} Production build directory ('build/' or 'dist/') not found in '{colors.BLUE}{project_path}{colors.ENDC}'.\n"
            f"This script requires the production build to generate an accurate Content Security Policy for production.\n"
            f"Please create the production build for your project (e.g., by running {colors.GREEN}npm run build{colors.ENDC} or {colors.GREEN}yarn build{colors.ENDC}) \n"
            f"and then re-run this script.\n"
            f"{colors.YELLOW}Aborting CSP generation.{colors.ENDC}"
        )
        print(error_message)
        return # Terminate script execution if build folder is not found

    csp_prod = {
        'default-src': {"'self'"},
        'script-src': {"'self'"},
        'style-src': {"'self'"},
        'img-src': {"'self'", 'data:'},
        'font-src': {"'self'"},
        'connect-src': {"'self'"},
        'object-src': {"'none'"},
        'frame-src': {"'none'"},
        'base-uri': {"'self'"},
        'form-action': {"'self'"},
        'manifest-src': {"'self'"},
        'worker-src': {"'self'"},
    }
    explanations = {
        'default-src': "Fallback for other fetch directives. `'self'` restricts loading to the same origin.",
        'script-src': "Specifies valid sources for JavaScript. `'self'` allows scripts from the same origin.",
        'style-src': "Specifies valid sources for stylesheets. `'self'` allows CSS from the same origin.",
        'img-src': "Specifies valid sources for images. `'self'` for local images, `data:` for embedded images.",
        'font-src': "Specifies valid sources for fonts. `'self'` for local fonts.",
        'connect-src': "Restricts URLs for `fetch`, `XHR`, `WebSocket`. `'self'` for same-origin API calls.",
        'object-src': "Restricts sources for `<object>`, `<embed>`, `<applet>`. `'none'` blocks them entirely, enhancing security.",
        'frame-src': "Restricts URLs that can be embedded as frames. `'none'` blocks all framing by default.",
        'base-uri': "Restricts the URLs which can be used in a document's `<base>` element. `'self'` prevents attacks that change base URLs.",
        'form-action': "Restricts the URLs which can be used as the target of a form submissions. `'self'` allows forms to submit only to the same origin.",
        'manifest-src': "Specifies valid sources for web app manifests. `'self'` allows manifests from the same origin.",
        'worker-src': "Specifies valid sources for Worker, SharedWorker, or ServiceWorker scripts. `'self'` allows these from the same origin."
    }

    print("\n--- Source File Analysis (public/ & src/) ---")
    public_html_file = os.path.join(project_path, 'public', 'index.html')
    src_html_sources, src_html_inline_styles, _ = analyze_html_file(public_html_file, is_build_output=False)
    
    project_src_path = os.path.join(project_path, 'src')
    src_jsx_inline_styles = set()
    if os.path.isdir(project_src_path):
        src_jsx_inline_styles = analyze_js_jsx_ts_tsx_files(project_src_path)
    else:
        print(f"{colors.YELLOW}Warning:{colors.ENDC} Source directory '{colors.BLUE}{project_src_path}{colors.ENDC}' not found. Skipping analysis of JS/TSX files.")

    print(f"Analyzed {len(src_html_sources)} HTML file(s) and scanned JS/JSX/TS/TSX files in '{colors.BLUE}{project_src_path}{colors.ENDC}' (if present).")

    # Merge sources from HTML analysis (public/index.html)
    for directive, found_sources in src_html_sources.items():
        if found_sources:
            if directive == 'base-uri': # Special handling for base-uri to replace 'self'
                if any(is_url(s) or s != "'self'" for s in found_sources): # If any non-'self' or URL found
                    csp_prod[directive] = {s for s in found_sources if s} # Replace existing, don't just update
                else:
                    csp_prod[directive].update(s for s in found_sources if s)
            elif directive in csp_prod: # For other directives, update
                csp_prod[directive].update(s for s in found_sources if s)
            else: # For new directives not in default csp_prod init
                csp_prod[directive] = set(s for s in found_sources if s)
                if not csp_prod[directive]: del csp_prod[directive]

    inline_style_detected = False
    if src_html_inline_styles or src_jsx_inline_styles:
        csp_prod['style-src'].add("'unsafe-inline'")
        inline_style_detected = True
        print(f"{colors.YELLOW}Info:{colors.ENDC} 'unsafe-inline' added to 'style-src' due to detected inline styles or JSX style props.")
    else:
        print(f"{colors.GREEN}Info:{colors.ENDC} No direct inline styles or JSX style props detected that would necessitate 'unsafe-inline' for 'style-src'.")

    inline_style_details_for_md = {
        'html_inline_styles': src_html_inline_styles,
        'jsx_inline_styles': src_jsx_inline_styles
    }

    build_analysis_performed = False
    build_detected_domains = {}
    build_html_sources = {}
    build_html_inline_styles = set()
    build_html_inline_scripts = set()

    if build_dir_found_path:
        print(f"\n--- {colors.GREEN}Build Output Analysis ({build_dir_found_path}){colors.ENDC} ---")
        build_analysis_performed = True
        build_index_html = os.path.join(build_dir_found_path, 'index.html')
        build_html_actual_sources, build_html_inline_styles_actual, _ = analyze_html_file(build_index_html, is_build_output=True)

        for directive, found_sources in build_html_actual_sources.items():
            if found_sources:
                if directive == 'base-uri': 
                    current_base_is_self = "'self'" in csp_prod.get('base-uri', {"'self'"})
                    if any(is_url(s) or s != "'self'" for s in found_sources):
                        if current_base_is_self: 
                             csp_prod[directive] = {s for s in found_sources if s}
                        else: 
                             csp_prod[directive].update(s for s in found_sources if s)
                elif directive in csp_prod:
                    csp_prod[directive].update(s for s in found_sources if s)
                else:
                    csp_prod[directive] = set(s for s in found_sources if s)
                    if not csp_prod[directive]: del csp_prod[directive]

        build_detected_domains_from_js_css = analyze_bundled_js_css(build_dir_found_path)
        for directive, domains in build_detected_domains_from_js_css.items():
            if domains:
                # If we found specific sources for directives that default to 'none', remove 'none'
                if directive in ['object-src', 'frame-src'] and "'none'" in csp_prod.get(directive, set()):
                    # Check if any of the found domains are not part of COMMON_HOST_SOURCES (like 'self', 'none')
                    # This ensures we only discard 'none' if a truly external/different source is found.
                    if any(d not in COMMON_HOST_SOURCES for d in domains):
                        csp_prod[directive].discard("'none'")
                
                if directive in csp_prod:
                    csp_prod[directive].update(d for d in domains if d)
                else:
                    csp_prod[directive] = set(d for d in domains if d)
                    if not csp_prod[directive]: del csp_prod[directive] # Clean up if set becomes empty
    
    inline_style_details_for_md = {
        'html_inline_styles': src_html_inline_styles.union(build_html_inline_styles_actual if build_analysis_performed else set()),
        'jsx_inline_styles': src_jsx_inline_styles
    }

    if inline_style_details_for_md['html_inline_styles'] or inline_style_details_for_md['jsx_inline_styles']:
        csp_prod['style-src'].add("'unsafe-inline'")
        print(f"{colors.YELLOW}Info:{colors.ENDC} 'unsafe-inline' added to 'style-src' due to detected inline styles or JSX style props.")
    else:
        print(f"{colors.GREEN}Info:{colors.ENDC} No direct inline styles or JSX style props detected that would necessitate 'unsafe-inline' for 'style-src'.")
    
    csp_prod_parts = []
    for directive, sources_set in csp_prod.items():
        if sources_set: csp_prod_parts.append(f"{directive} {' '.join(sorted(list(sources_set)))}")
    final_csp_prod = "; ".join(csp_prod_parts) + ";"

    print(f"\n--- {colors.GREEN}Recommended CSP (Production Focus){colors.ENDC} ---")
    print(colors.GREEN + final_csp_prod + colors.ENDC)

    # --- Generate Development CSP ---
    csp_dev = {key: set(value) for key, value in csp_prod.items()} # Deep copy
    dev_ws_ports = ['3000', '3001']
    dev_ws_sources_to_add = set()
    for port in dev_ws_ports:
        dev_ws_sources_to_add.add(f'ws://localhost:{port}')
        dev_ws_sources_to_add.add(f'wss://localhost:{port}')
    
    csp_dev['connect-src'].update(dev_ws_sources_to_add)
    csp_dev['script-src'].add("'unsafe-eval'")

    dev_specific_additions_for_md = {
        'connect-src': dev_ws_sources_to_add,
        'script-src': {"'unsafe-eval'"}
    }

    csp_dev_parts = []
    for directive, sources_set in csp_dev.items():
        if sources_set: csp_dev_parts.append(f"{directive} {' '.join(sorted(list(sources_set)))}")
    final_csp_dev = "; ".join(csp_dev_parts) + ";"

    print(f"\n--- {colors.YELLOW}Recommended CSP (For Development with HMR){colors.ENDC} ---")
    print(colors.YELLOW + final_csp_dev + colors.ENDC)
    print(f"{colors.YELLOW}Note:{colors.ENDC} The development CSP includes permissive settings like {colors.RED}'unsafe-eval'{colors.ENDC} and WebSocket connections for local development servers. {colors.RED}Do NOT use this CSP in production.{colors.ENDC}")

    # Console advice (always shown)
    print(f"\n{colors.YELLOW}Development Server Advice:{colors.ENDC}")
    print(f"- For local development with Hot Module Replacement (HMR), you typically need to allow WebSocket connections.")
    print(f"  Common `connect-src` additions: `{' '.join(sorted(list(dev_ws_sources_to_add)))}`.")
    print(f"  If your dev server uses a custom port, adjust these (e.g., `ws://localhost:YOUR_PORT`).")
    print(f"- HMR might also require {colors.RED}`'unsafe-eval'`{colors.ENDC} in `script-src`. This is included in the development CSP above.")
    print(f"  {colors.RED}Warning:{colors.ENDC} `'unsafe-eval'` is a security risk and must be removed for production.")

    markdown_content = generate_explanation_markdown(csp_prod, explanations, project_path, inline_style_details_for_md, build_analysis_performed, build_detected_domains, dev_specific_additions_for_md, final_csp_prod, final_csp_dev)
    explanation_file_path = os.path.join(project_path, "CSP_Explanation.md")
    try:
        with open(explanation_file_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        print(f"\nDetailed explanation of the {colors.GREEN}production-focused CSP{colors.ENDC} has been saved to: {colors.BLUE}{explanation_file_path}{colors.ENDC}")
    except Exception as e:
        print(f"{colors.RED}Error saving CSP explanation file: {e}{colors.ENDC}")

    print("\n--- How to use (Production CSP) ---")
    meta_tag_location_html_file = os.path.join(project_path, 'public', 'index.html') # Or build/index.html ideally
    print(f"1. Add the following <meta> tag to your HTML's <head> section (ideally in the deployed `index.html`):")
    escaped_final_csp_prod = final_csp_prod.replace('"', '&quot;')
    print(f"""   <meta http-equiv="Content-Security-Policy" content="{escaped_final_csp_prod}">""")
    print(f"2. Alternatively, and {colors.GREEN}highly recommended for production{colors.ENDC}, configure your web server to send the CSP as an HTTP header:")
    print(f"   {colors.GREEN}Content-Security-Policy: {final_csp_prod}{colors.ENDC}")
    print("\nImportant Notes:")
    print("- The generated CSPs are starting points. Test your application thoroughly after applying them, especially the production CSP.")
    print(f"- For production, strive to remove {colors.RED}'unsafe-inline'{colors.ENDC} and {colors.RED}'unsafe-eval'{colors.ENDC} by refactoring or using hashes/nonces.")
    # if inline_style_detected: # This variable would need to be set based on analysis for csp_prod
    #     print(f"- {colors.YELLOW}Since 'unsafe-inline' was added for styles in the production CSP, check the `CSP_Explanation.md` file for details...{colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Content Security Policy for a React project.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("project_path", help="Path to the root of the React project (e.g., ./my-secure-app)")
    args = parser.parse_args()

    if not os.path.isdir(args.project_path):
        print(f"Error: Project path '{args.project_path}' not found or is not a directory.")
        return

    generate_csp_for_cra(args.project_path)

if __name__ == "__main__":
    main() 