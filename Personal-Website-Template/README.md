# Personal Website Template

Welcome to the Personal Website Template! This web app is designed to help you create a personalized website easily. It's particularly useful for computer science students, freshers, software professionals, data professionals, and anyone else looking to showcase their work and profile. The template is built using React.js, HTML, CSS, and JavaScript.

![Personal Website Screenshot](./src/components/images/personal_website_template_ss.png)

## Table of Contents
1. [Key Features](#key-features)
2. [Technologies Used](#technologies-used)
3. [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Running the Project](#running-the-project)
4. [Personalizing the Project](#personalizing-the-project)
    - [Changes in the `./public` Folder](#changes-in-the-public-folder)
    - [Changes in the `./src` Folder](#changes-in-the-src-folder)
5. [Hosting on GitHub](#hosting-on-github)
6. [Helpful Websites](#helpful-websites)
7. [Contributing](#contributing)
8. [License](#license)
9. [Contact](#contact)

## Key Features

- **Customizable Home Section**: Personalize your name, introduction, and animation.
- **Skills Showcase**: Display your skills with customizable icons and animations.
- **Education and Experience**: List your educational background and professional experience.
- **Projects Section**: Highlight your projects with screenshots and links.
- **Contact Form**: Simple contact form with Formspree integration.
- **Responsive Design**: Optimized for desktop and mobile devices.

## Technologies Used

- **React.js**: For building the user interface.
- **HTML**: For the structure of the web pages.
- **CSS**: For styling the application.
- **JavaScript**: For interactivity and functionality.
- **Node.js**: Required to run the development server for the frontend application.

## Getting Started

### Prerequisites

- Node.js (v12.x or later)

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/NJITCDS/Personal-Website-Template.git
    ```
2. Navigate to the project directory:
    ```bash
    cd Personal-Website-Template
    ```
3. Install the dependencies:
    ```bash
    npm install
    ```

### Running the Project

1. Start the application:
    ```bash
    npm start
    ```
2. Open your browser and navigate to `http://localhost:3000`.

## Personalizing the Project

### Changes in the `./public` Folder

- **Website Icon and Title** (`./public/index.html`)
    - Change the profile photo or logo by replacing `avatar.png` in the `./public` folder and update the reference in line 6 of `index.html`.
    - Update the website title in `index.html` at line 9.

### Changes in the `./src` Folder

- **Home Section Name and Introduction** (`./src/App.js`)
    - Update your name at line 31 and introduction at line 34 in `App.js`.

- **Home Section Animation** (`./src/App.js`)
    - Find and customize an animation from [LottieFiles](https://lottiefiles.com/) and save the `.json` file in `./src/components/animations`. Reference the file at line 42 in `App.js`.

- **Home Section Connection Links** (`./src/components/Connect.js`)
    - Update your LinkedIn, GitHub, and resume links in `Connect.js`.

- **Nav Bar Profile Image/Logo** (`./src/components/Navbar.js`)
    - Replace `avatar.png` in the `./src/components/images` folder and update the reference at line 17 in `Navbar.js`.

- **Skills Section** (`./src/components/Skills.js`)
    - Edit the `skillsSection` constant at line 8 in `Skills.js` to update your skills and their icons.

- **Education and Experience** (`./src/components/Education.js`, `./src/components/Experience.js`)
    - Update your education details in the `education` constant at line 3 in `Education.js`.
    - Update your experience details in the `experience` constant at line 3 in `Experience.js`.

- **Projects** (`./src/components/Projects.js`)
    - Add your projects to the `projects` constant in `Projects.js`.
    - **Recommended Image Ratio**: For best results, use images with a 16:9 ratio for project screenshots.

- **Contact Section** (`./src/components/Contact.js`)
    - Update your email, Formspree endpoint, and Google Maps iframe code in `Contact.js`.

## Hosting on GitHub

1. Add homepage to `package.json`:
    ```json
    "homepage": "https://myusername.github.io/my-app",
    ```
    Replace `myusername` with your GitHub username and `my-app` with your repository name.

2. Install `gh-pages`:
    ```bash
    npm install --save gh-pages
    ```

3. Deploy the site:
    ```bash
    npm run deploy
    ```

4. Configure GitHub Pages:
    - Go to your repository settings on GitHub.
    - Select `Pages` from the menu.
    - Ensure the branch is set to `gh-pages`.

## Helpful Websites

- **[LottieFiles](https://lottiefiles.com/)**: Customize and download animations.
- **[SVGRepo](https://www.svgrepo.com/)**: Source for SVG icons.
- **[ChatGPT](https://chatgpt.com/)**: AI tool for explanations, debugging, and content enhancement.
- **[CodePen](https://codepen.io/)**: Experiment with HTML, CSS, and JS elements.
- **[CodeSandbox](https://codesandbox.io/)**: Create and run React apps.
- **[Formspree](https://formspree.io/)**: Handle form submissions and get email notifications.
- **[Crop Circle](https://crop-circle.imageonline.co/#circlecropresult)**: Crop images into circles.

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create your feature branch:
    ```bash
    git checkout -b feature/AmazingFeature
    ```
3. Commit your changes:
    ```bash
    git commit -m 'Add some AmazingFeature'
    ```
4. Push to the branch:
    ```bash
    git push origin feature/AmazingFeature
    ```
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For inquiries regarding this project, please contact:

- GitHub: [Koustubh Sahu](https://github.com/KoustubhSahu)

---

Thank you for using the Personal Website Template! We hope it helps you create a stunning personal website.
