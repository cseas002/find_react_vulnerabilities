Help me in writing readme and license for my project, Repo name is "Personal Website Template"
I used react.js, html, css, js for this web app. 
add other relevant sections like License and technology and other things to it. 

Create an index for this readme as this is gonna be too long.
Organise it very nicely, so that it looks good. 
Make it look lively and attractive. 

I am not sure which license to use, I guess MIT license should be fine as this is meant for others to use and they cna use it in any way they like. So mention that in the lisence section as well.

I created a personal website template and I am filing out demo data  in it , like fake name designation projects and so on, It is mainly focused on computer science students, fresher, software professional, data professional, and such people, but people from other fields are welcome to use this template, 

Below is all the content of the readme file I can think of, you need to structure it better and make it look good. below I talk about the steps on how to personalise this project and how to host it in github. I have also added some of the useful websites which can be helpful in creating this website. When I talk about those websites in the description or instructions, mentions that they can read more about it below, and link it. Add you own explanation where needed, for example for the helpfull websites or github deployment.  


Changes in ./public folder 
-Website icon and Website title (./public/index.html)
Here you would need to have a profile photo or your personal logo which will be your website icon. In this template we are using avatar.png as a placeholder, you can change it to have a more personalised icon. TO change it paste the image in ./public folder, adn then inside index.html you can reference that image in line 6. 
While inside index.html you can also change the website title to have a more suitable title.

both these changes are recommended. 



Changes in ./src folder 
-Home Section Name and introduction (./src/App.js)
To change your name and introduction for the website, simply got to ./src/App.js and type your name at line 31, and your introduction at line 34. Save this and your changes would be reflected in your website.

-Home section Animation (./src/App.js)
To change the animation in home section, you need to find a suitable animation from lottiefiles.com, you can edit it to  match your website color scheme, which is  #6200ea, #f5f5f5 along with white i.e. #ffffff. You can save this customised .json file from lottiefiles.com into ./src/components/animations folder adn then reference this animation in ./src/App.js at line 42, (fileName attribute inside Animation tag). it is important that all the animation files are stored in ./src/components/animations, this web app is configured accordingly. 


-Home section connection links (./src/components/Connect.js)
inside your ./src folder you can change the address for your LinkedIn profile, GitHub profile and resume. We don't give email here, email icon scrolls down to contact part. 
For resume link just put your resume on google drive and share that document link here. Make sure to change the access so that any one with he link can access it. As of now this points to Harvard resume template. 

For more customised changes you can visit ./src/components/Connect.js, and change what you need accordingly. 

If you wish to change the animation of the guy coding next to introduction

Changes in ./src/components folder
- Nav bar profile image/logo (./src/components/Navbar.js)
here you can change the placeholder profile pic in navbar with your profile pic or a personal logo.  (personal logo can be you initials or anything you design). Just put your desired image in ./src/components/images folder and then reference that image in ./src/components/Navbar.js, at line 17 inside img tag. replace avatar.png with whatever you wish to have displayed.
NOTE: do not change the class name which is avatar, you can change the alt text but keep the class name as avatar, changing it will result in improper styling. 


-Skills section, editing the skills (./src/components/Skills.js)
For the skills section , you can make some changes at ./src/components/Skills.js 
you can edit the constant "skillsSection" defined at line 8. 
I have divided skills in 4 groups, Frontend, Backend, Database, Other Technologies. 
make sure that you keep the formatting of the array, , it is an array of js objects, each object in the array has the following attribute
name (name of the skills group, you can change this)
class (do not change this, if you change this you well have to reflect the change sin Skills.css. It is not advisable to change this class name.)
animation (this is a custom animation from lottiefiles.com, you can get your own custom animation from here and replace the existing one)
skills (this is an array of the skills you will display in this group. Each object in this array has 2 attributes, "name", which is name of the skill and "icon" which is icon for this skill)


You can change the skill name just by changing the name attribute of the object in skills array,( line 10, 12,14,16). For change in icon, you need to download the icon and save the image in ./src/components/images/icon folder, and then reflect that icon name in the relative object's icon attribute. Be sure to save your new icon in ./src/components/images/icon adn not in ./src/components/images. As a rule all the icons would eb saved in icon sub folder, and other images such as project screenshots nand profile pic/logo  would be saved in image folder.

for change in animation, get your animation file, .json file, from lottiefiles.com (note that you can edit the animation to match teh color scheme of the fiel, we use #6200ea and #f5f5f5 along with white i.e. #ffffff), save that animation in ./src/components/animations folder and then reference that animation in the animation attribute of teh realtive object inside skillsSection constant (./src/components/Skills.js line 8).


If you choose to reduce the number of skill groups, make sure to adjust the grid styling in ./src/components/Skills.css, starting at line 63 (Responsive design) accordingly,
Or else styling might not look very good. the website will work but the styling might not look good)


-Background Section Education Content (./src/components/Education.js)
To enter your education detial add your detials in ./src/components/Education.js in "education" constant definaed at line 3. 
Type in your degree, university, duration or year, and detial. I have metioned some random gpa as detial, you can add you gpa or something else. Even if you choose to no have any detials shown here, you MUST still keep the detial attribute here, just make it blank, but do not delete it.  
You can choose to reduce the number of degree details here. Although it is recommended that you keep the 3 3 degree details

-Background Section Experience Content (./src/components/Experience.js)
Similar to education details, you can change your Experience details by making changes to  "experience" constant in ./src/components/Experience.js file defined at line 3. Similar to Education detail, it is important to have the detail attribute. If you wish to not show it, make the content of it empy, (empty string) but keep it. 
also you can reduce the number or experiences you wana show but it is recommended to keep it to 3. 

-Background Section Animation (./src/components/Background.js)
This would be similar to changing animation in home section. You will need to find a suitable animation from lottiefiles.com and download it to ./src/components/animations. And then reference the name of your download in   ./src/components/Background.js at line 23. ( inside Animation tag, attribute filename)


-Projects (./src/components/Projects.js)
In order to showcase your project, you will need to update the constant "projects". "projects" is an array of js objects with following fields,
title (title of your project)
technologies (array of technologies/tools used in this project which you would wanna highlight)
summary (a brief summary of what the project is about)
screenshot (name of the screenshot image in the ./src/components/images folder, if this parameter in not provided then project title would eb displayed)
gitHub (link to GitHub repo where then project is saved)
liveURL (link to a live website if being hosted somewhere)

You can create as many objects as you wish and that many project cards would be generated. You can change the parameters accordingly.  
for technologies array, only highlight few of the technologies for each project, too much content here might disturb the styling. Similar to technologies, try to keep the summary brief, as a long summary may result in styling issue. screenshot, github, and liveURL are not required fields. To display an image for your project, you will have to place the screenshot of the project in the ./src/components/images folder, and then reflect the name of the screenshot in the screenshot field of the respective object. If you choose not to have screenshot field, title of the project would be visible instead of image. However if you provide a wrong name for the screenshot, it may result in the app crashing, so be aware of that, if you do not wish to display screenshot, remove that field form respective js object. If github or liveURL is not provided (field not included in the object), then on hover, their icon would not be visible. 
If required you can change the padding and other style properties in ./src/components/Projects.css


NOTE: If you are including github link to your project, make sure you have a nice readme file describing the project very well, here you can go in detail and talk about your project, technology used and other things. Be as detailed as possible, you can generate a nice readme file using chatGPT or other AI tools, all you have to do is provide a description about your project and its technology, and you will get a nice readme file. You can also generate license using the same process. 



-Contact section (./src/components/Contact.js)
YOu have 3 things to chnage here, 
Email
formspree endpoint
map

To change your email, simply change the value fo the constant email at line 7 in the file ./src/components/Contact.js
formspree is a service which we use in thie project to handle our contact form, and get notified when someone submits it. it is FREE, just like all the services we are using in this project. Integrating this serive is super easy, all you need to do is provide your formspree endpoint in the action attribute of your form. TO get your end point, you end to create an account in the formspree website,, create a new form anbd you will be presented with your own end point, just copy that and paste it as the value of action attribute in line 34 of ./src/components/Contact.js
Showcasing your location in the map is easier than what you are thinking probably. Just go to google map, search for your loaction, it can be your locality or city or state or even country if you wish to showcase that, then go to share, copy the iframe code provided and paste this in the place of existing iframe code at line 61 in ./src/components/Contact.js. After pasting it, you need to make 1 more change, inside your iframe code, there would be style attribute, it would be something like, 
style="border:0;"
you end to change it to make it 
style={{border:0}}
replacing double inverted commas with double curly braces. and removing the semicolon

This is an important change, as react has a special way of inline styling. Html accepts inline styling as a stirng, but in react inline styling is being accepted as a js object, and because we are adding a js object in between HTML code, we need to enclose it in curly braces, hence 2 set of curly braces.  


once you do this, you are good to go,
with these steps you have your own personal website, and you can showcase it. you can host this website in github itself. 

Hosting your React app in github:

You can visit "https://create-react-app.dev/docs/deployment/#github-pages" to see the official guide to host react app using gh-pages, or you can follow the following detailed steps which explains the same. 

Step 1: Add homepage to package.json
first we need to add the following to package.json,
  "homepage": "https://myusername.github.io/my-app",
where "myusername" is your github username and "my-app" is the name of your repo
Replace the existing homepage link ("https://KoustubhSahu.github.io/Personal-Website-Template") with your link

Step 2: Ensuring gh-pages is installed
after this you need to gh-pages library installed in your project, if you followed thi readme file and did a "npm i" at teh start you shouwl already ahave this, but if you don't you can always install it now by the command 

"npm install --save gh-pages"

Step 3: Deploy the site by running npm run deploy
Commit all your changes and push the lates code to github. 
Now you need to run the command 
npm run deploy

to deploy teh app in github. 

Ste 4: Making sure Github pages use gh-pages
Go to your github repository, 
go to settings,
select pages from the menu on the left, 
Here under branch github-pages should be selected, if for some reason some other branch is selected, change it to gh-pages.



and just like that you have created and hosted your own personal website. Congratulations.🥳


NOTE: It might take a few minutes for the change to be reflected and the link to work. 





Helpful Websites:
lottiefiles.com
This is a wonderful tool in a web dev's arsenal. it provides you with wonder full animation which you can easily integrate in your website. They have a subscription model, but also offer free tier, and you can find many such animation in free tier. You can select an animation, try different color pallet o n it, or create a new pallet of your own. 
If you need more customising, you can edit the animation in the lottie editor, and then change the color of individual elements to match your needs,. In this project our color pallet is #6200ea, #f5f5f5 along with white i.e. #ffffff. You an of course use other colors if you choose to, just make sure it matches well with the existing pallet.  You can then download the image in json format, save it in ./src/components/animations for this project, and then reflect the name of the downloaded animation in the relative component (Animation tag, or a constant holding the data)

https://www.svgrepo.com/
This is the best place to find svg. I prefer working with svg as compared to image fields, whenever possible. All the icons in this websites are svg files, and almost all are from this website. 
svg give you a wonderful ability to customise your file without much effort, you can change the color, size, padding, shape of your file while downloading it. you can download it as a .svg file which you can later import using img tag, or just copy the code for that particular svg and use it directly in your web app. Getting svg code rather than downloading the file gives you an advantage, which is that you can change the color  and other attributes of your svg dynamically by targeting it using is or class. 

https://chatgpt.com/ (or any other AI chatbot)
Needless to say, it is a wonderful tool. If you are using it to create everything in your project, then may be you are using it wrong. I recommend it using as:
- Explainer: explain any particular concept in detail with example, or get an idea on how to proceed if you feel stuck, even discuss approaches to find out the most efficient one. 
- Debugger: Debugging a code can be frustrating, if you encounter an error and couldn't figure why you are encountering it, you can provide some of the code and ask why are you getting that particular error and how can you resolve it. this could be very helpful if you error is occurring due to a silly thing like spelling mistake, this could save you a whole lot of time. I encounter such error more than  would like to admit.  
- Content Enhancer: Very useful when writing Readme file or license, you just have to provide the basic content and it would populate it, format it and present it in a nice way. Also useful if you need some content to fit in your website, like project summary or Profile introduction.  


https://codepen.io/
An awesome place to experiment with certain elements of your website. If mid way through development I wanna try something new, or wanna change the existing element, I often copy past part of my code here and experiment with it, finding out the best way to make it work. Also works for understand working of any particular concept and see it in action. Unfortunately here you are restricted to HTML CSS JS can't run React code here. 


https://codesandbox.io/
Similar to codepen, but only better. Here you can test out React apps. You can even create and run React apps from here. wonderful tool.


https://formspree.io/
We use this for our contact form, this service is free and helps you to get emails notification when someone fills out a form to reach you out.
All you can to do is create an account, create a form, and then copy the end point of your form and paste it as action attribute of form tag in Contact.js. It is wonderful tool again. 

https://crop-circle.imageonline.co/#circlecropresult
Usefull in cropping images in circle. Can be used for icons if necessary.
