import React from 'react';
import { Link as ScrollLink } from 'react-scroll';
import { Link as RouterLink, BrowserRouter as Router } from 'react-router-dom';

import "./Connect.css";
function Connect(props) {

    // a way around of style tag in svg
    const st0 = { fill: '#ffffff' };

    return (
        <div className="container">
            <Router>
                <RouterLink id="linkedin" className="connect-logo connect-button" to={props.linkedin} target="_blank" rel="noopener noreferrer">
                    <svg fill="#6200ea" height="100%" width="100%" version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlnsXlink="http://www.w3.org/1999/xlink" viewBox="-143 145 512 512" xmlSpace="preserve">
                        <g id="SVGRepo_bgCarrier" strokeWidth="0"></g>
                        <g id="SVGRepo_tracerCarrier" strokeLinecap="round" strokeLinejoin="round"></g>
                        <g id="SVGRepo_iconCarrier">
                            <path d="M113,145c-141.4,0-256,114.6-256,256s114.6,256,256,256s256-114.6,256-256S254.4,145,113,145z M41.4,508.1H-8.5V348.4h49.9V508.1z M15.1,328.4h-0.4c-18.1,0-29.8-12.2-29.8-27.7c0-15.8,12.1-27.7,30.5-27.7c18.4,0,29.7,11.9,30.1,27.7C45.6,316.1,33.9,328.4,15.1,328.4z M241,508.1h-56.6v-82.6c0-21.6-8.8-36.4-28.3-36.4c-14.9,0-23.2,10-27,19.6c-1.4,3.4-1.2,8.2-1.2,13.1v86.3H71.8c0,0,0.7-146.4,0-159.7h56.1v25.1c3.3-11,21.2-26.6,49.8-26.6c35.5,0,63.3,23,63.3,72.4V508.1z"></path>
                        </g>
                    </svg>
                </RouterLink>


                <RouterLink id="github" className="connect-logo connect-button" to={props.github} target="_blank" rel="noopener noreferrer">
                    <svg viewBox="0 0 20 20" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlnsXlink="http://www.w3.org/1999/xlink" fill="#6200ea">

                        <g id="SVGRepo_bgCarrier" strokeWidth="0"></g>
                        <g id="SVGRepo_tracerCarrier" strokeLinecap="round" strokeLinejoin="round"></g>
                        <g id="SVGRepo_iconCarrier">
                            <title>github [#142]</title>
                            <desc>Created with Sketch.</desc>
                            <defs></defs>
                            <g id="Page-1" stroke="none" strokeWidth="1" fill="none" fillRule="evenodd">
                                <g id="Dribbble-Light-Preview" transform="translate(-140.000000, -7559.000000)" fill="#6200ea">
                                    <g id="icons" transform="translate(56.000000, 160.000000)">
                                        <path d="M94,7399 C99.523,7399 104,7403.59 104,7409.253 C104,7413.782 101.138,7417.624 97.167,7418.981 C96.66,7419.082 96.48,7418.762 96.48,7418.489 C96.48,7418.151 96.492,7417.047 96.492,7415.675 C96.492,7414.719 96.172,7414.095 95.813,7413.777 C98.04,7413.523 100.38,7412.656 100.38,7408.718 C100.38,7407.598 99.992,7406.684 99.35,7405.966 C99.454,7405.707 99.797,7404.664 99.252,7403.252 C99.252,7403.252 98.414,7402.977 96.505,7404.303 C95.706,7404.076 94.85,7403.962 94,7403.958 C93.15,7403.962 92.295,7404.076 91.497,7404.303 C89.586,7402.977 88.746,7403.252 88.746,7403.252 C88.203,7404.664 88.546,7405.707 88.649,7405.966 C88.01,7406.684 87.619,7407.598 87.619,7408.718 C87.619,7412.646 89.954,7413.526 92.175,7413.785 C91.889,7414.041 91.63,7414.493 91.54,7415.156 C90.97,7415.418 89.522,7415.871 88.63,7414.304 C88.63,7414.304 88.101,7413.319 87.097,7413.247 C87.097,7413.247 86.122,7413.234 87.029,7413.87 C87.029,7413.87 87.684,7414.185 88.139,7415.37 C88.139,7415.37 88.726,7417.2 91.508,7416.58 C91.513,7417.437 91.522,7418.245 91.522,7418.489 C91.522,7418.76 91.338,7419.077 90.839,7418.982 C86.865,7417.627 84,7413.783 84,7409.253 C84,7403.59 88.478,7399 94,7399" id="github-[#142]"></path>
                                    </g>
                                </g>
                            </g>
                        </g>
                    </svg>
                </RouterLink>



                <ScrollLink id="gmail" className="connect-logo connect-button" to={props.contact} smooth={true} duration={500}>
                    <svg xmlns="http://www.w3.org/2000/svg" aria-label="Gmail" role="img" viewBox="-76.8 -76.8 665.6 665.6" fill="#000000">
                        <g id="SVGRepo_bgCarrier" strokeWidth="0">
                            <rect x="-76.8" y="-76.8" width="665.6" height="665.6" rx="332.8" fill="#6200ea"></rect>
                        </g>
                        <g id="SVGRepo_tracerCarrier" strokeLinecap="round" strokeLinejoin="round"></g>
                        <g id="SVGRepo_iconCarrier">
                            <rect width="512" height="512" rx="15%" fill="#6200ea"></rect>
                            <path id="gmail-1" d="M158 391v-142l-82-63V361q0 30 30 30" fill="#d4d4d4"></path>
                            <path id="gmail-2" d="M154 248l102 77l102-77v-98l-102 77l-102-77" fill="#e0e0e0"></path>
                            <path id="gmail-3" d="M354 391v-142l82-63V361q0 30-30 30" fill="#ebebeb"></path>
                            <path id="gmail-4" d="M76 188l82 63v-98l-30-23c-27-21-52 0-52 26" fill="#f5f5f5"></path>
                            <path id="gmail-5" d="M436 188l-82 63v-98l30-23c27-21 52 0 52 26" fill="#ffffff"></path>
                        </g>
                    </svg>
                </ScrollLink>



                <RouterLink id="resume" className="connect-logo" to={props.resume} target="_blank" rel="noopener noreferrer">
                    <svg
                        version="1.1"
                        id="_x32_"
                        xmlns="http://www.w3.org/2000/svg"
                        xmlnsXlink="http://www.w3.org/1999/xlink"
                        viewBox="0 0 512 512"
                        xmlSpace="preserve"
                        fill="#ffffff"
                    >
                        <g id="SVGRepo_bgCarrier" strokeWidth="0"></g>
                        <g id="SVGRepo_tracerCarrier" strokeLinecap="round" strokeLinejoin="round"></g>
                        <g id="SVGRepo_iconCarrier">
                            {/* <style type="text/css">.st0{fill:#FFFFFF}</style> */}
                            <g>
                                <path className="st0" style={st0} d="M276.239,252.183c-6.37,2.127-13.165,3.308-20.239,3.308c-7.074,0-13.87-1.181-20.24-3.308c-46.272,7.599-70.489,41.608-70.489,82.877H256h90.728C346.728,293.791,322.515,259.782,276.239,252.183z"></path>
                                <path className="st0" style={st0} d="M256,240.788c27.43,0,49.658-22.24,49.658-49.666v-14.087c0-27.426-22.228-49.659-49.658-49.659c-27.43,0-49.658,22.233-49.658,49.659v14.087C206.342,218.548,228.57,240.788,256,240.788z"></path>
                                <path className="st0" style={st0} d="M378.4,0H133.582C86.234,0,47.7,38.542,47.7,85.899v340.22C47.7,473.476,86.234,512,133.582,512h205.695h13.175l9.318-9.301l93.229-93.229l9.301-9.31v-13.174V85.899C464.3,38.542,425.766,0,378.4,0z M432.497,386.985H384.35c-24.882,0-45.074,20.183-45.074,45.073v48.139H133.582c-29.866,0-54.078-24.221-54.078-54.078V85.899c0-29.874,24.212-54.096,54.078-54.096H378.4c29.876,0,54.096,24.222,54.096,54.096V386.985z"></path>
                            </g>
                        </g>
                    </svg>
                    <span className="text">Resume</span>
                </RouterLink>
            </Router>
        </div>
    );
}

export default Connect;
