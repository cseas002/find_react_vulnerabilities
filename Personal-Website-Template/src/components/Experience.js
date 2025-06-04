import React from 'react';

const experience = [
  {
    position: 'Software Developer',
    company: 'Awesome Company',
    duration: 'Jan 2023 - Present',
    detail: 'Created Full-Stack applications using React.js, Node.js, and Express.js.',
  },
  {
    position: 'QA Engineer',
    company: 'Second Awesome Company',
    duration: 'Oct 2021 - Dec 2022',
    detail: 'Wrote test cases and performed manual testing for a web application.',
  },
  {
    position: 'Software Developer Intern',
    company: 'Thrid Awesome Company',
    duration: 'Feb 2019 - Jul 2021',
    detail: 'Created APIs using Node.js and Express.js for a web application.',
  }
];

const Experience = () => {
  return (
    <div className="timeline" id="experience">
      <div className="timeline-container">

        {experience.map((item, index) => (
          <div key={index} className={`timeline-row ${index%2===0 ? "timeline-left" : "timeline-right" }`}>
            <div className="timeline-content active">
              <h3 className="timeline-heading">{item.position}</h3>
              <p className="timeline-subheading">{item.company}</p>
              <p className="timeline-duration">{item.duration}</p>
              <p className="timeline-detail">{item.detail}</p>
            </div>

            <div className="timeline-content" />
          </div>
        ))}
      </div>
      <div className="timneline-spine"> </div>
    </div>
  );
}

export default Experience;
