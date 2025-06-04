import React, { useEffect, useState } from 'react';
import './Animation.css';
import Lottie from 'react-lottie';


// Recuried attribute:  fileName
// Optional attribute: width (default 100%), height (default unset)
const Animation = (props) => {
  const [animationData, setAnimationData] = useState(null);

  useEffect(() => {
    // Function to dynamically import animation data based on the provided file name
    const loadAnimation = async (fileName) => {
      try {
        const animation = await import(`./animations/${fileName}`);
        setAnimationData(animation.default); // `.default` is necessary when using ES modules
      } catch (error) {
        console.error("Error loading animation file:", error);
      }
    };

    if (props.fileName) {
      loadAnimation(props.fileName);
    }
  }, [props.fileName]);

  if (!animationData) {
    return <div>Loading...</div>;
  }

  const defaultOptions = {
    loop: true,
    autoplay: true,
    animationData: animationData, 
    rendererSettings: {
      preserveAspectRatio: "xMidYMid slice"
    }
  };

  return (
    <div className="animation">
      <Lottie 
        options={defaultOptions}
        height={props.height ? props.height : 'unset'}
        width={props.width ? props.width : '100%'}
      />
    </div>
  );
};

export default Animation;
