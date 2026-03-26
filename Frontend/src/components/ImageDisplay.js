// import React from 'react';
// import './ImageDisplay.css';
// import madhyapradeshpolice from '../assets/images/madhyapradeshpolice.jpg'; // Adjust relative path if necessary

// import madhyapradeshgov from 'D:/Repo/TraceHost/Frontend/src/assets/images/madhyapradeshgov.jpg' ;

// const ImageDisplay = () => {
//   return (
//     <div className ="image-container">
//         <a href = "https://www.mppolice.gov.in" target= "_blank" rel="noopener noreferrer" >
//             <img
//             src={madhyapradeshpolice}
//             alt="Madhya Pradesh Police"
//             className="image-style"
//             />
            
            
//         </a> 
//         <div class="logo-title">
// 				<h1>Madhya Pradesh Police</h1>
// 				<small>"Desh Bhakti- Jan Seva"</small>
// 		</div>  
//                 <div className  ="image2-container">
//                 <a href = "https://mp.gov.in" target= "_blank" rel="noopener noreferrer" >
//                     <img
//                     src={madhyapradeshgov}
//                     alt="Madhya Pradesh Government"
//                     className="image2-style"
//                     />
//                 </a>
//             </div>
//     </div>
// );
// };

// export default ImageDisplay;

import React from 'react';
import './ImageDisplay.css';
import madhyapradeshpolice from '../assets/images/madhyapradeshpolice_1.jpg'; // Adjust relative path if necessary
import madhyapradeshgov from 'D:/Repo/TraceHost/Frontend/src/assets/images/madhyapradeshgov.jpg';

const ImageDisplay = () => {
  return (
    <div className="image-container">
      <div className="logo-title">
        <h1>Madhya Pradesh Police</h1>
        <small>"Desh Bhakti- Jan Seva"</small>
      </div>

      <a href="https://www.mppolice.gov.in" target="_blank" rel="noopener noreferrer">
        <img
          src={madhyapradeshpolice}
          alt="Madhya Pradesh Police"
          className="image-style"
        />
      </a>

      <div className="image2-container">
        <a href="https://mp.gov.in" target="_blank" rel="noopener noreferrer">
          <img
            src={madhyapradeshgov}
            alt="Madhya Pradesh Government"
            className="image2-style"
          />
        </a>
      </div>
    </div>
  );
};

export default ImageDisplay;