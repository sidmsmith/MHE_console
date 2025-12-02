// Vercel Analytics - load the insights script
// This script is automatically provided by Vercel when Analytics is enabled
(function() {
  const script = document.createElement('script');
  script.src = '/_vercel/insights/script.js';
  script.defer = true;
  script.onerror = function() {
    console.warn('Vercel Analytics script failed to load. Make sure Analytics is enabled in Vercel dashboard and the app is redeployed.');
  };
  document.head.appendChild(script);
})();

