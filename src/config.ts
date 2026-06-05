export const getBackendUrl = () => {
  // If we are running on AI Studio environment, we can just use the relative URL (empty string)
  // this connects to the Express backend deployed in the same container.
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    // Check if we are running the app inside AI Studio (dev or preview share links)
    if (hostname.includes('run.app')) {
        return ''; 
    }
  }

  // For the Android APK/Phone, we use your Render backend to avoid CORS restrictions
  // Make sure your Render backend has the latest code deployed!
  return 'https://pwnnet-toolkit.onrender.com';
};
