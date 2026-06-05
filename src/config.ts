export const getBackendUrl = () => {
  // Check if we have a user-defined override in localStorage
  if (typeof window !== 'undefined') {
    const override = localStorage.getItem('pwnnet_backend_url');
    if (override) return override;

    const hostname = window.location.hostname;
    // Check if we are running the app inside AI Studio (dev or preview share links)
    if (hostname.includes('run.app')) {
        return ''; 
    }
    // Handle local development on PC
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
      return 'http://localhost:3000';
    }
  }

  // For the Android APK/Phone, we default to the Render backend
  // But allow users to change it in Settings if they are running a local node
  return 'https://pwnnet-toolkit.onrender.com';
};
