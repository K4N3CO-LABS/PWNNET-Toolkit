export const getBackendUrl = () => {
  // Check if we have a user-defined override in localStorage
  if (typeof window !== 'undefined') {
    const override = localStorage.getItem('pwnnet_backend_url');
    if (override) return override;

    const hostname = window.location.hostname;

    // Check if we are running inside AI Studio
    if (hostname.includes('run.app')) {
        return ''; 
    }

    // ON PC: If you are running 'npm run dev' on your computer
    // we use localhost.
    // ON PHONE: Capacitor also uses 'localhost', so we need to distinguish.
    // We check for the bridge or the native platform.
    const isNative = (window as any).Capacitor?.getPlatform?.() !== undefined || !!(window as any).androidBridge;

    if (!isNative && (hostname === 'localhost' || hostname === '127.0.0.1')) {
      return 'http://localhost:3000';
    }
  }

  // Default production backend for the APK
  return 'https://pwnnet-toolkit.onrender.com';
};
