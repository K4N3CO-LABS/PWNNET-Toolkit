export const openExternalLink = (url: string) => {
  const isAndroid = /android/i.test(navigator.userAgent);
  if (isAndroid) {
    try {
      const scheme = url.startsWith('https') ? 'https' : 'http';
      const urlWithoutScheme = url.replace(/^https?:\/\//, '');
      const intentUrl = `intent://${urlWithoutScheme}#Intent;scheme=${scheme};package=com.android.chrome;end;`;
      
      const a = document.createElement('a');
      a.href = intentUrl;
      a.target = '_blank';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      return;
    } catch (e) {
      console.error('Intent fallback failed', e);
    }
  }

  const win = window.open(url, '_blank', 'noopener,noreferrer');
  if (!win) {
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
};