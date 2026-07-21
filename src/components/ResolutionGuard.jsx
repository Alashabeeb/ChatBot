import { useState, useEffect } from 'react';
import { MonitorX } from 'lucide-react';

export default function ResolutionGuard({ children }) {
  const [isSupported, setIsSupported] = useState(true);

  useEffect(() => {
    const checkResolution = () => {
      // Check if the viewport width is less than 1366
      // (We don't strictly check height to 768 because browser tabs/URL bars reduce viewport height 
      // even on a 1366x768 physical screen)
      if (window.innerWidth < 1366) {
        setIsSupported(false);
      } else {
        setIsSupported(true);
      }
    };

    // Check immediately on mount
    checkResolution();

    // Listen for resize events
    window.addEventListener('resize', checkResolution);
    return () => window.removeEventListener('resize', checkResolution);
  }, []);

  if (!isSupported) {
    return (
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: '100vh',
        width: '100vw',
        backgroundColor: 'var(--bg-primary)',
        color: 'var(--text-primary)',
        padding: '40px',
        textAlign: 'center',
        fontFamily: 'var(--font-sans)'
      }}>
        <MonitorX size={80} style={{ color: 'var(--accent)', marginBottom: '24px' }} />
        <h1 style={{ fontSize: '32px', marginBottom: '16px', fontWeight: 600 }}>Unsupported Resolution</h1>
        <p style={{ fontSize: '18px', color: 'var(--text-secondary)', maxWidth: '600px', lineHeight: 1.6 }}>
          GBB ChatBot requires a minimum screen resolution of <b>1366 x 768</b>. 
          <br /><br />
          Your current window width is <b>{window.innerWidth}px</b>. Please maximize your browser window or switch to a device with a larger display to continue.
        </p>
      </div>
    );
  }

  return children;
}
