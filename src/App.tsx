import { useState, useEffect, Component, ReactNode } from 'react';
import { Tab, ToolDef } from './types';
import { TopBar } from './components/TopBar';
import { BottomNav } from './components/BottomNav';
import { TerminalEmulator } from './components/Terminal';
import { ToolsGrid } from './views/ToolsGrid';
import { Logbook } from './views/Logbook';
import { Resources } from './views/Resources';
import { Settings } from './views/Settings';
import { DorksPage } from './views/DorksPage';
import { CustomToolRouter } from './views/CustomTools';
import { SplashScreen } from './components/SplashScreen';
import { AboutModal } from './components/AboutModal';
import { FavoritesModal } from './components/FavoritesModal';
import { AnimatePresence } from 'motion/react';
import { initKotlinLogger } from './utils/kotlinLogger';

class ErrorBoundary extends Component<{children: ReactNode}, {hasError: boolean, error: Error | null}> {
  state = { hasError: false, error: null };
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return <div className="p-4 text-red-500 font-mono text-sm break-all">App Crashed: {this.state.error?.message} - {(this.state.error as any)?.stack}</div>;
    }
    return this.props.children;
  }
}

export default function App() {
  const [showSplash, setShowSplash] = useState(true);
  const [showAbout, setShowAbout] = useState(false);
  const [showFavorites, setShowFavorites] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>('tools');
  const [activeTool, setActiveTool] = useState<ToolDef | null>(null);

  useEffect(() => {
    initKotlinLogger();
  }, []);

  // Handle hardware back button for Tools
  useEffect(() => {
    const handlePopState = (e: PopStateEvent) => {
      // If we go back and there's no tool state, but we had a tool open, close it
      if (activeTool && (!e.state || e.state.view !== 'tool')) {
        setActiveTool(null);
      }
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [activeTool]);

  const handleSelectTool = (tool: ToolDef) => {
    setActiveTool(tool);
    window.history.pushState({ view: 'tool', id: tool.id }, '');
  };

  const handleCloseTool = () => {
    setActiveTool(null);
    if (window.history.state?.view === 'tool') {
      window.history.back();
    }
  };

  const getTitle = () => {
    switch (activeTab) {
      case 'tools': return 'PwnNet Tools';
      case 'logbook': return 'Logs';
      case 'resources': return 'Resources';
      case 'settings': return 'System';
    }
  };

  return (
    <ErrorBoundary>
      <AnimatePresence>
        {showSplash && <SplashScreen onComplete={() => setShowSplash(false)} />}
      </AnimatePresence>
      <div className="flex flex-col h-[100dvh] w-full bg-obsidian text-neon-green font-mono overflow-hidden" style={{ paddingTop: 'env(safe-area-inset-top)', paddingBottom: 'env(safe-area-inset-bottom)' }}>
        <TopBar 
          title={getTitle()} 
          onTerminalToggle={activeTab === 'tools' ? () => setActiveTool(activeTool) : undefined} 
          onFavoritesClick={() => setShowFavorites(true)}
          onAboutClick={() => setShowAbout(true)}
        />
      
      <div className="flex-1 relative overflow-hidden flex flex-col">
        {activeTab === 'tools' && <ToolsGrid onSelectTool={handleSelectTool} />}
        {activeTab === 'logbook' && <Logbook />}
        {activeTab === 'resources' && <Resources />}
        {activeTab === 'settings' && <Settings />}

        {activeTool && activeTool.id === 'dorks' ? (
          <DorksPage tool={activeTool} onClose={handleCloseTool} />
        ) : activeTool && activeTool.actionType === 'custom' ? (
          <CustomToolRouter tool={activeTool} onClose={handleCloseTool} />
        ) : activeTool && (
          <TerminalEmulator 
            tool={activeTool} 
            onClose={handleCloseTool} 
          />
        )}
      </div>

      {showFavorites && (
        <FavoritesModal 
          onClose={() => setShowFavorites(false)} 
          onSelectTool={handleSelectTool} 
        />
      )}
      {showAbout && <AboutModal onClose={() => setShowAbout(false)} />}

      <div className="shrink-0 z-50 relative bg-obsidian">
        <BottomNav activeTab={activeTab} setActiveTab={setActiveTab} disabled={!!activeTool} />
      </div>
    </div>
    </ErrorBoundary>
  );
}
