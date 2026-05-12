import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from 'antd'
import LayoutSidebar from './components/Layout'
import Dashboard from './pages/Dashboard'
import CTFSolver from './pages/CTFSolver'
import LLMGuard from './pages/LLMGuard'
import ThreatLens from './pages/ThreatLens'
import AdverLab from './pages/AdverLab'

function App() {
  return (
    <Layout style={{ minHeight: '100vh' }}>
      <LayoutSidebar />
      <Layout>
        <Layout.Content style={{ margin: '16px' }}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/ctf-solver" element={<CTFSolver />} />
            <Route path="/llm-guard" element={<LLMGuard />} />
            <Route path="/threat-lens" element={<ThreatLens />} />
            <Route path="/adver-lab" element={<AdverLab />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Layout.Content>
      </Layout>
    </Layout>
  )
}

export default App
