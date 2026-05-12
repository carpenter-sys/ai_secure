import { useNavigate, useLocation } from 'react-router-dom'
import { Layout, Menu } from 'antd'
import {
  DashboardOutlined,
  BugOutlined,
  SafetyCertificateOutlined,
  RadarChartOutlined,
  ExperimentOutlined,
} from '@ant-design/icons'

const { Sider } = Layout

const menuItems = [
  { key: '/', icon: <DashboardOutlined />, label: 'Dashboard' },
  { key: '/ctf-solver', icon: <BugOutlined />, label: 'CTF-AutoSolver' },
  { key: '/llm-guard', icon: <SafetyCertificateOutlined />, label: 'LLM-Guard' },
  { key: '/threat-lens', icon: <RadarChartOutlined />, label: 'ThreatLens' },
  { key: '/adver-lab', icon: <ExperimentOutlined />, label: 'AdverLab' },
]

export default function LayoutSidebar() {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <Sider width={220} style={{ background: '#001529' }}>
      <div style={{
        height: 64,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: '#fff',
        fontSize: 18,
        fontWeight: 'bold',
        borderBottom: '1px solid rgba(255,255,255,0.1)',
      }}>
        SecureAI Toolkit
      </div>
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[location.pathname]}
        items={menuItems}
        onClick={({ key }) => navigate(key)}
      />
    </Sider>
  )
}
