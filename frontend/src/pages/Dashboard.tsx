import { Row, Col, Card, Typography, Tag } from 'antd'
import {
  BugOutlined,
  SafetyCertificateOutlined,
  RadarChartOutlined,
  ExperimentOutlined,
} from '@ant-design/icons'

const { Title, Paragraph } = Typography

const modules = [
  {
    title: 'CTF-AutoSolver',
    icon: <BugOutlined style={{ fontSize: 32, color: '#1890ff' }} />,
    description: 'AI驱动的CTF自动解题器，支持Web/Pwn/Reverse/Crypto等题型',
    tags: ['ReAct Agent', 'LLM+Tools', 'Auto Exploit'],
    color: '#1890ff',
    path: '/ctf-solver',
  },
  {
    title: 'LLM-Guard',
    icon: <SafetyCertificateOutlined style={{ fontSize: 32, color: '#52c41a' }} />,
    description: 'LLM安全测试框架，Prompt Injection/Jailbreak攻击与防御',
    tags: ['Red Team', 'Prompt Injection', 'Jailbreak'],
    color: '#52c41a',
    path: '/llm-guard',
  },
  {
    title: 'ThreatLens',
    icon: <RadarChartOutlined style={{ fontSize: 32, color: '#faad14' }} />,
    description: '基于ML的威胁检测引擎，AutoEncoder/LightGBM/CNN多模型',
    tags: ['Anomaly Detection', 'Flow Analysis', 'LLM-Assisted'],
    color: '#faad14',
    path: '/threat-lens',
  },
  {
    title: 'AdverLab',
    icon: <ExperimentOutlined style={{ fontSize: 32, color: '#f5222d' }} />,
    description: '对抗样本攻防实验室，FGSM/PGD/C&W攻击与防御实验',
    tags: ['Adversarial ML', 'FGSM/PGD/C&W', 'Defense Training'],
    color: '#f5222d',
    path: '/adver-lab',
  },
]

export default function Dashboard() {
  return (
    <div>
      <Title level={2}>SecureAI Toolkit</Title>
      <Paragraph type="secondary">
        AI安全攻防工具集 - 覆盖AI赋能安全与AI自身安全两大方向
      </Paragraph>

      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        {modules.map((mod) => (
          <Col xs={24} sm={12} key={mod.title}>
            <Card
              hoverable
              style={{ borderTop: `3px solid ${mod.color}` }}
            >
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: 16 }}>
                {mod.icon}
                <Title level={4} style={{ margin: '0 0 0 12px' }}>{mod.title}</Title>
              </div>
              <Paragraph>{mod.description}</Paragraph>
              <div>
                {mod.tags.map((tag) => (
                  <Tag key={tag} color={mod.color}>{tag}</Tag>
                ))}
              </div>
            </Card>
          </Col>
        ))}
      </Row>
    </div>
  )
}
