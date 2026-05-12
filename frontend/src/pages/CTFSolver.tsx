import { useState } from 'react'
import { Card, Form, Select, Input, Button, Typography, Steps, Timeline, Tag, Space, message } from 'antd'
import { BugOutlined, SendOutlined } from '@ant-design/icons'
import axios from 'axios'

const { Title, Paragraph, Text } = Typography
const { TextArea } = Input

const categories = [
  { value: 'web', label: 'Web' },
  { value: 'pwn', label: 'Pwn' },
  { value: 'reverse', label: 'Reverse' },
  { value: 'crypto', label: 'Crypto' },
  { value: 'misc', label: 'Misc' },
  { value: 'forensics', label: 'Forensics' },
]

export default function CTFSolver() {
  const [form] = Form.useForm()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [analysisResult, setAnalysisResult] = useState<any>(null)

  const handleSolve = async (values: any) => {
    setLoading(true)
    try {
      const response = await axios.post('/api/ctf/solve', {
        challenge: {
          title: values.title,
          description: values.description,
          category: values.category,
          url: values.url || null,
        },
        provider: values.provider || 'openai',
        auto_execute: false,
      })
      setResult(response.data)
      message.success('解题完成')
    } catch (error: any) {
      message.error(error.response?.data?.detail || '解题失败')
    } finally {
      setLoading(false)
    }
  }

  const handleAnalyze = async () => {
    const values = form.getFieldsValue()
    if (!values.title || !values.description) {
      message.warning('请填写题目信息')
      return
    }
    setLoading(true)
    try {
      const response = await axios.post('/api/ctf/analyze', null, {
        params: {
          title: values.title,
          description: values.description,
          category: values.category,
          url: values.url,
        },
      })
      setAnalysisResult(response.data)
      message.success('分析完成')
    } catch (error: any) {
      message.error('分析失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <Title level={3}>
        <BugOutlined /> CTF-AutoSolver
      </Title>
      <Paragraph type="secondary">
        基于ReAct Agent的CTF自动解题器，支持Web/Pwn/Reverse/Crypto等题型
      </Paragraph>

      <Card style={{ marginTop: 16 }}>
        <Form form={form} layout="vertical" onFinish={handleSolve}>
          <Form.Item name="title" label="题目名称" rules={[{ required: true }]}>
            <Input placeholder="e.g., Easy SQL Injection" />
          </Form.Item>

          <Form.Item name="category" label="题目类别" rules={[{ required: true }]} initialValue="web">
            <Select options={categories} />
          </Form.Item>

          <Form.Item name="description" label="题目描述" rules={[{ required: true }]}>
            <TextArea rows={4} placeholder="粘贴CTF题目描述..." />
          </Form.Item>

          <Form.Item name="url" label="目标URL (可选)">
            <Input placeholder="e.g., http://challenge.example.com:8080" />
          </Form.Item>

          <Form.Item name="provider" label="LLM Provider" initialValue="openai">
            <Select options={[
              { value: 'openai', label: 'OpenAI' },
              { value: 'ollama', label: 'Ollama (本地)' },
            ]} />
          </Form.Item>

          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={loading} icon={<SendOutlined />}>
                自动解题
              </Button>
              <Button onClick={handleAnalyze} loading={loading}>
                仅分析
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Card>

      {analysisResult && (
        <Card title="分析结果" style={{ marginTop: 16 }}>
          <Paragraph>{analysisResult.analysis}</Paragraph>
        </Card>
      )}

      {result && (
        <Card title="解题结果" style={{ marginTop: 16 }}>
          {result.solution?.flag && (
            <div style={{ marginBottom: 16 }}>
              <Tag color="green" style={{ fontSize: 16, padding: '4px 12px' }}>
                Flag: {result.solution.flag}
              </Tag>
            </div>
          )}

          <Title level={5}>解题步骤</Title>
          <Timeline
            items={result.solution?.steps?.map((step: any, i: number) => ({
              color: step.type === 'error' ? 'red' : 'blue',
              children: (
                <div>
                  <Text strong>迭代 {step.iteration} - {step.type}</Text>
                  {step.tool && <Tag style={{ marginLeft: 8 }}>{step.tool}</Tag>}
                  <br />
                  <Text type="secondary">{step.content || step.observation || ''}</Text>
                </div>
              ),
            }))}
          />
        </Card>
      )}
    </div>
  )
}
