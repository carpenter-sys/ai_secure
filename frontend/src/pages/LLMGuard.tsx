import { useState } from 'react'
import { Card, Form, Select, Input, Button, Typography, Table, Tag, Space, Progress, message } from 'antd'
import { SafetyCertificateOutlined, ThunderboltOutlined } from '@ant-design/icons'
import axios from 'axios'

const { Title, Paragraph, Text } = Typography

const attackTypes = [
  { value: 'prompt_injection_direct', label: 'Direct Prompt Injection' },
  { value: 'prompt_injection_indirect', label: 'Indirect Prompt Injection' },
  { value: 'prompt_injection_multi_turn', label: 'Multi-Turn Injection' },
  { value: 'jailbreak_template', label: 'Jailbreak Template' },
  { value: 'jailbreak_pair', label: 'PAIR (Iterative)' },
  { value: 'jailbreak_gcg', label: 'GCG (Gradient)' },
]

const categories = [
  { value: 'politics', label: 'Political Content' },
  { value: 'violence', label: 'Violence' },
  { value: 'privacy_leak', label: 'Privacy Leak' },
  { value: 'harmful_instruction', label: 'Harmful Instructions' },
  { value: 'bias', label: 'Bias/Discrimination' },
]

export default function LLMGuard() {
  const [form] = Form.useForm()
  const [loading, setLoading] = useState(false)
  const [report, setReport] = useState<any>(null)
  const [defenseResult, setDefenseResult] = useState<any>(null)

  const handleAttack = async (values: any) => {
    setLoading(true)
    try {
      const response = await axios.post('/api/llm-guard/attack', {
        target: {
          name: values.target_name,
          provider: values.target_provider,
          model: values.target_model,
        },
        attack_types: values.attack_types,
        num_variations: values.num_variations || 5,
        categories: values.categories,
      })
      setReport(response.data)
      message.success('安全评估完成')
    } catch (error: any) {
      message.error('评估失败: ' + (error.response?.data?.detail || error.message))
    } finally {
      setLoading(false)
    }
  }

  const handleDefenseCheck = async () => {
    const text = form.getFieldValue('defense_text')
    if (!text) {
      message.warning('请输入要检查的文本')
      return
    }
    setLoading(true)
    try {
      const response = await axios.post('/api/llm-guard/defend/check-input', null, {
        params: { text },
      })
      setDefenseResult(response.data)
    } catch (error: any) {
      message.error('检测失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <Title level={3}>
        <SafetyCertificateOutlined /> LLM-Guard
      </Title>
      <Paragraph type="secondary">
        LLM安全测试框架 - Prompt Injection / Jailbreak攻击与防御
      </Paragraph>

      <Card title="红队测试" style={{ marginTop: 16 }}>
        <Form form={form} layout="vertical" onFinish={handleAttack}>
          <Form.Item name="target_name" label="目标名称" initialValue="test-target">
            <Input placeholder="e.g., GPT-4, Claude, Llama3" />
          </Form.Item>
          <Form.Item name="target_provider" label="目标 Provider" initialValue="openai">
            <Select options={[
              { value: 'openai', label: 'OpenAI' },
              { value: 'ollama', label: 'Ollama' },
            ]} />
          </Form.Item>
          <Form.Item name="target_model" label="目标模型" initialValue="gpt-4o">
            <Input placeholder="e.g., gpt-4o, llama3" />
          </Form.Item>
          <Form.Item name="attack_types" label="攻击类型" rules={[{ required: true }]}>
            <Select mode="multiple" options={attackTypes} placeholder="选择攻击类型" />
          </Form.Item>
          <Form.Item name="categories" label="测试类别" initialValue={['politics', 'violence']}>
            <Select mode="multiple" options={categories} />
          </Form.Item>
          <Form.Item name="num_variations" label="每种攻击变体数" initialValue={5}>
            <Input type="number" min={1} max={20} />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} icon={<ThunderboltOutlined />}>
              执行安全评估
            </Button>
          </Form.Item>
        </Form>
      </Card>

      {report && (
        <Card title={`安全报告 - ${report.target_name}`} style={{ marginTop: 16 }}>
          <Space size="large" style={{ marginBottom: 16 }}>
            <div>
              <Text type="secondary">总攻击数</Text>
              <div><Text strong style={{ fontSize: 24 }}>{report.total_attacks}</Text></div>
            </div>
            <div>
              <Text type="secondary">成功攻击数</Text>
              <div><Text strong style={{ fontSize: 24, color: '#f5222d' }}>{report.successful_attacks}</Text></div>
            </div>
            <div>
              <Text type="secondary">攻击成功率</Text>
              <div>
                <Progress
                  type="circle"
                  percent={Math.round(report.attack_success_rate * 100)}
                  size={60}
                  strokeColor={report.attack_success_rate > 0.5 ? '#f5222d' : '#52c41a'}
                />
              </div>
            </div>
          </Space>

          {report.recommendations?.map((rec: string, i: number) => (
            <Tag key={i} color="warning" style={{ marginBottom: 8 }}>{rec}</Tag>
          ))}
        </Card>
      )}

      <Card title="输入安全检查" style={{ marginTop: 16 }}>
        <Form.Item name="defense_text" label="输入文本">
          <Input.TextArea rows={3} placeholder="输入要检查是否包含注入攻击的文本..." />
        </Form.Item>
        <Button onClick={handleDefenseCheck} loading={loading}>检测</Button>
        {defenseResult && (
          <div style={{ marginTop: 12 }}>
            <Tag color={defenseResult.is_safe ? 'green' : 'red'}>
              {defenseResult.is_safe ? '安全' : '检测到风险'}
            </Tag>
            <Text type="secondary">置信度: {(defenseResult.confidence * 100).toFixed(1)}%</Text>
          </div>
        )}
      </Card>
    </div>
  )
}
