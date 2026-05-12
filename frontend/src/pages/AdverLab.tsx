import { useState } from 'react'
import { Card, Form, Select, Input, Button, Typography, Table, Tag, Slider, Space, message } from 'antd'
import { ExperimentOutlined } from '@ant-design/icons'
import axios from 'axios'

const { Title, Paragraph } = Typography

const attackTypes = [
  { value: 'fgsm', label: 'FGSM (Fast Gradient Sign)' },
  { value: 'pgd', label: 'PGD (Projected Gradient Descent)' },
  { value: 'cw', label: 'C&W (Carlini & Wagner)' },
]

const defenseTypes = [
  { value: 'adversarial_training', label: 'Adversarial Training' },
  { value: 'input_preprocessing', label: 'Input Preprocessing' },
]

const datasets = [
  { value: 'mnist', label: 'MNIST' },
  { value: 'cifar10', label: 'CIFAR-10' },
]

export default function AdverLab() {
  const [form] = Form.useForm()
  const [loading, setLoading] = useState(false)
  const [experiments, setExperiments] = useState<any[]>([])

  const handleRunExperiment = async (values: any) => {
    setLoading(true)
    try {
      const response = await axios.post('/api/adver-lab/experiment/run', {
        name: values.name || `exp_${Date.now()}`,
        attack_type: values.attack_type,
        defense_type: values.defense_type || null,
        dataset: values.dataset,
        epsilon: values.epsilon / 1000,
        attack_params: {},
        defense_params: {},
      })
      setExperiments(prev => [...prev, response.data])
      message.success('实验配置已创建')
    } catch (error: any) {
      message.error('实验创建失败')
    } finally {
      setLoading(false)
    }
  }

  const fetchExperiments = async () => {
    try {
      const response = await axios.get('/api/adver-lab/experiment/list')
      setExperiments(response.data.experiments || [])
    } catch {
      message.error('获取实验列表失败')
    }
  }

  return (
    <div>
      <Title level={3}>
        <ExperimentOutlined /> AdverLab
      </Title>
      <Paragraph type="secondary">
        对抗样本攻防实验室 - FGSM / PGD / C&W 攻击与防御实验
      </Paragraph>

      <Card title="新建实验" style={{ marginTop: 16 }}>
        <Form form={form} layout="vertical" onFinish={handleRunExperiment}>
          <Form.Item name="name" label="实验名称">
            <Input placeholder="e.g., fgsm_mnist_eps30" />
          </Form.Item>
          <Form.Item name="attack_type" label="攻击类型" rules={[{ required: true }]} initialValue="fgsm">
            <Select options={attackTypes} />
          </Form.Item>
          <Form.Item name="defense_type" label="防御方法">
            <Select allowClear options={defenseTypes} placeholder="可选" />
          </Form.Item>
          <Form.Item name="dataset" label="数据集" initialValue="mnist">
            <Select options={datasets} />
          </Form.Item>
          <Form.Item name="epsilon" label="扰动强度 (epsilon x1000)" initialValue={30}>
            <Slider min={1} max={100} marks={{ 1: '0.001', 30: '0.03', 100: '0.1' }} />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={loading}>
                创建实验
              </Button>
              <Button onClick={fetchExperiments}>
                刷新列表
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Card>

      {experiments.length > 0 && (
        <Card title="实验列表" style={{ marginTop: 16 }}>
          <Table
            dataSource={experiments}
            columns={[
              { title: 'ID', dataIndex: 'id', key: 'id' },
              { title: '攻击', dataIndex: 'attack_type', key: 'attack_type', render: (v: string) => <Tag color="red">{v}</Tag> },
              { title: '防御', dataIndex: 'defense_type', key: 'defense_type', render: (v: string) => v ? <Tag color="blue">{v}</Tag> : <Tag>N/A</Tag> },
              { title: '状态', dataIndex: 'status', key: 'status', render: (v: string) => <Tag color="processing">{v}</Tag> },
            ]}
            pagination={false}
            size="small"
          />
        </Card>
      )}
    </div>
  )
}
