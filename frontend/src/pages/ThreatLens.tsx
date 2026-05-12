import { useState } from 'react'
import { Card, Form, Select, Input, Button, Typography, Table, Tag, Descriptions, message } from 'antd'
import { RadarChartOutlined } from '@ant-design/icons'
import axios from 'axios'

const { Title, Paragraph } = Typography

export default function ThreatLens() {
  const [loading, setLoading] = useState(false)
  const [modelStatus, setModelStatus] = useState<any>(null)
  const [detectionResult, setDetectionResult] = useState<any>(null)

  const handleDetect = async (values: any) => {
    setLoading(true)
    try {
      const response = await axios.post('/api/threat-lens/detect/single', null, {
        params: values,
      })
      setDetectionResult(response.data)
      message.success('检测完成')
    } catch (error: any) {
      message.error('检测失败')
    } finally {
      setLoading(false)
    }
  }

  const fetchModelStatus = async () => {
    try {
      const response = await axios.get('/api/threat-lens/models/status')
      setModelStatus(response.data)
    } catch {
      message.error('获取模型状态失败')
    }
  }

  return (
    <div>
      <Title level={3}>
        <RadarChartOutlined /> ThreatLens
      </Title>
      <Paragraph type="secondary">
        AI威胁检测引擎 - AutoEncoder / LightGBM / CNN 多模型
      </Paragraph>

      <Card title="流量检测" style={{ marginTop: 16 }}>
        <Form layout="vertical" onFinish={handleDetect}>
          <Form.Item name="src_ip" label="源IP" initialValue="192.168.1.100">
            <Input />
          </Form.Item>
          <Form.Item name="dst_ip" label="目标IP" initialValue="10.0.0.1">
            <Input />
          </Form.Item>
          <Form.Item name="src_port" label="源端口" initialValue={12345}>
            <Input type="number" />
          </Form.Item>
          <Form.Item name="dst_port" label="目标端口" initialValue={80}>
            <Input type="number" />
          </Form.Item>
          <Form.Item name="protocol" label="协议" initialValue="TCP">
            <Select options={[
              { value: 'TCP', label: 'TCP' },
              { value: 'UDP', label: 'UDP' },
              { value: 'ICMP', label: 'ICMP' },
            ]} />
          </Form.Item>
          <Form.Item name="model_name" label="检测模型" initialValue="autoencoder">
            <Select options={[
              { value: 'autoencoder', label: 'AutoEncoder (异常检测)' },
              { value: 'lightgbm', label: 'LightGBM (分类)' },
              { value: 'cnn1d', label: '1D-CNN (分类)' },
            ]} />
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading}>
              检测威胁
            </Button>
            <Button style={{ marginLeft: 8 }} onClick={fetchModelStatus}>
              模型状态
            </Button>
          </Form.Item>
        </Form>
      </Card>

      {detectionResult && (
        <Card title="检测结果" style={{ marginTop: 16 }}>
          <Descriptions bordered>
            <Descriptions.Item label="流ID">{detectionResult.flow_id}</Descriptions.Item>
            <Descriptions.Item label="是否威胁">
              <Tag color={detectionResult.is_threat ? 'red' : 'green'}>
                {detectionResult.is_threat ? '威胁' : '正常'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="威胁类型">{detectionResult.threat_type || 'N/A'}</Descriptions.Item>
            <Descriptions.Item label="置信度">{(detectionResult.confidence * 100).toFixed(2)}%</Descriptions.Item>
            <Descriptions.Item label="检测模型">{detectionResult.model_name}</Descriptions.Item>
          </Descriptions>
        </Card>
      )}

      {modelStatus && (
        <Card title="模型状态" style={{ marginTop: 16 }}>
          <Table
            dataSource={Object.entries(modelStatus).map(([name, info]: any) => ({
              key: name,
              name,
              ...info,
            }))}
            columns={[
              { title: '模型', dataIndex: 'name', key: 'name' },
              { title: '类型', dataIndex: 'type', key: 'type' },
              { title: '已训练', dataIndex: 'is_trained', key: 'is_trained', render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '是' : '否'}</Tag> },
            ]}
            pagination={false}
          />
        </Card>
      )}
    </div>
  )
}
