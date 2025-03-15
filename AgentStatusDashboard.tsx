// src/components/dashboards/AgentStatusDashboard.tsx
import React, { useEffect, useMemo, useCallback } from 'react';
import { useQuery, useSubscription } from '@apollo/client';
import { 
  LineChart, 
  CartesianGrid, 
  XAxis, 
  YAxis, 
  Tooltip,
  Legend,
  Line,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  Cell
} from 'recharts';
import { 
  Space, 
  Spin, 
  Alert, 
  Card, 
  Typography, 
  Tag,
  Tabs,
  List,
  Avatar 
} from 'antd';
import { 
  LockOutlined, 
  WarningOutlined, 
  ClusterOutlined,
  CodeSandboxOutlined
} from '@ant-design/icons';
import { 
  AGENT_TELEMETRY_SUBSCRIPTION, 
  GET_AGENT_CLUSTER_STATE,
  AGENT_AUDIT_LOGS_QUERY
} from '../../graphql/queries';
import { 
  formatBytes,
  decryptTelemetryPayload,
  calculateThreatLevel,
  networkTopologyMapper 
} from '../../lib/securityUtils';
import type { 
  AgentTelemetry,
  ClusterNode,
  ResourceUsage,
  SecurityAlert 
} from '../../types/agentTypes';

const { Title, Text } = Typography;
const { TabPane } = Tabs;

interface AgentStatusDashboardProps {
  clusterId: string;
  jwtToken: string;
  threatThreshold?: number;
}

const AGENT_HEARTBEAT_INTERVAL = 5000;

const AgentStatusDashboard: React.FC<AgentStatusDashboardProps> = ({
  clusterId,
  jwtToken,
  threatThreshold = 0.8
}) => {
  const { loading, error, data, refetch } = useQuery(GET_AGENT_CLUSTER_STATE, {
    variables: { clusterId },
    context: {
      headers: {
        Authorization: `Bearer ${jwtToken}`
      }
    },
    fetchPolicy: 'network-only'
  });

  const { data: subscriptionData } = useSubscription(AGENT_TELEMETRY_SUBSCRIPTION, {
    variables: { clusterId },
    context: {
      headers: {
        Authorization: `Bearer ${jwtToken}`
      }
    },
    onSubscriptionData: ({ subscriptionData }) => {
      if (subscriptionData.data?.agentTelemetry) {
        handleSecurityEvent(subscriptionData.data.agentTelemetry);
      }
    }
  });

  const [alerts, setAlerts] = React.useState<SecurityAlert[]>([]);
  const [selectedNode, setSelectedNode] = React.useState<string | null>(null);
  
  const handleSecurityEvent = useCallback((telemetry: AgentTelemetry) => {
    const decrypted = decryptTelemetryPayload(telemetry.encryptedPayload);
    const threatLevel = calculateThreatLevel(decrypted);
    
    if (threatLevel >= threatThreshold) {
      setAlerts(prev => [...prev, {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        severity: threatLevel > 0.9 ? 'CRITICAL' : 'WARNING',
        agentId: telemetry.agentId,
        description: `Anomaly detected in ${decrypted.metricType} metric`,
        metadata: decrypted
      }]);
    }
  }, [threatThreshold]);

  const processedData = useMemo(() => {
    if (!data?.clusterState) return [];
    return networkTopologyMapper(data.clusterState.nodes);
  }, [data]);

  const nodeStatusCounts = useMemo(() => ({
    active: data?.clusterState.nodes.filter((n: ClusterNode) => n.status === 'ACTIVE').length,
    degraded: data?.clusterState.nodes.filter((n: ClusterNode) => n.status === 'DEGRADED').length,
    offline: data?.clusterState.nodes.filter((n: ClusterNode) => n.status === 'OFFLINE').length
  }), [data]);

  if (error) return (
    <Alert
      type="error"
      message="Security Violation"
      description="Failed to load cluster state - TLS handshake rejected"
      icon={<LockOutlined />}
    />
  );

  return (
    <div className="agent-dashboard-container">
      <Space direction="vertical" style={{ width: '100%' }}>
        <Card bordered={false} bodyStyle={{ padding: '0 24px' }}>
          <Tabs defaultActiveKey="1" animated>
            <TabPane tab={
              <span>
                <ClusterOutlined />
                Cluster Overview
              </span>
            } key="1">
              <div className="dashboard-section">
                <Title level={4} className="security-header">
                  Node Status Distribution
                  <Tag color="geekblue" style={{ marginLeft: 16 }}>
                    TLS 1.3 Encrypted
                  </Tag>
                </Title>
                
                <ResponsiveContainer width="100%" height={300}>
                  <ScatterChart margin={{ top: 20, right: 40, bottom: 20, left: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis
                      type="number"
                      dataKey="x"
                      name="Network Latency"
                      unit="ms"
                      domain={[0, 300]}
                    />
                    <YAxis
                      type="number"
                      dataKey="y"
                      name="CPU Usage"
                      unit="%"
                      domain={[0, 100]}
                    />
                    <Tooltip
                      cursor={{ strokeDasharray: '3 3' }}
                      formatter={(value: number, name: string) => [
                        name === 'x' ? `${value}ms` : `${value}%`,
                        name === 'x' ? 'Latency' : 'CPU Usage'
                      ]}
                    />
                    <Scatter
                      name="Node Status"
                      data={processedData}
                      fill="#8884d8"
                      onClick={(data: any) => setSelectedNode(data.payload.id)}
                    >
                      {processedData.map((entry: any, index: number) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={
                            entry.status === 'ACTIVE' ? '#82ca9d' :
                            entry.status === 'DEGRADED' ? '#ffc658' :
                            '#ff7300'
                          }
                        />
                      ))}
                    </Scatter>
                    <Legend
                      payload={[
                        { value: 'Active', type: 'circle', color: '#82ca9d' },
                        { value: 'Degraded', type: 'circle', color: '#ffc658' },
                        { value: 'Offline', type: 'circle', color: '#ff7300' }
                      ]}
                    />
                  </ScatterChart>
                </ResponsiveContainer>

                <div className="node-metrics-summary">
                  <MetricBadge
                    title="Active Nodes"
                    value={nodeStatusCounts.active}
                    status="success"
                  />
                  <MetricBadge
                    title="Degraded Nodes"
                    value={nodeStatusCounts.degraded}
                    status="warning"
                  />
                  <MetricBadge
                    title="Offline Nodes"
                    value={nodeStatusCounts.offline}
                    status="error"
                  />
                </div>
              </div>
            </TabPane>

            <TabPane tab={
              <span>
                <WarningOutlined />
                Security Alerts ({alerts.length})
              </span>
            } key="2">
              <AlertList alerts={alerts} onAcknowledge={(id) => 
                setAlerts(prev => prev.filter(a => a.id !== id))} 
              />
            </TabPane>

            <TabPane tab={
              <span>
                <CodeSandboxOutlined />
                Resource Telemetry
              </span>
            } key="3">
              <ResourceUsageTimeline 
                data={subscriptionData?.agentTelemetry || []}
                selectedNode={selectedNode}
              />
            </TabPane>
          </Tabs>
        </Card>
      </Space>
    </div>
  );
};

const MetricBadge: React.FC<{ title: string; value: number; status: 'success' | 'warning' | 'error' }> = 
({ title, value, status }) => (
  <div className="metric-badge">
    <Text strong>{title}</Text>
    <Tag color={
      status === 'success' ? 'green' :
      status === 'warning' ? 'gold' : 'volcano'
    }>
      {value}
    </Tag>
  </div>
);

const AlertList: React.FC<{ 
  alerts: SecurityAlert[]; 
  onAcknowledge: (id: string) => void 
}> = ({ alerts, onAcknowledge }) => (
  <List
    itemLayout="horizontal"
    dataSource={alerts}
    renderItem={(alert) => (
      <List.Item
        actions={[
          <Text key="time" type="secondary">
            {new Date(alert.timestamp).toLocaleTimeString()}
          </Text>,
          <a key="ack" onClick={() => onAcknowledge(alert.id)}>
            ACKNOWLEDGE
          </a>
        ]}
      >
        <List.Item.Meta
          avatar={<Avatar icon={<WarningOutlined />} />}
          title={
            <Space>
              <Tag color={alert.severity === 'CRITICAL' ? 'red' : 'orange'}>
                {alert.severity}
              </Tag>
              {alert.description}
            </Space>
          }
          description={`Agent ID: ${alert.agentId} | Metric: ${alert.metadata.metricType}`}
        />
      </List.Item>
    )}
  />
);

const ResourceUsageTimeline: React.FC<{ 
  data: AgentTelemetry[]; 
  selectedNode?: string | null 
}> = ({ data, selectedNode }) => {
  const filteredData = useMemo(() => 
    data.filter(d => 
      !selectedNode || d.agentId === selectedNode
    ).map(d => ({
      ...decryptTelemetryPayload(d.encryptedPayload),
      timestamp: new Date(d.timestamp).toLocaleTimeString()
    })),
    [data, selectedNode]
  );

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={filteredData}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="timestamp" />
        <YAxis yAxisId="left" />
        <YAxis yAxisId="right" orientation="right" />
        <Tooltip
          formatter={(value: number, name: string) => [
            name === 'cpuUsage' ? `${value}% CPU` :
            name === 'memoryUsage' ? formatBytes(value) :
            `${value}ms Latency`,
            name.replace(/([A-Z])/g, ' \$1').toUpperCase()
          ]}
        />
        <Legend />
        <Line
          yAxisId="left"
          type="monotone"
          dataKey="cpuUsage"
          stroke="#8884d8"
          dot={false}
        />
        <Line
          yAxisId="left"
          type="monotone"
          dataKey="memoryUsage"
          stroke="#82ca9d"
          dot={false}
        />
        <Line
          yAxisId="right"
          type="monotone"
          dataKey="networkLatency"
          stroke="#ffc658"
          dot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
};

export default React.memo(AgentStatusDashboard);
