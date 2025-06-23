import React from 'react';
import { Shield, AlertTriangle, Activity, Eye } from 'lucide-react';
import StatsCard from '../components/Dashboard/StatsCard';
import ThreatMap from '../components/Dashboard/ThreatMap';
import RecentThreats from '../components/Dashboard/RecentThreats';
import { useApi } from '../context/ApiContext';

const Dashboard = () => {
  const { threatData } = useApi();

  const stats = {
    totalThreats: threatData.length,
    activeMonitoring: 1,
    vulnerabilities: threatData.reduce((acc, threat) => acc + threat.vulnerabilities.length, 0),
    blockedAttacks: threatData.filter(
      (threat) => threat.riskLevel === 'high' || threat.riskLevel === 'critical'
    ).length
  };

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatsCard
          title="Total Threats Detected"
          value={stats.totalThreats}
          icon={AlertTriangle}
          color="danger"
          trend={{ value: 12, isPositive: false }}
        />
        <StatsCard
          title="Active Monitoring"
          value={stats.activeMonitoring}
          icon={Eye}
          color="primary"
          trend={{ value: 5, isPositive: true }}
        />
        <StatsCard
          title="Vulnerabilities Found"
          value={stats.vulnerabilities}
          icon={Shield}
          color="warning"
          trend={{ value: 8, isPositive: false }}
        />
        <StatsCard
          title="High Risk Threats"
          value={stats.blockedAttacks}
          icon={Activity}
          color="success"
          trend={{ value: 15, isPositive: true }}
        />
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ThreatMap />
        <RecentThreats />
      </div>
    </div>
  );
};

export default Dashboard;
