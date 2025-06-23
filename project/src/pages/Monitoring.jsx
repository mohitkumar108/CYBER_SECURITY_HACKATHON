import React from 'react';
import { Activity, Wifi, Server, AlertCircle } from 'lucide-react';
import { useApi } from '../context/ApiContext';

const Monitoring = () => {
  const { threatData, loading } = useApi();

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <Activity className="h-6 w-6 text-primary-600" />
          <h2 className="text-xl font-semibold text-gray-800">Real-time Network Monitoring</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
            <div className="flex items-center gap-3">
              <Wifi className="h-8 w-8 text-green-600" />
              <div>
                <p className="text-2xl font-bold text-green-800">Online</p>
                <p className="text-sm text-green-600">Network Status</p>
              </div>
            </div>
          </div>

          <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex items-center gap-3">
              <Server className="h-8 w-8 text-blue-600" />
              <div>
                <p className="text-2xl font-bold text-blue-800">{threatData.length}</p>
                <p className="text-sm text-blue-600">IPs Monitored</p>
              </div>
            </div>
          </div>

          <div className="p-4 bg-orange-50 border border-orange-200 rounded-lg">
            <div className="flex items-center gap-3">
              <AlertCircle className="h-8 w-8 text-orange-600" />
              <div>
                <p className="text-2xl font-bold text-orange-800">
                  {threatData.filter(t => t.riskLevel === 'high' || t.riskLevel === 'critical').length}
                </p>
                <p className="text-sm text-orange-600">Active Alerts</p>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-gray-800">Live Activity Feed</h3>

          {loading && (
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
              <span className="ml-3 text-gray-600">Monitoring network activity...</span>
            </div>
          )}

          <div className="space-y-3">
            {threatData.slice(0, 10).map((threat) => (
              <div key={threat.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-4">
                  <div
                    className={`w-3 h-3 rounded-full ${
                      threat.riskLevel === 'critical'
                        ? 'bg-red-500 animate-pulse'
                        : threat.riskLevel === 'high'
                        ? 'bg-orange-500 animate-pulse'
                        : threat.riskLevel === 'medium'
                        ? 'bg-yellow-500'
                        : 'bg-green-500'
                    }`}
                  ></div>
                  <div>
                    <p className="font-medium text-gray-800">{threat.ip}</p>
                    <p className="text-sm text-gray-600">{threat.city}, {threat.country}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium text-gray-800">{threat.ports.length} open ports</p>
                  <p className="text-xs text-gray-500">{new Date(threat.lastSeen).toLocaleTimeString()}</p>
                </div>
              </div>
            ))}

            {threatData.length === 0 && !loading && (
              <div className="text-center py-8 text-gray-500">
                <Activity className="h-12 w-12 mx-auto mb-3 text-gray-300" />
                <p>No network activity detected</p>
                <p className="text-sm">Start analyzing IPs to see monitoring data</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Monitoring;
