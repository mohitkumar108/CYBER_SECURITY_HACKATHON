import React from 'react';
import { AlertTriangle, Clock, MapPin, Shield } from 'lucide-react';
import { useApi } from '../../context/ApiContext';

const RecentThreats = () => {
  const { threatData } = useApi();

  const getRiskColor = (level) => {
    switch (level) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex items-center gap-3 mb-6">
        <AlertTriangle className="h-6 w-6 text-danger-600" />
        <h3 className="text-lg font-semibold text-gray-800">Recent Threats</h3>
      </div>

      <div className="space-y-4">
        {threatData.length > 0 ? (
          threatData.slice(0, 5).map((threat) => (
            <div key={threat.id} className="p-4 border border-gray-200 rounded-lg hover:shadow-md transition-shadow">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <Shield className="h-5 w-5 text-primary-600" />
                  <div>
                    <p className="font-semibold text-gray-800">{threat.ip}</p>
                    <div className="flex items-center gap-2 text-sm text-gray-600">
                      <MapPin className="h-3 w-3" />
                      <span>{threat.city}, {threat.country}</span>
                    </div>
                  </div>
                </div>
                <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getRiskColor(threat.riskLevel)}`}>
                  {threat.riskLevel.toUpperCase()}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-gray-600">Organization</p>
                  <p className="font-medium text-gray-800 truncate">{threat.org}</p>
                </div>
                <div>
                  <p className="text-gray-600">Open Ports</p>
                  <p className="font-medium text-gray-800">{threat.ports.length} ports</p>
                </div>
              </div>

              <div className="flex items-center gap-2 mt-3 text-xs text-gray-500">
                <Clock className="h-3 w-3" />
                <span>Last seen: {formatTime(threat.lastSeen)}</span>
              </div>
            </div>
          ))
        ) : (
          <div className="text-center py-8 text-gray-500">
            <AlertTriangle className="h-12 w-12 mx-auto mb-3 text-gray-300" />
            <p>No recent threats detected</p>
            <p className="text-sm">Your network appears to be secure</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default RecentThreats;
