import React from 'react';
import { Shield, MapPin, Server, AlertTriangle, Clock, Globe } from 'lucide-react';
import { useApi } from '../../context/ApiContext';

const ThreatDetails = () => {
  const { threatData } = useApi();

  if (threatData.length === 0) {
    return (
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="text-center py-12 text-gray-500">
          <Shield className="h-16 w-16 mx-auto mb-4 text-gray-300" />
          <h3 className="text-lg font-medium text-gray-700 mb-2">No Analysis Results</h3>
          <p>Enter an IP address above to start threat analysis</p>
        </div>
      </div>
    );
  }

  const latestThreat = threatData[0];

  const getRiskColor = (level) => {
    switch (level) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex items-center gap-3 mb-6">
        <AlertTriangle className="h-6 w-6 text-danger-600" />
        <h3 className="text-lg font-semibold text-gray-800">Threat Analysis Results</h3>
      </div>

      <div className="space-y-6">
        {/* Risk Level */}
        <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-primary-600" />
            <div>
              <p className="font-semibold text-gray-800">Risk Assessment</p>
              <p className="text-sm text-gray-600">Overall threat level</p>
            </div>
          </div>
          <span className={`px-4 py-2 rounded-full text-sm font-bold border ${getRiskColor(latestThreat.riskLevel)}`}>
            {latestThreat.riskLevel.toUpperCase()} RISK
          </span>
        </div>

        {/* Basic Information */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Globe className="h-4 w-4 text-primary-600" />
              <p className="font-medium text-gray-700">IP Address</p>
            </div>
            <p className="text-lg font-mono text-gray-900">{latestThreat.ip}</p>
          </div>

          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <MapPin className="h-4 w-4 text-primary-600" />
              <p className="font-medium text-gray-700">Location</p>
            </div>
            <p className="text-gray-900">{latestThreat.city}, {latestThreat.country}</p>
          </div>

          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Server className="h-4 w-4 text-primary-600" />
              <p className="font-medium text-gray-700">Organization</p>
            </div>
            <p className="text-gray-900 truncate">{latestThreat.org}</p>
          </div>

          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <Clock className="h-4 w-4 text-primary-600" />
              <p className="font-medium text-gray-700">Last Seen</p>
            </div>
            <p className="text-gray-900">{new Date(latestThreat.lastSeen).toLocaleString()}</p>
          </div>
        </div>

        {/* Open Ports */}
        <div className="p-4 border border-gray-200 rounded-lg">
          <h4 className="font-medium text-gray-700 mb-3">Open Ports ({latestThreat.ports.length})</h4>
          <div className="flex flex-wrap gap-2">
            {latestThreat.ports.length > 0 ? (
              latestThreat.ports.map((port) => (
                <span key={port} className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm font-medium">
                  {port}
                </span>
              ))
            ) : (
              <span className="text-gray-500 text-sm">No open ports detected</span>
            )}
          </div>
        </div>

        {/* Services */}
        <div className="p-4 border border-gray-200 rounded-lg">
          <h4 className="font-medium text-gray-700 mb-3">Detected Services</h4>
          <div className="flex flex-wrap gap-2">
            {latestThreat.services.length > 0 ? (
              latestThreat.services.map((service, index) => (
                <span key={index} className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-medium">
                  {service}
                </span>
              ))
            ) : (
              <span className="text-gray-500 text-sm">No services detected</span>
            )}
          </div>
        </div>

        {/* Vulnerabilities */}
        <div className="p-4 border border-gray-200 rounded-lg">
          <h4 className="font-medium text-gray-700 mb-3">Known Vulnerabilities ({latestThreat.vulnerabilities.length})</h4>
          {latestThreat.vulnerabilities.length > 0 ? (
            <div className="space-y-2">
              {latestThreat.vulnerabilities.map((vuln, index) => (
                <div key={index} className="p-2 bg-red-50 border border-red-200 rounded text-sm text-red-800">
                  {vuln}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-green-600 text-sm">No known vulnerabilities detected</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default ThreatDetails;
