import React from 'react';
import { MapPin, Globe } from 'lucide-react';
import { useApi } from '../../context/ApiContext';

const ThreatMap = () => {
  const { threatData } = useApi();

  const threatsByCountry = threatData.reduce((acc, threat) => {
    acc[threat.country] = (acc[threat.country] || 0) + 1;
    return acc;
  }, {});

  const topCountries = Object.entries(threatsByCountry)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex items-center gap-3 mb-6">
        <Globe className="h-6 w-6 text-primary-600" />
        <h3 className="text-lg font-semibold text-gray-800">Global Threat Distribution</h3>
      </div>

      <div className="space-y-4">
        {topCountries.length > 0 ? (
          topCountries.map(([country, count]) => (
            <div key={country} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
              <div className="flex items-center gap-3">
                <MapPin className="h-4 w-4 text-danger-500" />
                <span className="font-medium text-gray-700">{country}</span>
              </div>
              <div className="flex items-center gap-2 w-1/2">
                <span className="text-sm text-gray-600">{count} threats</span>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-danger-500 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${(count / Math.max(...Object.values(threatsByCountry))) * 100}%` }}
                  ></div>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="text-center py-8 text-gray-500">
            <Globe className="h-12 w-12 mx-auto mb-3 text-gray-300" />
            <p>No threat data available</p>
            <p className="text-sm">Start analyzing IPs to see threat distribution</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatMap;
