import React from 'react';
import { Activity as ActivityIcon, Clock, MapPin, Server } from 'lucide-react';
import { useApi } from '../context/ApiContext';

const Activity = () => {
  const { threatData } = useApi();

  const sortedActivity = [...threatData].sort(
    (a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime()
  );

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <ActivityIcon className="h-6 w-6 text-primary-600" />
          <h2 className="text-xl font-semibold text-gray-800">Activity Log</h2>
        </div>

        <div className="space-y-4">
          {sortedActivity.length > 0 ? (
            sortedActivity.map((activity) => (
              <div
                key={activity.id}
                className="p-4 border border-gray-200 rounded-lg hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-3 h-3 rounded-full ${
                        activity.riskLevel === 'critical'
                          ? 'bg-red-500'
                          : activity.riskLevel === 'high'
                          ? 'bg-orange-500'
                          : activity.riskLevel === 'medium'
                          ? 'bg-yellow-500'
                          : 'bg-green-500'
                      }`}
                    ></div>
                    <div>
                      <p className="font-semibold text-gray-800">Threat Analysis Completed</p>
                      <p className="text-sm text-gray-600">IP Address: {activity.ip}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-gray-500">
                    <Clock className="h-4 w-4" />
                    <span>{new Date(activity.lastSeen).toLocaleString()}</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div className="flex items-center gap-2">
                    <MapPin className="h-4 w-4 text-gray-400" />
                    <span className="text-gray-600">Location:</span>
                    <span className="font-medium">
                      {activity.city}, {activity.country}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Server className="h-4 w-4 text-gray-400" />
                    <span className="text-gray-600">Ports:</span>
                    <span className="font-medium">{activity.ports.length} open</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-gray-600">Risk Level:</span>
                    <span
                      className={`font-medium ${
                        activity.riskLevel === 'critical'
                          ? 'text-red-600'
                          : activity.riskLevel === 'high'
                          ? 'text-orange-600'
                          : activity.riskLevel === 'medium'
                          ? 'text-yellow-600'
                          : 'text-green-600'
                      }`}
                    >
                      {activity.riskLevel.toUpperCase()}
                    </span>
                  </div>
                </div>

                {activity.vulnerabilities.length > 0 && (
                  <div className="mt-3 p-2 bg-red-50 border border-red-200 rounded text-sm">
                    <span className="text-red-700 font-medium">
                      {activity.vulnerabilities.length} vulnerabilities detected
                    </span>
                  </div>
                )}
              </div>
            ))
          ) : (
            <div className="text-center py-12 text-gray-500">
              <ActivityIcon className="h-16 w-16 mx-auto mb-4 text-gray-300" />
              <h3 className="text-lg font-medium text-gray-700 mb-2">No Activity Recorded</h3>
              <p>Start analyzing IP addresses to see activity logs</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Activity;
