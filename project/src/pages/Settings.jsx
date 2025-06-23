import React from 'react';
import { Settings as SettingsIcon, Key, Bell, Shield, Database } from 'lucide-react';

const Settings = () => {
  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-6">
          <SettingsIcon className="h-6 w-6 text-primary-600" />
          <h2 className="text-xl font-semibold text-gray-800">Settings</h2>
        </div>

        <div className="space-y-6">
          {/* API Configuration */}
          <div className="p-6 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-3 mb-4">
              <Key className="h-5 w-5 text-primary-600" />
              <h3 className="text-lg font-semibold text-gray-800">API Configuration</h3>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Shodan API Key
                </label>
                <input
                  type="password"
                  placeholder="Enter your Shodan API key"
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Get your API key from <a href="https://shodan.io" target="_blank" rel="noopener noreferrer" className="text-primary-600 hover:underline">shodan.io</a>
                </p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  VirusTotal API Key
                </label>
                <input
                  type="password"
                  placeholder="Enter your VirusTotal API key"
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Get your API key from <a href="https://virustotal.com" target="_blank" rel="noopener noreferrer" className="text-primary-600 hover:underline">virustotal.com</a>
                </p>
              </div>
            </div>
          </div>

          {/* Notification Settings */}
          <div className="p-6 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-3 mb-4">
              <Bell className="h-5 w-5 text-primary-600" />
              <h3 className="text-lg font-semibold text-gray-800">Notification Settings</h3>
            </div>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-gray-700">High Risk Threats</p>
                  <p className="text-sm text-gray-500">Get notified when high or critical threats are detected</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" className="sr-only peer" defaultChecked />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                </label>
              </div>
              
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-gray-700">New Vulnerabilities</p>
                  <p className="text-sm text-gray-500">Alert when new vulnerabilities are discovered</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" className="sr-only peer" defaultChecked />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                </label>
              </div>
            </div>
          </div>

          {/* Security Settings */}
          <div className="p-6 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-3 mb-4">
              <Shield className="h-5 w-5 text-primary-600" />
              <h3 className="text-lg font-semibold text-gray-800">Security Settings</h3>
            </div>
            
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-gray-700">Auto-block High Risk IPs</p>
                  <p className="text-sm text-gray-500">Automatically block IPs with critical risk levels</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" className="sr-only peer" />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
                </label>
              </div>
            </div>
          </div>

          {/* Data Management */}
          <div className="p-6 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-3 mb-4">
              <Database className="h-5 w-5 text-primary-600" />
              <h3 className="text-lg font-semibold text-gray-800">Data Management</h3>
            </div>
            
            <div className="space-y-4">
              <button className="px-4 py-2 bg-danger-600 text-white rounded-lg hover:bg-danger-700 transition-colors">
                Clear All Threat Data
              </button>
              <p className="text-sm text-gray-500">
                This will permanently delete all stored threat analysis data
              </p>
            </div>
          </div>

          {/* Save Button */}
          <div className="flex justify-end">
            <button className="px-6 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors">
              Save Settings
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
