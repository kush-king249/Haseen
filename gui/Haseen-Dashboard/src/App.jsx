import { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { Shield, Activity, Settings, AlertTriangle, BarChart3, Users, Lock, Database, Wifi, Eye, EyeOff } from 'lucide-react'
import { Button } from '@/components/ui/button.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Progress } from '@/components/ui/progress.jsx'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs.jsx'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert.jsx'
import { LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import './App.css'

function App() {
  const [isRunning, setIsRunning] = useState(false)
  const [stats, setStats] = useState({
    totalPackets: 15847,
    blockedPackets: 2341,
    allowedPackets: 13506,
    threatsDetected: 89,
    cpuUsage: 23.5,
    memoryUsage: 67.2,
    uptime: 86400,
    activeConnections: 156
  })

  const [recentAlerts, setRecentAlerts] = useState([
    {
      id: 1,
      type: 'sql_injection',
      severity: 'high',
      sourceIp: '192.168.1.105',
      timestamp: new Date().toLocaleString('ar-SA'),
      description: 'محاولة حقن SQL مكتشفة'
    },
    {
      id: 2,
      type: 'port_scan',
      severity: 'medium',
      sourceIp: '10.0.0.45',
      timestamp: new Date(Date.now() - 300000).toLocaleString('ar-SA'),
      description: 'مسح منافذ مشبوه'
    },
    {
      id: 3,
      type: 'brute_force',
      severity: 'high',
      sourceIp: '203.45.67.89',
      timestamp: new Date(Date.now() - 600000).toLocaleString('ar-SA'),
      description: 'هجوم قوة غاشمة على SSH'
    }
  ])

  const [trafficData, setTrafficData] = useState([
    { time: '00:00', allowed: 120, blocked: 15, threats: 2 },
    { time: '04:00', allowed: 89, blocked: 8, threats: 1 },
    { time: '08:00', allowed: 245, blocked: 32, threats: 5 },
    { time: '12:00', allowed: 189, blocked: 28, threats: 3 },
    { time: '16:00', allowed: 298, blocked: 45, threats: 8 },
    { time: '20:00', allowed: 156, blocked: 22, threats: 4 }
  ])

  const [protocolData, setProtocolData] = useState([
    { name: 'HTTP', value: 45, color: '#3b82f6' },
    { name: 'HTTPS', value: 35, color: '#10b981' },
    { name: 'SSH', value: 8, color: '#f59e0b' },
    { name: 'FTP', value: 7, color: '#ef4444' },
    { name: 'أخرى', value: 5, color: '#8b5cf6' }
  ])

  const [topAttackers, setTopAttackers] = useState([
    { ip: '203.45.67.89', attacks: 23, country: 'غير معروف' },
    { ip: '192.168.1.105', attacks: 18, country: 'محلي' },
    { ip: '10.0.0.45', attacks: 12, country: 'محلي' },
    { ip: '185.220.101.42', attacks: 9, country: 'غير معروف' },
    { ip: '172.16.0.88', attacks: 7, country: 'محلي' }
  ])

  const toggleFirewall = () => {
    setIsRunning(!isRunning)
  }

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high': return 'destructive'
      case 'medium': return 'warning'
      case 'low': return 'secondary'
      default: return 'secondary'
    }
  }

  const formatUptime = (seconds) => {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    return `${days} يوم، ${hours} ساعة، ${minutes} دقيقة`
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800" dir="rtl">
      {/* Header */}
      <header className="bg-white dark:bg-slate-800 shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4 space-x-reverse">
              <div className="flex items-center space-x-2 space-x-reverse">
                <Shield className="h-8 w-8 text-blue-600" />
                <div>
                  <h1 className="text-xl font-bold text-slate-900 dark:text-white">حصين</h1>
                  <p className="text-xs text-slate-500 dark:text-slate-400">نظام جدار الحماية المتقدم</p>
                </div>
              </div>
            </div>
            
            <div className="flex items-center space-x-4 space-x-reverse">
              <Badge variant={isRunning ? "default" : "secondary"} className="flex items-center space-x-1 space-x-reverse">
                <div className={`w-2 h-2 rounded-full ${isRunning ? 'bg-green-500' : 'bg-gray-400'}`}></div>
                <span>{isRunning ? 'يعمل' : 'متوقف'}</span>
              </Badge>
              
              <Button 
                onClick={toggleFirewall}
                variant={isRunning ? "destructive" : "default"}
                className="flex items-center space-x-2 space-x-reverse"
              >
                {isRunning ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                <span>{isRunning ? 'إيقاف' : 'تشغيل'}</span>
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card className="bg-gradient-to-r from-blue-500 to-blue-600 text-white">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">إجمالي الحزم</CardTitle>
              <Activity className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.totalPackets.toLocaleString('ar-SA')}</div>
              <p className="text-xs opacity-80">منذ بدء التشغيل</p>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-red-500 to-red-600 text-white">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">الحزم المحظورة</CardTitle>
              <Lock className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.blockedPackets.toLocaleString('ar-SA')}</div>
              <p className="text-xs opacity-80">
                {((stats.blockedPackets / stats.totalPackets) * 100).toFixed(1)}% من الإجمالي
              </p>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-green-500 to-green-600 text-white">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">الحزم المسموحة</CardTitle>
              <Wifi className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.allowedPackets.toLocaleString('ar-SA')}</div>
              <p className="text-xs opacity-80">
                {((stats.allowedPackets / stats.totalPackets) * 100).toFixed(1)}% من الإجمالي
              </p>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-orange-500 to-orange-600 text-white">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">التهديدات المكتشفة</CardTitle>
              <AlertTriangle className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.threatsDetected}</div>
              <p className="text-xs opacity-80">تهديد نشط</p>
            </CardContent>
          </Card>
        </div>

        {/* System Status */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 space-x-reverse">
                <BarChart3 className="h-5 w-5" />
                <span>حالة النظام</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>استخدام المعالج</span>
                  <span>{stats.cpuUsage}%</span>
                </div>
                <Progress value={stats.cpuUsage} className="h-2" />
              </div>
              
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>استخدام الذاكرة</span>
                  <span>{stats.memoryUsage}%</span>
                </div>
                <Progress value={stats.memoryUsage} className="h-2" />
              </div>
              
              <div className="pt-2 border-t">
                <div className="text-sm text-slate-600 dark:text-slate-400">
                  <p>مدة التشغيل: {formatUptime(stats.uptime)}</p>
                  <p>الاتصالات النشطة: {stats.activeConnections}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>توزيع البروتوكولات</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={protocolData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {protocolData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value) => `${value}%`} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 space-x-reverse">
                <Users className="h-5 w-5" />
                <span>أكثر المهاجمين نشاطاً</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {topAttackers.slice(0, 5).map((attacker, index) => (
                  <div key={index} className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium">{attacker.ip}</p>
                      <p className="text-xs text-slate-500">{attacker.country}</p>
                    </div>
                    <Badge variant="destructive">{attacker.attacks}</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="dashboard" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="dashboard">لوحة التحكم</TabsTrigger>
            <TabsTrigger value="alerts">التنبيهات</TabsTrigger>
            <TabsTrigger value="traffic">حركة المرور</TabsTrigger>
            <TabsTrigger value="rules">القواعد</TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>حركة المرور خلال 24 ساعة</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={trafficData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Area type="monotone" dataKey="allowed" stackId="1" stroke="#10b981" fill="#10b981" name="مسموح" />
                      <Area type="monotone" dataKey="blocked" stackId="1" stroke="#ef4444" fill="#ef4444" name="محظور" />
                      <Area type="monotone" dataKey="threats" stackId="1" stroke="#f59e0b" fill="#f59e0b" name="تهديدات" />
                    </AreaChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>الأحداث الأخيرة</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 max-h-80 overflow-y-auto">
                    {recentAlerts.map((alert) => (
                      <Alert key={alert.id} className="border-r-4 border-r-red-500">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertTitle className="flex items-center justify-between">
                          <span>{alert.description}</span>
                          <Badge variant={getSeverityColor(alert.severity)}>
                            {alert.severity === 'high' ? 'عالي' : alert.severity === 'medium' ? 'متوسط' : 'منخفض'}
                          </Badge>
                        </AlertTitle>
                        <AlertDescription>
                          <div className="mt-2 text-sm text-slate-600 dark:text-slate-400">
                            <p>المصدر: {alert.sourceIp}</p>
                            <p>الوقت: {alert.timestamp}</p>
                          </div>
                        </AlertDescription>
                      </Alert>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="alerts">
            <Card>
              <CardHeader>
                <CardTitle>سجل التنبيهات</CardTitle>
                <CardDescription>جميع التنبيهات الأمنية المكتشفة</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {recentAlerts.map((alert) => (
                    <div key={alert.id} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center space-x-3 space-x-reverse">
                        <AlertTriangle className={`h-5 w-5 ${
                          alert.severity === 'high' ? 'text-red-500' : 
                          alert.severity === 'medium' ? 'text-yellow-500' : 'text-blue-500'
                        }`} />
                        <div>
                          <p className="font-medium">{alert.description}</p>
                          <p className="text-sm text-slate-500">من {alert.sourceIp} في {alert.timestamp}</p>
                        </div>
                      </div>
                      <Badge variant={getSeverityColor(alert.severity)}>
                        {alert.severity === 'high' ? 'عالي' : alert.severity === 'medium' ? 'متوسط' : 'منخفض'}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="traffic">
            <Card>
              <CardHeader>
                <CardTitle>تحليل حركة المرور</CardTitle>
                <CardDescription>إحصائيات مفصلة لحركة البيانات</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={400}>
                  <LineChart data={trafficData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Line type="monotone" dataKey="allowed" stroke="#10b981" strokeWidth={2} name="مسموح" />
                    <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} name="محظور" />
                    <Line type="monotone" dataKey="threats" stroke="#f59e0b" strokeWidth={2} name="تهديدات" />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="rules">
            <Card>
              <CardHeader>
                <CardTitle>قواعد جدار الحماية</CardTitle>
                <CardDescription>إدارة قواعد الحماية والتحكم في الوصول</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-lg font-medium">القواعد النشطة</h3>
                    <Button>إضافة قاعدة جديدة</Button>
                  </div>
                  
                  <div className="space-y-3">
                    {[
                      { name: 'السماح لحركة HTTP المحلية', status: 'نشط', priority: 1 },
                      { name: 'حظر SSH من الخارج', status: 'نشط', priority: 2 },
                      { name: 'السماح لـ DNS', status: 'نشط', priority: 3 },
                      { name: 'حظر المنافذ المشبوهة', status: 'نشط', priority: 4 }
                    ].map((rule, index) => (
                      <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                        <div>
                          <p className="font-medium">{rule.name}</p>
                          <p className="text-sm text-slate-500">الأولوية: {rule.priority}</p>
                        </div>
                        <div className="flex items-center space-x-2 space-x-reverse">
                          <Badge variant="default">{rule.status}</Badge>
                          <Button variant="outline" size="sm">تعديل</Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="bg-white dark:bg-slate-800 border-t mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex justify-between items-center">
            <div className="text-sm text-slate-500 dark:text-slate-400">
              <p>© 2024 حصين - نظام جدار الحماية المتقدم</p>
              <p>تم التطوير بواسطة Hassan Mohamed Hassan Ahmed</p>
            </div>
            <div className="flex items-center space-x-4 space-x-reverse">
              <Button variant="ghost" size="sm">
                <Settings className="h-4 w-4 ml-2" />
                الإعدادات
              </Button>
              <Button variant="ghost" size="sm">
                <Database className="h-4 w-4 ml-2" />
                النسخ الاحتياطي
              </Button>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App
