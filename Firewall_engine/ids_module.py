#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Haseen Intrusion Detection System (IDS)
نظام كشف التسلل

هذا الملف يحتوي على منطق كشف التسلل والهجمات
This file contains intrusion detection and attack detection logic
"""

import time
import json
import yaml
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
import ipaddress

@dataclass
class ThreatAlert:
    """تنبيه تهديد"""
    threat_id: str
    threat_type: str
    severity: str  # low, medium, high, critical
    source_ip: str
    target_ip: str
    description: str
    timestamp: float
    evidence: Dict[str, Any]
    risk_score: int

class IDSModule:
    """وحدة كشف التسلل"""
    
    def __init__(self, config: Dict[str, Any]):
        """تهيئة نظام كشف التسلل"""
        self.config = config
        self.enabled = config.get('enabled', True)
        self.alert_threshold = config.get('alert_threshold', 5)
        self.rules_file = config.get('rules_file', 'ids_rules.yaml')
        
        # تحميل قواعد الكشف
        self.detection_rules = self._load_detection_rules()
        
        # إحصائيات الهجمات
        self.attack_stats = defaultdict(int)
        self.recent_alerts = deque(maxlen=1000)
        
        # تتبع الأنشطة المشبوهة
        self.suspicious_ips = defaultdict(list)
        self.connection_tracking = defaultdict(dict)
        self.failed_attempts = defaultdict(int)
        
        # قوائم سوداء وبيضاء
        self.blacklisted_ips = set()
        self.whitelisted_ips = set()
        
        # أنماط الهجمات المعروفة
        self.attack_patterns = {
            'port_scan': {
                'description': 'مسح المنافذ',
                'pattern': 'multiple_ports_single_ip',
                'threshold': 10,
                'time_window': 60
            },
            'brute_force': {
                'description': 'هجوم القوة الغاشمة',
                'pattern': 'multiple_failed_auth',
                'threshold': 5,
                'time_window': 300
            },
            'ddos': {
                'description': 'هجوم حجب الخدمة الموزع',
                'pattern': 'high_connection_rate',
                'threshold': 100,
                'time_window': 60
            },
            'sql_injection': {
                'description': 'حقن SQL',
                'pattern': 'sql_patterns_in_payload',
                'threshold': 1,
                'time_window': 1
            },
            'xss': {
                'description': 'هجوم البرمجة النصية المتقاطعة',
                'pattern': 'xss_patterns_in_payload',
                'threshold': 1,
                'time_window': 1
            }
        }
        
        # معرفات التهديدات
        self.threat_counter = 0
    
    def _load_detection_rules(self) -> Dict[str, Any]:
        """تحميل قواعد الكشف"""
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # إنشاء قواعد افتراضية
            default_rules = {
                'signature_rules': [
                    {
                        'id': 'SQL_001',
                        'name': 'SQL Injection Attempt',
                        'pattern': r'(\bunion\b.*\bselect\b)|(\bselect\b.*\bfrom\b.*\bwhere\b)',
                        'severity': 'high',
                        'description': 'محاولة حقن SQL مكتشفة'
                    },
                    {
                        'id': 'XSS_001',
                        'name': 'Cross-Site Scripting Attempt',
                        'pattern': r'<script.*?>.*?</script>|javascript:',
                        'severity': 'medium',
                        'description': 'محاولة هجوم XSS مكتشفة'
                    },
                    {
                        'id': 'CMD_001',
                        'name': 'Command Injection Attempt',
                        'pattern': r';.*\b(cat|ls|pwd|whoami|id|uname)\b',
                        'severity': 'high',
                        'description': 'محاولة حقن أوامر مكتشفة'
                    }
                ],
                'behavioral_rules': [
                    {
                        'id': 'SCAN_001',
                        'name': 'Port Scan Detection',
                        'type': 'port_scan',
                        'threshold': 10,
                        'time_window': 60,
                        'severity': 'medium',
                        'description': 'مسح منافذ مكتشف'
                    },
                    {
                        'id': 'BRUTE_001',
                        'name': 'Brute Force Attack',
                        'type': 'brute_force',
                        'threshold': 5,
                        'time_window': 300,
                        'severity': 'high',
                        'description': 'هجوم قوة غاشمة مكتشف'
                    }
                ],
                'ip_reputation': {
                    'blacklist': [],
                    'whitelist': ['127.0.0.1', '::1']
                }
            }
            
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                yaml.dump(default_rules, f, default_flow_style=False, allow_unicode=True)
            
            return default_rules
    
    def check_packet(self, packet_data: Dict[str, Any], 
                    analysis_result: Any) -> Dict[str, Any]:
        """فحص الحزمة للكشف عن التهديدات"""
        if not self.enabled:
            return {'threat_detected': False}
        
        result = {
            'threat_detected': False,
            'alerts': [],
            'risk_score': 0,
            'threat_types': []
        }
        
        try:
            src_ip = packet_data.get('src_ip', '')
            dst_ip = packet_data.get('dst_ip', '')
            
            # فحص القوائم السوداء والبيضاء
            if self._is_blacklisted(src_ip):
                alert = self._create_alert(
                    'BLACKLIST_001',
                    'blacklisted_ip',
                    'high',
                    src_ip,
                    dst_ip,
                    f'حركة مرور من IP مدرج في القائمة السوداء: {src_ip}',
                    {'blacklisted_ip': src_ip}
                )
                result['alerts'].append(alert)
                result['threat_detected'] = True
                result['threat_types'].append('blacklisted_ip')
            
            if self._is_whitelisted(src_ip):
                return result  # تخطي الفحص للعناوين الموثوقة
            
            # فحص القواعد التوقيعية
            signature_alerts = self._check_signature_rules(packet_data)
            if signature_alerts:
                result['alerts'].extend(signature_alerts)
                result['threat_detected'] = True
                result['threat_types'].extend([alert.threat_type for alert in signature_alerts])
            
            # فحص القواعد السلوكية
            behavioral_alerts = self._check_behavioral_rules(packet_data)
            if behavioral_alerts:
                result['alerts'].extend(behavioral_alerts)
                result['threat_detected'] = True
                result['threat_types'].extend([alert.threat_type for alert in behavioral_alerts])
            
            # فحص الأنماط المشبوهة
            pattern_alerts = self._check_attack_patterns(packet_data, analysis_result)
            if pattern_alerts:
                result['alerts'].extend(pattern_alerts)
                result['threat_detected'] = True
                result['threat_types'].extend([alert.threat_type for alert in pattern_alerts])
            
            # حساب درجة المخاطر الإجمالية
            if result['alerts']:
                result['risk_score'] = self._calculate_threat_risk_score(result['alerts'])
            
            # تحديث الإحصائيات
            self._update_statistics(result)
            
            # حفظ التنبيهات
            for alert in result['alerts']:
                self.recent_alerts.append(alert)
            
            return result
            
        except Exception as e:
            return {
                'threat_detected': False,
                'error': str(e),
                'alerts': [],
                'risk_score': 0,
                'threat_types': []
            }
    
    def _is_blacklisted(self, ip: str) -> bool:
        """فحص ما إذا كان العنوان في القائمة السوداء"""
        return ip in self.blacklisted_ips
    
    def _is_whitelisted(self, ip: str) -> bool:
        """فحص ما إذا كان العنوان في القائمة البيضاء"""
        return ip in self.whitelisted_ips
    
    def _check_signature_rules(self, packet_data: Dict[str, Any]) -> List[ThreatAlert]:
        """فحص القواعد التوقيعية"""
        alerts = []
        payload = packet_data.get('payload', '')
        
        if not payload:
            return alerts
        
        signature_rules = self.detection_rules.get('signature_rules', [])
        
        for rule in signature_rules:
            pattern = rule.get('pattern', '')
            if re.search(pattern, payload, re.IGNORECASE):
                alert = self._create_alert(
                    rule['id'],
                    rule['name'].lower().replace(' ', '_'),
                    rule['severity'],
                    packet_data.get('src_ip', ''),
                    packet_data.get('dst_ip', ''),
                    rule['description'],
                    {
                        'rule_id': rule['id'],
                        'pattern': pattern,
                        'matched_content': payload[:200]  # أول 200 حرف
                    }
                )
                alerts.append(alert)
        
        return alerts
    
    def _check_behavioral_rules(self, packet_data: Dict[str, Any]) -> List[ThreatAlert]:
        """فحص القواعد السلوكية"""
        alerts = []
        src_ip = packet_data.get('src_ip', '')
        dst_port = packet_data.get('dst_port', 0)
        timestamp = packet_data.get('timestamp', time.time())
        
        # تتبع الاتصالات
        self._track_connection(src_ip, dst_port, timestamp)
        
        behavioral_rules = self.detection_rules.get('behavioral_rules', [])
        
        for rule in behavioral_rules:
            rule_type = rule.get('type', '')
            
            if rule_type == 'port_scan':
                if self._detect_port_scan(src_ip, rule):
                    alert = self._create_alert(
                        rule['id'],
                        'port_scan',
                        rule['severity'],
                        src_ip,
                        packet_data.get('dst_ip', ''),
                        rule['description'],
                        {
                            'scanned_ports': list(self.connection_tracking[src_ip].keys()),
                            'port_count': len(self.connection_tracking[src_ip])
                        }
                    )
                    alerts.append(alert)
            
            elif rule_type == 'brute_force':
                if self._detect_brute_force(src_ip, rule):
                    alert = self._create_alert(
                        rule['id'],
                        'brute_force',
                        rule['severity'],
                        src_ip,
                        packet_data.get('dst_ip', ''),
                        rule['description'],
                        {
                            'failed_attempts': self.failed_attempts[src_ip],
                            'time_window': rule['time_window']
                        }
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _check_attack_patterns(self, packet_data: Dict[str, Any], 
                             analysis_result: Any) -> List[ThreatAlert]:
        """فحص أنماط الهجمات"""
        alerts = []
        
        # استخراج الأنماط المشبوهة من نتائج التحليل
        if hasattr(analysis_result, 'suspicious_patterns'):
            suspicious_patterns = analysis_result.suspicious_patterns
            
            for pattern in suspicious_patterns:
                if pattern in ['sql_injection', 'xss', 'command_injection']:
                    alert = self._create_alert(
                        f'PATTERN_{pattern.upper()}',
                        pattern,
                        'high',
                        packet_data.get('src_ip', ''),
                        packet_data.get('dst_ip', ''),
                        f'نمط هجوم مكتشف: {pattern}',
                        {
                            'pattern_type': pattern,
                            'payload_sample': packet_data.get('payload', '')[:100]
                        }
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _track_connection(self, src_ip: str, dst_port: int, timestamp: float):
        """تتبع الاتصالات"""
        if src_ip not in self.connection_tracking:
            self.connection_tracking[src_ip] = {}
        
        if dst_port not in self.connection_tracking[src_ip]:
            self.connection_tracking[src_ip][dst_port] = []
        
        self.connection_tracking[src_ip][dst_port].append(timestamp)
        
        # تنظيف البيانات القديمة (أكثر من ساعة)
        cutoff_time = timestamp - 3600
        self.connection_tracking[src_ip][dst_port] = [
            t for t in self.connection_tracking[src_ip][dst_port] if t > cutoff_time
        ]
    
    def _detect_port_scan(self, src_ip: str, rule: Dict[str, Any]) -> bool:
        """كشف مسح المنافذ"""
        if src_ip not in self.connection_tracking:
            return False
        
        threshold = rule.get('threshold', 10)
        time_window = rule.get('time_window', 60)
        current_time = time.time()
        
        # عد المنافذ المختلفة في النافزة الزمنية
        recent_ports = set()
        for port, timestamps in self.connection_tracking[src_ip].items():
            for timestamp in timestamps:
                if current_time - timestamp <= time_window:
                    recent_ports.add(port)
        
        return len(recent_ports) >= threshold
    
    def _detect_brute_force(self, src_ip: str, rule: Dict[str, Any]) -> bool:
        """كشف هجوم القوة الغاشمة"""
        threshold = rule.get('threshold', 5)
        return self.failed_attempts[src_ip] >= threshold
    
    def _create_alert(self, threat_id: str, threat_type: str, severity: str,
                     source_ip: str, target_ip: str, description: str,
                     evidence: Dict[str, Any]) -> ThreatAlert:
        """إنشاء تنبيه تهديد"""
        self.threat_counter += 1
        
        # حساب درجة المخاطر حسب الخطورة
        risk_score_map = {
            'low': 25,
            'medium': 50,
            'high': 75,
            'critical': 100
        }
        
        return ThreatAlert(
            threat_id=f"{threat_id}_{self.threat_counter}",
            threat_type=threat_type,
            severity=severity,
            source_ip=source_ip,
            target_ip=target_ip,
            description=description,
            timestamp=time.time(),
            evidence=evidence,
            risk_score=risk_score_map.get(severity, 50)
        )
    
    def _calculate_threat_risk_score(self, alerts: List[ThreatAlert]) -> int:
        """حساب درجة المخاطر الإجمالية للتهديدات"""
        if not alerts:
            return 0
        
        # حساب المتوسط المرجح للدرجات
        total_score = sum(alert.risk_score for alert in alerts)
        max_score = max(alert.risk_score for alert in alerts)
        
        # الجمع بين المتوسط والحد الأقصى
        final_score = int((total_score / len(alerts)) * 0.7 + max_score * 0.3)
        
        return min(final_score, 100)
    
    def _update_statistics(self, result: Dict[str, Any]):
        """تحديث إحصائيات الهجمات"""
        if result['threat_detected']:
            for threat_type in result['threat_types']:
                self.attack_stats[threat_type] += 1
    
    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """الحصول على التنبيهات الأخيرة"""
        alerts = list(self.recent_alerts)[-limit:]
        return [asdict(alert) for alert in alerts]
    
    def get_attack_statistics(self) -> Dict[str, Any]:
        """الحصول على إحصائيات الهجمات"""
        return {
            'total_alerts': len(self.recent_alerts),
            'attack_types': dict(self.attack_stats),
            'top_attackers': self._get_top_attackers(),
            'recent_activity': self._get_recent_activity()
        }
    
    def _get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """الحصول على أكثر المهاجمين نشاطاً"""
        attacker_counts = defaultdict(int)
        
        for alert in self.recent_alerts:
            attacker_counts[alert.source_ip] += 1
        
        sorted_attackers = sorted(
            attacker_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]
        
        return [
            {'ip': ip, 'alert_count': count}
            for ip, count in sorted_attackers
        ]
    
    def _get_recent_activity(self, hours: int = 24) -> Dict[str, int]:
        """الحصول على النشاط الأخير"""
        cutoff_time = time.time() - (hours * 3600)
        recent_alerts = [
            alert for alert in self.recent_alerts
            if alert.timestamp > cutoff_time
        ]
        
        activity = defaultdict(int)
        for alert in recent_alerts:
            activity[alert.threat_type] += 1
        
        return dict(activity)
    
    def add_to_blacklist(self, ip: str) -> bool:
        """إضافة عنوان IP للقائمة السوداء"""
        try:
            ipaddress.ip_address(ip)  # التحقق من صحة العنوان
            self.blacklisted_ips.add(ip)
            return True
        except ValueError:
            return False
    
    def remove_from_blacklist(self, ip: str) -> bool:
        """إزالة عنوان IP من القائمة السوداء"""
        if ip in self.blacklisted_ips:
            self.blacklisted_ips.remove(ip)
            return True
        return False
    
    def reload_rules(self) -> bool:
        """إعادة تحميل قواعد الكشف"""
        try:
            self.detection_rules = self._load_detection_rules()
            return True
        except Exception:
            return False

if __name__ == "__main__":
    # اختبار نظام كشف التسلل
    config = {
        'enabled': True,
        'alert_threshold': 5,
        'rules_file': 'ids_rules.yaml'
    }
    
    ids = IDSModule(config)
    
    # حزمة اختبار مشبوهة
    test_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'payload': "GET /index.php?id=1' OR '1'='1 HTTP/1.1",
        'timestamp': time.time()
    }
    
    # محاكاة نتائج التحليل
    class MockAnalysis:
        def __init__(self):
            self.suspicious_patterns = ['sql_injection']
    
    analysis = MockAnalysis()
    result = ids.check_packet(test_packet, analysis)
    
    print(f"تهديد مكتشف: {result['threat_detected']}")
    print(f"عدد التنبيهات: {len(result['alerts'])}")
    print(f"أنواع التهديدات: {result['threat_types']}")
    print(f"درجة المخاطر: {result['risk_score']}")
