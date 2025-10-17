#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Haseen Rules Engine
محرك قواعد جدار الحماية

هذا الملف يحتوي على منطق تطبيق قواعد جدار الحماية
This file contains firewall rules application logic
"""

import yaml
import re
import ipaddress
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

class RuleAction(Enum):
    """إجراءات القواعد"""
    ALLOW = "allow"
    BLOCK = "block"
    DROP = "drop"
    LOG = "log"
    ALERT = "alert"

class RuleDirection(Enum):
    """اتجاهات القواعد"""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"

@dataclass
class FirewallRule:
    """قاعدة جدار الحماية"""
    id: str
    name: str
    enabled: bool
    priority: int
    action: RuleAction
    direction: RuleDirection
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    description: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0

@dataclass
class RuleResult:
    """نتيجة تطبيق القاعدة"""
    action: str
    rule_id: Optional[str]
    rule_name: Optional[str]
    matched: bool
    reason: str
    processing_time: float

class RulesEngine:
    """محرك قواعد جدار الحماية"""
    
    def __init__(self, config: Dict[str, Any]):
        """تهيئة محرك القواعد"""
        self.config = config
        self.default_action = config.get('default_action', 'allow')
        self.rules_file = config.get('rules_file', 'firewall_rules.yaml')
        
        # تحميل القواعد
        self.rule_stats = {}
        self.rules: List[FirewallRule] = []
        self.load_rules()
        self.total_processed = 0
        self.total_blocked = 0
        self.total_allowed = 0
        
        # ذاكرة التخزين المؤقت للقواعد
        self.rule_cache = {}
        self.cache_size = config.get('cache_size', 1000)
    
    def load_rules(self) -> bool:
        """تحميل القواعد من الملف"""
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                rules_data = yaml.safe_load(f)
            
            self.rules = []
            for rule_data in rules_data.get('rules', []):
                rule = FirewallRule(
                    id=rule_data['id'],
                    name=rule_data['name'],
                    enabled=rule_data.get('enabled', True),
                    priority=rule_data.get('priority', 100),
                    action=RuleAction(rule_data['action']),
                    direction=RuleDirection(rule_data.get('direction', 'bidirectional')),
                    source_ip=rule_data.get('source_ip'),
                    destination_ip=rule_data.get('destination_ip'),
                    source_port=rule_data.get('source_port'),
                    destination_port=rule_data.get('destination_port'),
                    protocol=rule_data.get('protocol'),
                    description=rule_data.get('description', ''),
                    created_at=rule_data.get('created_at', time.time()),
                    updated_at=rule_data.get('updated_at', time.time())
                )
                self.rules.append(rule)
            
            # ترتيب القواعد حسب الأولوية
            self.rules.sort(key=lambda x: x.priority)
            
            # تهيئة إحصائيات القواعد
            for rule in self.rules:
                self.rule_stats[rule.id] = {
                    'matches': 0,
                    'last_match': None
                }
            
            return True
            
        except FileNotFoundError:
            # إنشاء قواعد افتراضية
            self._create_default_rules()
            return True
        except Exception as e:
            print(f"خطأ في تحميل القواعد: {e}")
            return False
    
    def _create_default_rules(self):
        """إنشاء قواعد افتراضية"""
        default_rules = {
            'rules': [
                {
                    'id': 'ALLOW_LOOPBACK',
                    'name': 'السماح لحركة المرور المحلية',
                    'enabled': True,
                    'priority': 1,
                    'action': 'allow',
                    'direction': 'bidirectional',
                    'source_ip': '127.0.0.0/8',
                    'description': 'السماح لجميع حركة المرور المحلية'
                },
                {
                    'id': 'ALLOW_PRIVATE_HTTP',
                    'name': 'السماح لـ HTTP من الشبكة الخاصة',
                    'enabled': True,
                    'priority': 10,
                    'action': 'allow',
                    'direction': 'inbound',
                    'source_ip': '192.168.0.0/16',
                    'destination_port': 80,
                    'protocol': 'TCP',
                    'description': 'السماح لحركة HTTP من الشبكة الخاصة'
                },
                {
                    'id': 'ALLOW_PRIVATE_HTTPS',
                    'name': 'السماح لـ HTTPS من الشبكة الخاصة',
                    'enabled': True,
                    'priority': 10,
                    'action': 'allow',
                    'direction': 'inbound',
                    'source_ip': '192.168.0.0/16',
                    'destination_port': 443,
                    'protocol': 'TCP',
                    'description': 'السماح لحركة HTTPS من الشبكة الخاصة'
                },
                {
                    'id': 'BLOCK_SSH_EXTERNAL',
                    'name': 'حظر SSH من الخارج',
                    'enabled': True,
                    'priority': 20,
                    'action': 'block',
                    'direction': 'inbound',
                    'destination_port': 22,
                    'protocol': 'TCP',
                    'description': 'حظر محاولات SSH من الخارج'
                },
                {
                    'id': 'ALLOW_DNS',
                    'name': 'السماح لـ DNS',
                    'enabled': True,
                    'priority': 5,
                    'action': 'allow',
                    'direction': 'bidirectional',
                    'destination_port': 53,
                    'description': 'السماح لاستعلامات DNS'
                },
                {
                    'id': 'BLOCK_SUSPICIOUS_PORTS',
                    'name': 'حظر المنافذ المشبوهة',
                    'enabled': True,
                    'priority': 30,
                    'action': 'block',
                    'direction': 'inbound',
                    'destination_port': '1433,3389,5432',
                    'description': 'حظر المنافذ المشبوهة (قواعد البيانات، RDP)'
                }
            ]
        }
        
        with open(self.rules_file, 'w', encoding='utf-8') as f:
            yaml.dump(default_rules, f, default_flow_style=False, allow_unicode=True)
        
        self.load_rules()
    
    def apply_rules(self, packet_data: Dict[str, Any], 
                   analysis_result: Any, ids_result: Dict[str, Any]) -> RuleResult:
        """تطبيق القواعد على الحزمة"""
        start_time = time.time()
        
        try:
            self.total_processed += 1
            
            # إنشاء مفتاح للذاكرة المؤقتة
            cache_key = self._generate_cache_key(packet_data)
            
            # فحص الذاكرة المؤقتة
            if cache_key in self.rule_cache:
                cached_result = self.rule_cache[cache_key]
                cached_result.processing_time = time.time() - start_time
                return cached_result
            
            # تطبيق القواعد
            for rule in self.rules:
                if not rule.enabled:
                    continue
                
                if self._rule_matches(rule, packet_data, analysis_result, ids_result):
                    # تحديث إحصائيات القاعدة
                    self.rule_stats[rule.id]['matches'] += 1
                    self.rule_stats[rule.id]['last_match'] = time.time()
                    
                    # إنشاء النتيجة
                    result = RuleResult(
                        action=rule.action.value,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        matched=True,
                        reason=f"تطابق مع القاعدة: {rule.name}",
                        processing_time=time.time() - start_time
                    )
                    
                    # تحديث الإحصائيات العامة
                    if rule.action in [RuleAction.BLOCK, RuleAction.DROP]:
                        self.total_blocked += 1
                    elif rule.action == RuleAction.ALLOW:
                        self.total_allowed += 1
                    
                    # حفظ في الذاكرة المؤقتة
                    self._cache_result(cache_key, result)
                    
                    return result
            
            # لا توجد قاعدة متطابقة، تطبيق الإجراء الافتراضي
            result = RuleResult(
                action=self.default_action,
                rule_id=None,
                rule_name=None,
                matched=False,
                reason=f"تطبيق الإجراء الافتراضي: {self.default_action}",
                processing_time=time.time() - start_time
            )
            
            if self.default_action == 'allow':
                self.total_allowed += 1
            else:
                self.total_blocked += 1
            
            # حفظ في الذاكرة المؤقتة
            self._cache_result(cache_key, result)
            
            return result
            
        except Exception as e:
            return RuleResult(
                action='allow',  # في حالة الخطأ، السماح بالمرور
                rule_id=None,
                rule_name=None,
                matched=False,
                reason=f"خطأ في تطبيق القواعد: {str(e)}",
                processing_time=time.time() - start_time
            )
    
    def _rule_matches(self, rule: FirewallRule, packet_data: Dict[str, Any],
                     analysis_result: Any, ids_result: Dict[str, Any]) -> bool:
        """فحص ما إذا كانت القاعدة تنطبق على الحزمة"""
        
        # فحص البروتوكول
        if rule.protocol:
            packet_protocol = packet_data.get('protocol', '').upper()
            if rule.protocol.upper() != packet_protocol:
                return False
        
        # فحص عنوان IP المصدر
        if rule.source_ip:
            if not self._ip_matches(rule.source_ip, packet_data.get('src_ip', '')):
                return False
        
        # فحص عنوان IP الوجهة
        if rule.destination_ip:
            if not self._ip_matches(rule.destination_ip, packet_data.get('dst_ip', '')):
                return False
        
        # فحص منفذ المصدر
        if rule.source_port:
            if not self._port_matches(rule.source_port, packet_data.get('src_port', 0)):
                return False
        
        # فحص منفذ الوجهة
        if rule.destination_port:
            if not self._port_matches(rule.destination_port, packet_data.get('dst_port', 0)):
                return False
        
        # فحص الاتجاه
        if rule.direction != RuleDirection.BIDIRECTIONAL:
            packet_direction = self._determine_packet_direction(packet_data)
            if rule.direction.value != packet_direction:
                return False
        
        # فحص نتائج IDS
        if ids_result.get('threat_detected', False):
            # إذا كانت هناك تهديدات مكتشفة، تطبيق قواعد أكثر صرامة
            if rule.action == RuleAction.ALLOW and rule.priority > 50:
                return False
        
        return True
    
    def _ip_matches(self, rule_ip: str, packet_ip: str) -> bool:
        """فحص تطابق عنوان IP"""
        try:
            if '/' in rule_ip:
                # شبكة فرعية
                network = ipaddress.IPv4Network(rule_ip, strict=False)
                ip = ipaddress.IPv4Address(packet_ip)
                return ip in network
            else:
                # عنوان واحد
                return rule_ip == packet_ip
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    def _port_matches(self, rule_port, packet_port: int) -> bool:
        """فحص تطابق المنفذ"""
        if isinstance(rule_port, int):
            return rule_port == packet_port
        elif isinstance(rule_port, str):
            # نطاق من المنافذ أو قائمة
            if '-' in rule_port:
                # نطاق (مثل 80-90)
                start, end = map(int, rule_port.split('-'))
                return start <= packet_port <= end
            elif ',' in rule_port:
                # قائمة (مثل 80,443,8080)
                ports = [int(p.strip()) for p in rule_port.split(',')]
                return packet_port in ports
            else:
                # منفذ واحد
                return int(rule_port) == packet_port
        return False
    
    def _determine_packet_direction(self, packet_data: Dict[str, Any]) -> str:
        """تحديد اتجاه الحزمة"""
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        
        try:
            src_addr = ipaddress.IPv4Address(src_ip)
            dst_addr = ipaddress.IPv4Address(dst_ip)
            
            # تحديد الاتجاه بناءً على نوع العناوين
            if src_addr.is_private and not dst_addr.is_private:
                return 'outbound'
            elif not src_addr.is_private and dst_addr.is_private:
                return 'inbound'
            else:
                return 'internal'
                
        except (ipaddress.AddressValueError, ValueError):
            return 'unknown'
    
    def _generate_cache_key(self, packet_data: Dict[str, Any]) -> str:
        """إنشاء مفتاح للذاكرة المؤقتة"""
        key_parts = [
            packet_data.get('protocol', ''),
            packet_data.get('src_ip', ''),
            str(packet_data.get('src_port', 0)),
            packet_data.get('dst_ip', ''),
            str(packet_data.get('dst_port', 0))
        ]
        return '|'.join(key_parts)
    
    def _cache_result(self, cache_key: str, result: RuleResult):
        """حفظ النتيجة في الذاكرة المؤقتة"""
        if len(self.rule_cache) >= self.cache_size:
            # إزالة أقدم عنصر
            oldest_key = next(iter(self.rule_cache))
            del self.rule_cache[oldest_key]
        
        self.rule_cache[cache_key] = result
    
    def add_rule(self, rule_data: Dict[str, Any]) -> bool:
        """إضافة قاعدة جديدة"""
        try:
            rule = FirewallRule(
                id=rule_data['id'],
                name=rule_data['name'],
                enabled=rule_data.get('enabled', True),
                priority=rule_data.get('priority', 100),
                action=RuleAction(rule_data['action']),
                direction=RuleDirection(rule_data.get('direction', 'bidirectional')),
                source_ip=rule_data.get('source_ip'),
                destination_ip=rule_data.get('destination_ip'),
                source_port=rule_data.get('source_port'),
                destination_port=rule_data.get('destination_port'),
                protocol=rule_data.get('protocol'),
                description=rule_data.get('description', ''),
                created_at=time.time(),
                updated_at=time.time()
            )
            
            self.rules.append(rule)
            self.rules.sort(key=lambda x: x.priority)
            
            # تهيئة إحصائيات القاعدة
            self.rule_stats[rule.id] = {
                'matches': 0,
                'last_match': None
            }
            
            # مسح الذاكرة المؤقتة
            self.rule_cache.clear()
            
            return True
            
        except Exception as e:
            print(f"خطأ في إضافة القاعدة: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """إزالة قاعدة"""
        try:
            self.rules = [rule for rule in self.rules if rule.id != rule_id]
            
            if rule_id in self.rule_stats:
                del self.rule_stats[rule_id]
            
            # مسح الذاكرة المؤقتة
            self.rule_cache.clear()
            
            return True
            
        except Exception as e:
            print(f"خطأ في إزالة القاعدة: {e}")
            return False
    
    def update_rule(self, rule_id: str, rule_data: Dict[str, Any]) -> bool:
        """تحديث قاعدة"""
        try:
            for i, rule in enumerate(self.rules):
                if rule.id == rule_id:
                    # تحديث القاعدة
                    updated_rule = FirewallRule(
                        id=rule_id,
                        name=rule_data.get('name', rule.name),
                        enabled=rule_data.get('enabled', rule.enabled),
                        priority=rule_data.get('priority', rule.priority),
                        action=RuleAction(rule_data.get('action', rule.action.value)),
                        direction=RuleDirection(rule_data.get('direction', rule.direction.value)),
                        source_ip=rule_data.get('source_ip', rule.source_ip),
                        destination_ip=rule_data.get('destination_ip', rule.destination_ip),
                        source_port=rule_data.get('source_port', rule.source_port),
                        destination_port=rule_data.get('destination_port', rule.destination_port),
                        protocol=rule_data.get('protocol', rule.protocol),
                        description=rule_data.get('description', rule.description),
                        created_at=rule.created_at,
                        updated_at=time.time()
                    )
                    
                    self.rules[i] = updated_rule
                    self.rules.sort(key=lambda x: x.priority)
                    
                    # مسح الذاكرة المؤقتة
                    self.rule_cache.clear()
                    
                    return True
            
            return False
            
        except Exception as e:
            print(f"خطأ في تحديث القاعدة: {e}")
            return False
    
    def save_rules(self) -> bool:
        """حفظ القواعد في الملف"""
        try:
            rules_data = {
                'rules': [
                    {
                        'id': rule.id,
                        'name': rule.name,
                        'enabled': rule.enabled,
                        'priority': rule.priority,
                        'action': rule.action.value,
                        'direction': rule.direction.value,
                        'source_ip': rule.source_ip,
                        'destination_ip': rule.destination_ip,
                        'source_port': rule.source_port,
                        'destination_port': rule.destination_port,
                        'protocol': rule.protocol,
                        'description': rule.description,
                        'created_at': rule.created_at,
                        'updated_at': rule.updated_at
                    }
                    for rule in self.rules
                ]
            }
            
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                yaml.dump(rules_data, f, default_flow_style=False, allow_unicode=True)
            
            return True
            
        except Exception as e:
            print(f"خطأ في حفظ القواعد: {e}")
            return False
    
    def reload_rules(self) -> bool:
        """إعادة تحميل القواعد"""
        self.rule_cache.clear()
        return self.load_rules()
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """الحصول على قائمة القواعد"""
        return [asdict(rule) for rule in self.rules]
    
    def get_statistics(self) -> Dict[str, Any]:
        """الحصول على إحصائيات القواعد"""
        return {
            'total_rules': len(self.rules),
            'enabled_rules': len([r for r in self.rules if r.enabled]),
            'total_processed': self.total_processed,
            'total_blocked': self.total_blocked,
            'total_allowed': self.total_allowed,
            'cache_size': len(self.rule_cache),
            'rule_stats': self.rule_stats
        }

if __name__ == "__main__":
    # اختبار محرك القواعد
    config = {
        'default_action': 'allow',
        'rules_file': 'firewall_rules.yaml',
        'cache_size': 1000
    }
    
    engine = RulesEngine(config)
    
    # حزمة اختبار
    test_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP'
    }
    
    # تطبيق القواعد
    result = engine.apply_rules(test_packet, None, {})
    
    print(f"الإجراء: {result.action}")
    print(f"القاعدة المطبقة: {result.rule_name}")
    print(f"السبب: {result.reason}")
    print(f"وقت المعالجة: {result.processing_time:.4f} ثانية")
