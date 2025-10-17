#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Haseen Packet Analyzer
محلل حزم البيانات

هذا الملف يحتوي على منطق تحليل حزم البيانات والفحص العميق
This file contains packet analysis and deep inspection logic
"""

import re
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import ipaddress
import socket

@dataclass
class PacketAnalysis:
    """نتائج تحليل الحزمة"""
    packet_type: str
    protocol_info: Dict[str, Any]
    payload_analysis: Dict[str, Any]
    suspicious_patterns: List[str]
    risk_score: int
    analysis_time: float

class PacketAnalyzer:
    """محلل حزم البيانات"""
    
    def __init__(self, config: Dict[str, Any]):
        """تهيئة محلل الحزم"""
        self.config = config
        self.deep_inspection = config.get('deep_inspection', True)
        self.timeout = config.get('timeout', 30)
        
        # أنماط مشبوهة
        self.suspicious_patterns = {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)",
                r"(\bselect\b.*\bfrom\b.*\bwhere\b)",
                r"(\bdrop\b.*\btable\b)",
                r"(\binsert\b.*\binto\b)",
                r"(\bdelete\b.*\bfrom\b)",
                r"('.*or.*'.*=.*')",
                r"(--.*)",
                r"(/\*.*\*/)"
            ],
            'xss': [
                r"(<script.*?>.*?</script>)",
                r"(javascript:.*)",
                r"(on\w+\s*=)",
                r"(<iframe.*?>)",
                r"(<object.*?>)",
                r"(<embed.*?>)"
            ],
            'command_injection': [
                r"(;.*\b(cat|ls|pwd|whoami|id|uname)\b)",
                r"(\|.*\b(cat|ls|pwd|whoami|id|uname)\b)",
                r"(`.*`)",
                r"(\$\(.*\))",
                r"(&&.*\b(cat|ls|pwd|whoami|id|uname)\b)"
            ],
            'path_traversal': [
                r"(\.\.\/)",
                r"(\.\.\\)",
                r"(%2e%2e%2f)",
                r"(%2e%2e%5c)",
                r"(\.\.%2f)",
                r"(\.\.%5c)"
            ],
            'malware_signatures': [
                r"(eval\s*\()",
                r"(exec\s*\()",
                r"(system\s*\()",
                r"(shell_exec\s*\()",
                r"(base64_decode\s*\()",
                r"(gzinflate\s*\()",
                r"(str_rot13\s*\()"
            ]
        }
        
        # منافذ معروفة
        self.known_ports = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'MSSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        # شبكات خاصة
        self.private_networks = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8')
        ]
    
    def analyze(self, packet_data: Dict[str, Any]) -> PacketAnalysis:
        """تحليل حزمة البيانات"""
        start_time = time.time()
        
        try:
            # تحليل البروتوكول
            protocol_info = self._analyze_protocol(packet_data)
            
            # تحليل الحمولة
            payload_analysis = {}
            if self.deep_inspection and 'payload' in packet_data:
                payload_analysis = self._analyze_payload(packet_data['payload'])
            
            # البحث عن الأنماط المشبوهة
            suspicious_patterns = self._detect_suspicious_patterns(packet_data)
            
            # حساب درجة المخاطر
            risk_score = self._calculate_risk_score(
                protocol_info, payload_analysis, suspicious_patterns
            )
            
            # تحديد نوع الحزمة
            packet_type = self._classify_packet(packet_data, protocol_info)
            
            analysis_time = time.time() - start_time
            
            return PacketAnalysis(
                packet_type=packet_type,
                protocol_info=protocol_info,
                payload_analysis=payload_analysis,
                suspicious_patterns=suspicious_patterns,
                risk_score=risk_score,
                analysis_time=analysis_time
            )
            
        except Exception as e:
            # في حالة الخطأ، إرجاع تحليل أساسي
            return PacketAnalysis(
                packet_type='unknown',
                protocol_info={'error': str(e)},
                payload_analysis={},
                suspicious_patterns=[],
                risk_score=0,
                analysis_time=time.time() - start_time
            )
    
    def _analyze_protocol(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """تحليل معلومات البروتوكول"""
        info = {
            'src_ip': packet_data.get('src_ip', ''),
            'dst_ip': packet_data.get('dst_ip', ''),
            'src_port': packet_data.get('src_port', 0),
            'dst_port': packet_data.get('dst_port', 0),
            'protocol': packet_data.get('protocol', ''),
            'size': packet_data.get('size', 0)
        }
        
        # تحليل عناوين IP
        info['src_ip_type'] = self._classify_ip(info['src_ip'])
        info['dst_ip_type'] = self._classify_ip(info['dst_ip'])
        
        # تحليل المنافذ
        info['src_port_service'] = self.known_ports.get(info['src_port'], 'unknown')
        info['dst_port_service'] = self.known_ports.get(info['dst_port'], 'unknown')
        
        # تحليل الاتجاه
        info['direction'] = self._determine_direction(info)
        
        # تحليل حجم الحزمة
        info['size_category'] = self._classify_packet_size(info['size'])
        
        return info
    
    def _classify_ip(self, ip_str: str) -> str:
        """تصنيف عنوان IP"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            
            if ip.is_private:
                return 'private'
            elif ip.is_loopback:
                return 'loopback'
            elif ip.is_multicast:
                return 'multicast'
            elif ip.is_reserved:
                return 'reserved'
            else:
                return 'public'
                
        except (ipaddress.AddressValueError, ValueError):
            return 'invalid'
    
    def _determine_direction(self, protocol_info: Dict[str, Any]) -> str:
        """تحديد اتجاه الحزمة"""
        src_type = protocol_info['src_ip_type']
        dst_type = protocol_info['dst_ip_type']
        
        if src_type == 'private' and dst_type == 'public':
            return 'outbound'
        elif src_type == 'public' and dst_type == 'private':
            return 'inbound'
        elif src_type == 'private' and dst_type == 'private':
            return 'internal'
        else:
            return 'unknown'
    
    def _classify_packet_size(self, size: int) -> str:
        """تصنيف حجم الحزمة"""
        if size < 64:
            return 'tiny'
        elif size < 256:
            return 'small'
        elif size < 1024:
            return 'medium'
        elif size < 1500:
            return 'large'
        else:
            return 'jumbo'
    
    def _analyze_payload(self, payload: str) -> Dict[str, Any]:
        """تحليل حمولة الحزمة"""
        analysis = {
            'length': len(payload),
            'entropy': self._calculate_entropy(payload),
            'printable_ratio': self._calculate_printable_ratio(payload),
            'contains_binary': self._contains_binary_data(payload),
            'hash': hashlib.md5(payload.encode()).hexdigest()
        }
        
        # تحليل المحتوى النصي
        if analysis['printable_ratio'] > 0.8:
            analysis['text_analysis'] = self._analyze_text_content(payload)
        
        return analysis
    
    def _calculate_entropy(self, data: str) -> float:
        """حساب الإنتروبيا للبيانات"""
        if not data:
            return 0.0
        
        # حساب تكرار الأحرف
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # حساب الإنتروبيا
        entropy = 0.0
        data_len = len(data)
        
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _calculate_printable_ratio(self, data: str) -> float:
        """حساب نسبة الأحرف القابلة للطباعة"""
        if not data:
            return 0.0
        
        printable_count = sum(1 for char in data if char.isprintable())
        return printable_count / len(data)
    
    def _contains_binary_data(self, data: str) -> bool:
        """فحص وجود بيانات ثنائية"""
        # البحث عن أحرف غير قابلة للطباعة
        for char in data:
            if ord(char) < 32 and char not in '\t\n\r':
                return True
        return False
    
    def _analyze_text_content(self, text: str) -> Dict[str, Any]:
        """تحليل المحتوى النصي"""
        analysis = {
            'word_count': len(text.split()),
            'line_count': text.count('\n') + 1,
            'contains_urls': bool(re.search(r'https?://\S+', text)),
            'contains_emails': bool(re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)),
            'contains_ips': bool(re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)),
            'language': self._detect_language(text)
        }
        
        return analysis
    
    def _detect_language(self, text: str) -> str:
        """كشف لغة النص"""
        # كشف بسيط للغة العربية والإنجليزية
        arabic_chars = sum(1 for char in text if '\u0600' <= char <= '\u06FF')
        english_chars = sum(1 for char in text if char.isalpha() and char.isascii())
        
        total_chars = arabic_chars + english_chars
        
        if total_chars == 0:
            return 'unknown'
        
        arabic_ratio = arabic_chars / total_chars
        
        if arabic_ratio > 0.5:
            return 'arabic'
        elif english_chars > arabic_chars:
            return 'english'
        else:
            return 'mixed'
    
    def _detect_suspicious_patterns(self, packet_data: Dict[str, Any]) -> List[str]:
        """كشف الأنماط المشبوهة"""
        suspicious = []
        payload = packet_data.get('payload', '')
        
        if not payload:
            return suspicious
        
        # فحص كل نوع من الأنماط المشبوهة
        for pattern_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    suspicious.append(pattern_type)
                    break  # نمط واحد كافي لكل نوع
        
        return suspicious
    
    def _calculate_risk_score(self, protocol_info: Dict[str, Any], 
                            payload_analysis: Dict[str, Any], 
                            suspicious_patterns: List[str]) -> int:
        """حساب درجة المخاطر"""
        score = 0
        
        # نقاط البروتوكول
        if protocol_info.get('direction') == 'inbound':
            score += 10
        
        if protocol_info.get('dst_port_service') == 'unknown':
            score += 15
        
        if protocol_info.get('size_category') == 'jumbo':
            score += 5
        
        # نقاط الحمولة
        if payload_analysis:
            entropy = payload_analysis.get('entropy', 0)
            if entropy > 7:  # إنتروبيا عالية قد تشير لتشفير أو ضغط
                score += 20
            
            if payload_analysis.get('contains_binary', False):
                score += 10
            
            printable_ratio = payload_analysis.get('printable_ratio', 1)
            if printable_ratio < 0.5:
                score += 15
        
        # نقاط الأنماط المشبوهة
        score += len(suspicious_patterns) * 25
        
        # تحديد النتيجة النهائية (0-100)
        return min(score, 100)
    
    def _classify_packet(self, packet_data: Dict[str, Any], 
                        protocol_info: Dict[str, Any]) -> str:
        """تصنيف نوع الحزمة"""
        protocol = protocol_info.get('protocol', '').upper()
        dst_port = protocol_info.get('dst_port', 0)
        src_port = protocol_info.get('src_port', 0)
        
        # تصنيف حسب البروتوكول والمنفذ
        if protocol == 'TCP':
            if dst_port == 80 or src_port == 80:
                return 'http'
            elif dst_port == 443 or src_port == 443:
                return 'https'
            elif dst_port == 22 or src_port == 22:
                return 'ssh'
            elif dst_port == 21 or src_port == 21:
                return 'ftp'
            elif dst_port == 25 or src_port == 25:
                return 'smtp'
            else:
                return 'tcp'
        elif protocol == 'UDP':
            if dst_port == 53 or src_port == 53:
                return 'dns'
            else:
                return 'udp'
        elif protocol == 'ICMP':
            return 'icmp'
        else:
            return 'unknown'

if __name__ == "__main__":
    # اختبار المحلل
    config = {'deep_inspection': True, 'timeout': 30}
    analyzer = PacketAnalyzer(config)
    
    # حزمة اختبار
    test_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'size': 1024,
        'payload': 'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
    }
    
    result = analyzer.analyze(test_packet)
    print(f"نوع الحزمة: {result.packet_type}")
    print(f"درجة المخاطر: {result.risk_score}")
    print(f"الأنماط المشبوهة: {result.suspicious_patterns}")
    print(f"وقت التحليل: {result.analysis_time:.4f} ثانية")
