# {{ title }}

## 漏洞概述
{{ description }}

## 漏洞等级
**{{ severity | upper }}**

## 漏洞类型
{{ type }}

## 影响范围
{% if trigger_path %}
{% for path in trigger_path %}
- {{ path }}
{% endfor %}
{% else %}
待确认
{% endif %}

## 漏洞复现

### 复现步骤
{% if reproduction_steps %}
{% for step in reproduction_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
{% else %}
待补充
{% endif %}

### 测试载荷
```
{{ payload if payload else "N/A" }}
```

### 验证证据
{% if evidence %}
{% for key, value in evidence.items() %}
- **{{ key }}**: {{ value }}
{% endfor %}
{% else %}
待补充
{% endif %}

## 影响评估
{{ impact if impact else "待评估" }}

## 修复建议
{{ fix_suggestion if fix_suggestion else "待补充" }}

## 参考资料
- OWASP: https://owasp.org/
- CWE: https://cwe.mitre.org/

---
*由 Argus 漏洞挖掘系统自动生成 - {{ timestamp }}*
