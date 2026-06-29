# Argus 漏洞挖掘报告

**任务 ID**: {{ task_id }}
**目标**: {{ target_url }}
**生成时间**: {{ timestamp }}
**迭代次数**: {{ iteration_count }}

---

## 摘要

| 指标 | 值 |
|------|------|
| 发现漏洞数 | {{ findings_count }} |
| 验证假设数 | {{ tested_count }} |
| 误报数 | {{ false_positive_count }} |
| 严重(Critical) | {{ severity_critical }} |
| 高危(High) | {{ severity_high }} |
| 中危(Medium) | {{ severity_medium }} |
| 低危(Low) | {{ severity_low }} |

---

## 目标画像

**技术栈**: {{ tech_stack }}

**攻击面**:
{% if attack_surface_endpoints %}
{% for ep in attack_surface_endpoints %}
- {{ ep }}
{% endfor %}
{% else %}
- 未发现有效端点
{% endif %}

**侦察数据**:
- 子域名: {{ subdomains_count }} 个
- 开放端口: {{ open_ports }}

**工具健康度**:
{% if tool_health %}
{% for k, v in tool_health.items() %}
- {{ k }}: {{ v }}
{% endfor %}
{% else %}
- 未收集
{% endif %}

---

## 挖掘过程诊断

{% if findings_count == 0 %}
本次未发现确认漏洞。可能原因与建议：
{% if diagnosis %}
{% for d in diagnosis %}
- {{ d }}
{% endfor %}
{% else %}
- 侦察工具未能提取表单/参数时, 检查 Playwright 与 deep_crawl 健康度
- 仅 GET 探测可能漏掉 POST-only 注入点, 建议确认端点能力模型已启用 POST 探针
{% endif %}
{% endif %}

---

## 漏洞详情

{% if findings %}
{% for f in findings %}
### {{ loop.index }}. {{ f.title }}

| 属性 | 值 |
|------|------|
| 类型 | {{ f.type }} |
| 严重级别 | {{ f.severity }} |
| 关联假设 | {{ f.hypothesis_id }} |
| 工具验证 | {{ f.tool_used if f.tool_used else "纯 LLM 分析" }} |

**描述**: {{ f.description }}

**触发路径**:
{% for path in f.trigger_path %}
- `{{ path }}`
{% endfor %}

**攻击载荷**:
```
{{ f.payload if f.payload else "N/A" }}
```

**复现步骤**:
{% for step in f.reproduction_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

**证据**:
{% for key, value in f.evidence.items() %}
- **{{ key }}**: {{ value }}
{% endfor %}

---

{% endfor %}
{% else %}
*本次扫描未发现确认的漏洞。*
{% endif %}

## 误报记录

{% if false_positives %}
| 假设 ID | 原因 |
|---------|------|
{% for fp in false_positives %}
| {{ fp.hypothesis_id }} | {{ fp.reason }} |
{% endfor %}
{% else %}
*无误报记录。*
{% endif %}

---

## 建议

{% if recommendations %}
{% for rec in recommendations %}
{{ loop.index }}. {{ rec }}
{% endfor %}
{% else %}
- 定期进行安全扫描
- 关注 OWASP Top 10 漏洞类型
- 对发现的漏洞进行修复验证
{% endif %}

---

*由 Argus AI 漏洞挖掘系统自动生成*
