#!/usr/bin/env python3
"""
Generate Professional Report from WAF Logs
"""

import json
from collections import Counter
from datetime import datetime

def analyze_logs():
    """Analyze WAF logs and generate statistics"""
    
    try:
        with open('logs/waf_log.txt', 'r') as f:
            all_logs = [json.loads(line) for line in f if line.strip()]
    except:
        all_logs = []
    
    try:
        with open('logs/blocked_attacks.txt', 'r') as f:
            blocked_logs = [json.loads(line) for line in f if line.strip()]
    except:
        blocked_logs = []
    
    # Calculate statistics
    total_requests = len(all_logs)
    total_blocked = len(blocked_logs)
    total_allowed = total_requests - total_blocked
    detection_rate = (total_blocked / max(total_requests, 1)) * 100
    
    # Count attack types
    attack_types = Counter([log['attack_type'] for log in blocked_logs if log['attack_type']])
    
    # Count IPs
    attacker_ips = Counter([log['client_ip'] for log in blocked_logs])
    
    return {
        'total_requests': total_requests,
        'total_blocked': total_blocked,
        'total_allowed': total_allowed,
        'detection_rate': detection_rate,
        'attack_types': dict(attack_types),
        'attacker_ips': dict(attacker_ips)
    }

def generate_html_report(stats):
    """Create HTML dashboard"""
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SentinelShield WAF Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        .metric {{
            display: inline-block;
            margin: 20px;
            padding: 20px;
            background: #ecf0f1;
            border-radius: 5px;
            min-width: 200px;
        }}
        .metric-value {{
            font-size: 36px;
            font-weight: bold;
            color: #e74c3c;
        }}
        .metric-label {{
            font-size: 14px;
            color: #7f8c8d;
            text-transform: uppercase;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th {{
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .analysis {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }}
        .recommendation {{
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 20px 0;
        }}
        .todo {{
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 10px 0;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SentinelShield WAF Security Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Author:</strong> [Your Name]</p>
        
        <h2>📊 Key Metrics</h2>
        <div class="metric">
            <div class="metric-value">{stats['total_requests']}</div>
            <div class="metric-label">Total Requests</div>
        </div>
        <div class="metric">
            <div class="metric-value">{stats['total_blocked']}</div>
            <div class="metric-label">Blocked Attacks</div>
        </div>
        <div class="metric">
            <div class="metric-value">{stats['detection_rate']:.1f}%</div>
            <div class="metric-label">Detection Rate</div>
        </div>
        
        <h2>🎯 Attack Categories</h2>
        <table>
            <tr>
                <th>Attack Type</th>
                <th>Count</th>
                <th>Percentage</th>
            </tr>
"""
    
    for attack_type, count in sorted(stats['attack_types'].items(), key=lambda x: x[1], reverse=True):
        percentage = (count / max(stats['total_blocked'], 1)) * 100
        html += f"""
            <tr>
                <td>{attack_type.replace('_', ' ').title()}</td>
                <td>{count}</td>
                <td>{percentage:.1f}%</td>
            </tr>
"""
    
    html += """
        </table>
        
        <h2>🚨 Top Attacker IPs</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <th>Attack Count</th>
            </tr>
"""
    
    for ip, count in sorted(stats['attacker_ips'].items(), key=lambda x: x[1], reverse=True)[:10]:
        html += f"""
            <tr>
                <td>{ip}</td>
                <td>{count}</td>
            </tr>
"""
    
    html += """
        </table>
        
        <h2>📝 My Analysis</h2>
        <div class="todo">
            <strong>⚠️ IMPORTANT:</strong> You MUST fill in this section with your own analysis!
        </div>
        <div class="analysis">
            <h3>Key Findings:</h3>
            <ol>
                <li><strong>Detection Effectiveness:</strong> 
                    <div class="todo">[Write your analysis: Is 60-70% detection good? What does it mean?]</div>
                </li>
                <li><strong>Most Common Attack:</strong> 
                    <div class="todo">[Identify which attack type was most common and explain why attackers use it]</div>
                </li>
                <li><strong>False Positives:</strong> 
                    <div class="todo">[Were any legitimate requests blocked? Give examples and explain why]</div>
                </li>
                <li><strong>False Negatives:</strong> 
                    <div class="todo">[Did any attacks get through? Test and document them]</div>
                </li>
                <li><strong>Pattern Effectiveness:</strong>
                    <div class="todo">[Which patterns worked well? Which need improvement?]</div>
                </li>
            </ol>
        </div>
        
        <h2>💡 Improvements I Implemented</h2>
        <div class="todo">
            <strong>⚠️ IMPORTANT:</strong> Document YOUR improvements here!
        </div>
        <div class="recommendation">
            <h3>New Detection Rules I Added:</h3>
            <div class="todo">
                <p>[Add code of your new rules here, for example:]</p>
                <pre>
'new_attack': [
    r"pattern_here",  # Explanation
]
                </pre>
                <p>[Explain WHY you added this rule]</p>
                <p>[Show test results proving it works]</p>
            </div>
            
            <h3>Optimizations I Made:</h3>
            <div class="todo">
                <ol>
                    <li>[Optimization 1]: [Explain what and why]</li>
                    <li>[Optimization 2]: [Explain what and why]</li>
                </ol>
            </div>
            
            <h3>Bugs I Fixed:</h3>
            <div class="todo">
                <ol>
                    <li>[Bug 1]: [What was wrong and how you fixed it]</li>
                    <li>[Bug 2]: [What was wrong and how you fixed it]</li>
                </ol>
            </div>
        </div>
        
        <h2>🔬 Testing Analysis</h2>
        <div class="analysis">
            <h3>Test Results Breakdown:</h3>
            <div class="todo">
                <p><strong>SQL Injection Tests:</strong> [X passed / Y failed - explain why]</p>
                <p><strong>XSS Tests:</strong> [X passed / Y failed - explain why]</p>
                <p><strong>LFI Tests:</strong> [X passed / Y failed - explain why]</p>
                <p><strong>Command Injection Tests:</strong> [X passed / Y failed - explain why]</p>
            </div>
            
            <h3>Interesting Test Cases:</h3>
            <div class="todo">
                <ol>
                    <li><strong>Unexpected Pass:</strong> [Test that surprisingly passed - why?]</li>
                    <li><strong>Unexpected Fail:</strong> [Test that surprisingly failed - why?]</li>
                    <li><strong>Edge Case:</strong> [Interesting edge case you found]</li>
                </ol>
            </div>
        </div>
        
        <h2>🎯 Recommendations for Future</h2>
        <div class="recommendation">
            <h3>Short-term Improvements (1-2 weeks):</h3>
            <div class="todo">
                <ol>
                    <li>[Improvement 1 - explain what and why]</li>
                    <li>[Improvement 2 - explain what and why]</li>
                    <li>[Improvement 3 - explain what and why]</li>
                </ol>
            </div>
            
            <h3>Long-term Enhancements:</h3>
            <div class="todo">
                <ol>
                    <li>[Enhancement 1 - more advanced feature]</li>
                    <li>[Enhancement 2 - more advanced feature]</li>
                    <li>[Enhancement 3 - more advanced feature]</li>
                </ol>
            </div>
        </div>
        
        <h2>🎓 What I Learned</h2>
        <div class="analysis">
            <h3>Technical Skills:</h3>
            <div class="todo">
                <ul>
                    <li>[Skill 1: e.g., "How regex patterns work for security"]</li>
                    <li>[Skill 2: e.g., "Flask request interception"]</li>
                    <li>[Skill 3: e.g., "Understanding HTTP structure"]</li>
                </ul>
            </div>
            
            <h3>Security Concepts:</h3>
            <div class="todo">
                <ul>
                    <li>[Concept 1: e.g., "Why SQL injection is dangerous"]</li>
                    <li>[Concept 2: e.g., "How XSS affects users"]</li>
                    <li>[Concept 3: e.g., "Defense in depth principle"]</li>
                </ul>
            </div>
            
            <h3>Challenges Overcome:</h3>
            <div class="todo">
                <ol>
                    <li><strong>Challenge:</strong> [Problem you faced]
                        <br><strong>Solution:</strong> [How you solved it]
                    </li>
                    <li><strong>Challenge:</strong> [Problem you faced]
                        <br><strong>Solution:</strong> [How you solved it]
                    </li>
                </ol>
            </div>
        </div>
        
        <h2>📚 References</h2>
        <div class="analysis">
            <div class="todo">
                <p>List resources you used:</p>
                <ul>
                    <li>OWASP Top 10: [URL if you referenced it]</li>
                    <li>Flask Documentation: [Specific pages you used]</li>
                    <li>Regex Tutorial: [If you used one]</li>
                    <li>[Any other resources]</li>
                </ul>
            </div>
        </div>
        
        <hr style="margin: 40px 0;">
        <p style="text-align: center; color: #7f8c8d;">
            SentinelShield Educational WAF | Internship Project | [Your Name]
        </p>
    </div>
</body>
</html>
"""
    
    return html

def main():
    print("\n" + "="*70)
    print("  Generating SentinelShield Report...")
    print("="*70 + "\n")
    
    # Analyze logs
    print("[*] Analyzing logs...")
    stats = analyze_logs()
    
    # Generate HTML report
    print("[*] Creating HTML report...")
    html = generate_html_report(stats)
    
    with open('reports/dashboard.html', 'w') as f:
        f.write(html)
    
    # Print summary
    print("\n[✓] Report generated successfully!")
    print(f"\n📊 Summary:")
    print(f"   Total Requests: {stats['total_requests']}")
    print(f"   Blocked: {stats['total_blocked']}")
    print(f"   Detection Rate: {stats['detection_rate']:.1f}%")
    print(f"\n[→] Open report: firefox reports/dashboard.html")
    print("\n⚠️  IMPORTANT: The report has sections marked [TODO]")
    print("   You MUST fill these in with your own analysis!")
    print("="*70 + "\n")

if __name__ == '__main__':
    main()
