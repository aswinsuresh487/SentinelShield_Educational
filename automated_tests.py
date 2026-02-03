#!/usr/bin/env python3
"""
Automated Test Suite for SentinelShield
Sends multiple attack payloads and records results
"""

import requests
import json
from datetime import datetime

# Base URL (your WAF)
BASE_URL = "http://localhost:5000"

# Test cases: (name, url, expected_blocked)
TEST_CASES = [
    # Normal requests - should be ALLOWED
    ("Normal Homepage", "/index.php", False),
    ("Normal About Page", "/about.php?page=info", False),
    
    # SQL Injection - should be BLOCKED
    ("SQLi: OR clause", "/user.php?id=1' OR '1'='1", True),
    ("SQLi: UNION", "/user.php?id=1 UNION SELECT * FROM users", True),
    ("SQLi: Comment", "/user.php?id=1' --", True),
    
    # XSS - should be BLOCKED
    ("XSS: Script tag", "/search.php?q=<script>alert('XSS')</script>", True),
    ("XSS: Event handler", "/page.php?name=<img src=x onerror=alert(1)>", True),
    ("XSS: JavaScript protocol", "/link.php?url=javascript:alert(1)", True),
    
    # LFI - should be BLOCKED
    ("LFI: Directory traversal", "/file.php?page=../../../../etc/passwd", True),
    ("LFI: PHP wrapper", "/file.php?page=php://filter/resource=index", True),
    
    # Command Injection - should be BLOCKED
    ("CMDi: Semicolon", "/ping.php?host=127.0.0.1; cat /etc/passwd", True),
    ("CMDi: Pipe", "/ping.php?host=127.0.0.1 | whoami", True),
]

def run_tests():
    """Run all test cases and generate report"""
    
    print("\n" + "="*70)
    print("  SentinelShield Automated Testing")
    print("="*70 + "\n")
    
    results = {
        'total': 0,
        'passed': 0,
        'failed': 0,
        'blocked': 0,
        'allowed': 0,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'tests': []
    }
    
    for test_name, endpoint, expected_blocked in TEST_CASES:
        results['total'] += 1
        
        print(f"Testing: {test_name}")
        print(f"  URL: {endpoint}")
        
        try:
            # Send request
            response = requests.get(BASE_URL + endpoint, timeout=5)
            
            # Check if blocked (403 = Forbidden)
            was_blocked = (response.status_code == 403)
            
            # Did we get expected result?
            test_passed = (was_blocked == expected_blocked)
            
            if test_passed:
                results['passed'] += 1
                status = "✓ PASS"
            else:
                results['failed'] += 1
                status = "✗ FAIL"
            
            if was_blocked:
                results['blocked'] += 1
            else:
                results['allowed'] += 1
            
            print(f"  Expected: {'BLOCKED' if expected_blocked else 'ALLOWED'}")
            print(f"  Actual: {'BLOCKED' if was_blocked else 'ALLOWED'}")
            print(f"  Result: {status}\n")
            
            # Save test result
            results['tests'].append({
                'name': test_name,
                'endpoint': endpoint,
                'expected_blocked': expected_blocked,
                'was_blocked': was_blocked,
                'passed': test_passed,
                'status_code': response.status_code
            })
        
        except Exception as e:
            print(f"  ✗ ERROR: {e}\n")
            results['failed'] += 1
    
    # Print summary
    print("="*70)
    print("  TEST SUMMARY")
    print("="*70)
    print(f"Total Tests: {results['total']}")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"Blocked: {results['blocked']}")
    print(f"Allowed: {results['allowed']}")
    print(f"Success Rate: {(results['passed']/results['total'])*100:.1f}%")
    print("="*70 + "\n")
    
    # Save results
    with open('tests/test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("[✓] Results saved to: tests/test_results.json")

if __name__ == '__main__':
    run_tests()
