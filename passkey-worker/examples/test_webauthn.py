#!/usr/bin/env python3
"""
Test script for WebAuthn parameter detection

This script tests the WebAuthn parameter detector against known sites
that support passkeys.
"""
import os
import sys
import json
import logging

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.analyzers.webauthn_param_analyzer import WebAuthnParamAnalyzer


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s:%(name)s:%(levelname)s:%(message)s"
)
logger = logging.getLogger(__name__)


# Known sites with passkey support
TEST_SITES = [
    {
        "name": "GitHub",
        "domain": "github.com",
        "login_url": "https://github.com/login"
    },
    {
        "name": "Google",
        "domain": "accounts.google.com",
        "login_url": "https://accounts.google.com"
    },
    {
        "name": "Microsoft",
        "domain": "login.microsoft.com",
        "login_url": "https://login.microsoft.com"
    },
    {
        "name": "PayPal",
        "domain": "paypal.com",
        "login_url": "https://www.paypal.com/signin"
    },
    {
        "name": "Cloudflare",
        "domain": "dash.cloudflare.com",
        "login_url": "https://dash.cloudflare.com/login"
    }
]


def test_site(site: dict, headless: bool = True) -> dict:
    """
    Test WebAuthn parameter detection on a site
    
    Args:
        site: Site configuration dict
        headless: Run in headless mode
        
    Returns:
        Test results
    """
    logger.info(f"\n{'='*60}")
    logger.info(f"Testing: {site['name']} ({site['domain']})")
    logger.info(f"{'='*60}")
    
    config = {
        "browser": {
            "name": "CHROMIUM",
            "headless": headless,
            "timeout_default": 30,
            "timeout_navigation": 30,
            "width": 1920,
            "height": 1080,
            "locale": "en-US",
            "user_agent": "",
            "extensions": [],
            "scripts": [],
            "sleep_after_onload": 3,
            "wait_for_networkidle": True,
            "timeout_networkidle": 10,
            "sleep_after_networkidle": 2
        },
        "login_url": site.get("login_url")
    }
    
    try:
        analyzer = WebAuthnParamAnalyzer(site["domain"], config)
        result = analyzer.start()
        
        # Print summary
        logger.info(f"\nResults for {site['name']}:")
        logger.info(f"  Status: {result['status']}")
        logger.info(f"  WebAuthn Detected: {result['webauthn_params']['detected']}")
        
        if result['webauthn_params']['detected']:
            analysis = result['webauthn_params'].get('analysis', {})
            logger.info(f"  Captures: {analysis.get('total_captures', 0)}")
            logger.info(f"  RP IDs: {analysis.get('rp_ids_seen', [])}")
            logger.info(f"  Algorithms: {analysis.get('algorithm_names', [])}")
            logger.info(f"  User Verification: {analysis.get('user_verification_modes', [])}")
        
        if result['webauthn_params'].get('qr_detection', {}).get('found'):
            logger.info(f"  QR Code Detected: Yes (mobile-only flow)")
        
        return {
            "site": site["name"],
            "success": True,
            "result": result
        }
        
    except Exception as e:
        logger.error(f"Error testing {site['name']}: {e}")
        return {
            "site": site["name"],
            "success": False,
            "error": str(e)
        }


def main():
    """Run tests on all sites"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test WebAuthn parameter detection")
    parser.add_argument("--site", help="Test specific site by name", default=None)
    parser.add_argument("--headful", action="store_true", help="Run in headful mode (visible browser)")
    parser.add_argument("--output", "-o", help="Output file for results", default=None)
    
    args = parser.parse_args()
    
    # Select sites to test
    if args.site:
        sites = [s for s in TEST_SITES if s["name"].lower() == args.site.lower()]
        if not sites:
            logger.error(f"Site '{args.site}' not found")
            logger.info(f"Available sites: {', '.join([s['name'] for s in TEST_SITES])}")
            sys.exit(1)
    else:
        sites = TEST_SITES
    
    # Run tests
    results = []
    for site in sites:
        result = test_site(site, headless=not args.headful)
        results.append(result)
    
    # Summary
    logger.info(f"\n{'='*60}")
    logger.info("SUMMARY")
    logger.info(f"{'='*60}")
    
    successful = sum(1 for r in results if r["success"])
    detected = sum(1 for r in results if r.get("result", {}).get("webauthn_params", {}).get("detected"))
    
    logger.info(f"Total sites tested: {len(results)}")
    logger.info(f"Successful analyses: {successful}")
    logger.info(f"WebAuthn detected: {detected}")
    
    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()

