#!/usr/bin/env python3
"""
CLI tool for testing WebAuthn parameter detection
"""
import os
import sys
import json
import argparse
import logging
from modules.analyzers.webauthn_param_analyzer import WebAuthnParamAnalyzer


# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s:%(name)s:%(levelname)s:%(message)s"
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="WebAuthn Parameter Detection Tool")
    parser.add_argument("domain", help="Domain to analyze (e.g., example.com)")
    parser.add_argument("--login-url", help="Direct login page URL", default=None)
    parser.add_argument("--output", "-o", help="Output JSON file", default=None)
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--headless", action="store_true", default=True, help="Run in headless mode")
    parser.add_argument("--timeout", type=int, default=30, help="Navigation timeout in seconds")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Build config
    config = {
        "browser": {
            "name": "CHROMIUM",
            "headless": args.headless,
            "timeout_default": args.timeout,
            "timeout_navigation": args.timeout,
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
        "login_url": args.login_url
    }
    
    logger.info(f"Starting WebAuthn parameter analysis for: {args.domain}")
    
    try:
        analyzer = WebAuthnParamAnalyzer(args.domain, config)
        result = analyzer.start()
        
        # Print results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Results written to: {args.output}")
        else:
            print(json.dumps(result, indent=2))
        
        # Summary
        if "webauthn_params" in result:
            params = result["webauthn_params"]
            logger.info(f"WebAuthn calls detected: {len(params.get('captures', []))}")
            for i, capture in enumerate(params.get('captures', []), 1):
                logger.info(f"  Capture {i}: {capture.get('type')} on {capture.get('url')}")
        
        logger.info("Analysis complete!")
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()

