#!/usr/bin/env python3

import sys
import json
import asyncio
from playwright.async_api import async_playwright

async def run_click_analysis(target_url: str, selector: str = "button, a, input[type='submit']"):
    """
    Spins up a headless Chromium browser, records initial DOM state,
    triggers a click event on matching selectors, and captures outbound network calls.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    async with async_playwright() as p:
        # Launch Chromium headlessly with security sandbox arguments
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = await context.new_page()

        # Track background HTTP/XHR requests triggered by actions
        network_calls = []
        page.on("request", lambda req: network_calls.append({
            "url": req.url,
            "method": req.method,
            "resource_type": req.resource_type
        }))

        try:
            print(f"[+] Navigating to {target_url}...")
            await page.goto(target_url, wait_until="domcontentloaded", timeout=10000)
            
            # Initial Snapshot
            initial_url = page.url
            initial_html_len = len(await page.content())
            await page.screenshot(path="initial_page.png")
            print("[+] Initial screenshot saved to 'initial_page.png'")

            # Clear initial page-load network logs to isolate on-click activity
            network_calls.clear()

            # Perform the On-Click Interaction
            print(f"[+] Locating click target matching selector: '{selector}'")
            element = page.locator(selector).first
            
            click_success = False
            if await element.count() > 0:
                print("[+] Target found! Executing click event...")
                await element.click(timeout=5000)
                click_success = True
                
                # Wait 3 seconds for asynchronous JS / network calls to resolve
                await page.wait_for_timeout(3000)
            else:
                print("[-] No element matching the selector was found.")

            # Post-Click State Snapshot
            final_url = page.url
            final_html_len = len(await page.content())
            await page.screenshot(path="post_click_page.png")
            print("[+] Post-click screenshot saved to 'post_click_page.png'")

            # Analyze State Changes
            results = {
                "initial_url": initial_url,
                "final_url": final_url,
                "url_changed": initial_url != final_url,
                "dom_size_delta": final_html_len - initial_html_len,
                "click_executed": click_success,
                "requests_triggered_by_click": network_calls
            }

            await browser.close()
            return results

        except Exception as e:
            await browser.close()
            return {"error": f"Execution failed: {str(e)}"}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 interactive_analyzer.py <URL> [css_selector]")
        sys.exit(1)

    url_to_test = sys.argv[1]
    target_selector = sys.argv[2] if len(sys.argv) > 2 else "button, a, input[type='submit']"

    report = asyncio.run(run_click_analysis(url_to_test, target_selector))
    print(json.dumps(report, indent=2))