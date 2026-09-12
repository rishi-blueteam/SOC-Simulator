#!/usr/bin/env python3

import sys
import json
import asyncio
import os
import re
from datetime import datetime
from urllib.parse import urlparse
from playwright.async_api import async_playwright

def extract_domain(url: str) -> str:
    """Extracts clean hostname/domain from a given URL."""
    try:
        return urlparse(url).netloc
    except Exception:
        return ""

def sanitize_filename(name: str) -> str:
    """Sanitizes text to make it safe for filesystem paths."""
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', name)[:50]

async def start_interactive_session(target_url: str):
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    os.environ["DISPLAY"] = ":99"

    # Setup Dynamic Output Filenames and Folder Structure
    now = datetime.now()
    date_str = now.strftime("%d-%m-%y")          # Formats as dd/mm/yy (e.g., 09-09-26)
    timestamp_folder = now.strftime("%Y%m%d_%H%M%S")
    
    telemetry_filename = f"telemetry_{date_str}_log.json"
    screenshots_dir = f"session_screenshots_{timestamp_folder}"
    os.makedirs(screenshots_dir, exist_ok=True)

    print(f"[+] Output Folder Created: ./{screenshots_dir}/")
    print(f"[+] Telemetry File Target: {telemetry_filename}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-gpu",
                "--disable-software-rasterizer",
                "--window-size=1280,1024",
                "--start-maximized"
            ]
        )
        
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 1024}
        )

        telemetry = {
            "session_summary": {
                "original_url": target_url,
                "original_domain": extract_domain(target_url),
                "final_landed_url": "",
                "final_landed_domain": "",
                "redirect_trap_detected": False,
                "redirect_chain": []
            },
            "captured_screenshots": [],
            "clicks": [],
            "network_requests": [],
            "console_logs": [],
            "downloads": [],
            "status": "UNKNOWN"
        }

        # Global screenshot counter for chronological ordering
        screenshot_counter = 0

        async def capture_page_snapshot(page_obj, trigger_reason: str):
            """Captures and indexes full-page PNG screenshots."""
            nonlocal screenshot_counter
            screenshot_counter += 1
            domain = extract_domain(page_obj.url) or "unknown"
            filename = f"step_{screenshot_counter:02d}_{sanitize_filename(domain)}.png"
            filepath = os.path.join(screenshots_dir, filename)
            
            try:
                # Wait 500ms for animations/render to settle before snapping
                await asyncio.sleep(0.5)
                await page_obj.screenshot(path=filepath, full_page=True)
                
                snapshot_meta = {
                    "step": screenshot_counter,
                    "reason": trigger_reason,
                    "url": page_obj.url,
                    "domain": domain,
                    "file_path": filepath,
                    "timestamp": datetime.now().isoformat()
                }
                telemetry["captured_screenshots"].append(snapshot_meta)
                print(f"[+] Snapshot [{screenshot_counter:02d}] Saved: {filepath} ({trigger_reason})")
            except Exception as e:
                pass

        # 1. Thread-safe RPC Callback for Clicks (Bound to Context)
        async def handle_click_event(click_data):
            try:
                clicked_href = click_data.get("href") or ""
                target_domain = extract_domain(clicked_href) if clicked_href else "INLINE_ACTION"
                
                enhanced_click = {
                    "element_tag": click_data.get("tag"),
                    "element_text": click_data.get("text"),
                    "element_id": click_data.get("id"),
                    "clicked_href": clicked_href,
                    "target_domain": target_domain,
                    "current_page_url": click_data.get("current_url", ""),
                    "current_page_domain": extract_domain(click_data.get("current_url", "")),
                    "timestamp": click_data.get("timestamp")
                }
                
                telemetry["clicks"].append(enhanced_click)
                print(f"[+] Click Recorded: '{enhanced_click['element_text']}' -> Target: [{target_domain}]")
            except Exception:
                pass

        await context.expose_function("reportClickToPython", handle_click_event)

        # 2. Persistent Init Script attached to Context
        init_script = """
        document.addEventListener('click', e => {
            let elem = e.target;
            let interactive = elem.closest('a, button, input[type="submit"]') || elem;
            
            try {
                window.reportClickToPython({
                    tag: interactive.tagName,
                    id: interactive.id || '',
                    className: interactive.className || '',
                    text: (interactive.innerText || interactive.value || '').substring(0, 100).trim(),
                    href: interactive.href || interactive.getAttribute('href') || null,
                    current_url: window.location.href,
                    timestamp: new Date().toISOString()
                });
            } catch(err) {}
        }, true);
        """
        await context.add_init_script(init_script)

        page = await context.new_page()

        # Automate Screenshotting on every new page navigation
        async def on_frame_navigated(frame):
            if frame == page.main_frame:
                await capture_page_snapshot(page, f"Navigated to {extract_domain(page.url)}")

        page.on("framenavigated", lambda frame: asyncio.create_task(on_frame_navigated(frame)))

        # 3. Response & Redirect Listener
        async def handle_response(response):
            try:
                if 300 <= response.status <= 399:
                    redirect_target = response.headers.get("location", "")
                    telemetry["session_summary"]["redirect_chain"].append({
                        "from_url": response.url,
                        "from_domain": extract_domain(response.url),
                        "status_code": response.status,
                        "to_url": redirect_target,
                        "to_domain": extract_domain(redirect_target)
                    })

                req = response.request
                telemetry["network_requests"].append({
                    "url": req.url,
                    "domain": extract_domain(req.url),
                    "method": req.method,
                    "resource_type": req.resource_type,
                    "status_code": response.status,
                    "security_details": {
                        "is_https": req.url.startswith("https://"),
                        "security_headers": {
                            "content-security-policy": response.headers.get("content-security-policy", "MISSING"),
                            "strict-transport-security": response.headers.get("strict-transport-security", "MISSING"),
                            "x-frame-options": response.headers.get("x-frame-options", "MISSING")
                        }
                    }
                })
            except Exception:
                pass

        page.on("response", lambda res: asyncio.create_task(handle_response(res)))

        page.on("console", lambda msg: telemetry["console_logs"].append({
            "type": msg.type,
            "text": msg.text
        }))

        page.on("download", lambda d: telemetry["downloads"].append({
            "url": d.url,
            "download_domain": extract_domain(d.url),
            "suggested_filename": d.suggested_filename
        }))

        print(f"[+] Navigating to {target_url}...")
        
        try:
            await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            telemetry["status"] = "ONLINE"
        except Exception as e:
            print(f"\n[-] Navigation Failed: Domain is offline or unresolvable: {e}\n")
            telemetry["status"] = "OFFLINE_OR_UNRESOLVABLE"
            with open(telemetry_filename, "w") as f:
                json.dump(telemetry, f, indent=2)
            await browser.close()
            return

        print("\n" + "="*60)
        print("  NOVNC LIVE INTERACTIVE SESSION ACTIVE")
        print("="*60)
        print("Interact with the page in noVNC.")
        print("Press Ctrl+C in this terminal when finished to stop & save.")
        print("="*60 + "\n")

        # Keep session alive
        try:
            while True:
                await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n[+] Session interrupt received. Finalizing telemetry...")

        # Safe Session Shutdown Sequence
        try:
            final_url = page.url
            final_domain = extract_domain(final_url)
            orig_domain = telemetry["session_summary"]["original_domain"]

            telemetry["session_summary"]["final_landed_url"] = final_url
            telemetry["session_summary"]["final_landed_domain"] = final_domain
            
            if orig_domain and final_domain and orig_domain.lower() != final_domain.lower():
                telemetry["session_summary"]["redirect_trap_detected"] = True

            # Final session closure snapshot
            await capture_page_snapshot(page, "Final Session State")
        except Exception as e:
            print(f"[-] Could not capture final screenshot: {e}")

        # Save JSON File with system date naming convention
        with open(telemetry_filename, "w") as f:
            json.dump(telemetry, f, indent=2)

        print(f"[+] Telemetry report successfully saved to '{telemetry_filename}'")
        print(f"[+] All snapshots stored inside folder: './{screenshots_dir}/'")
        
        try:
            await browser.close()
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 manual_analyzer.py <URL>")
        sys.exit(1)

    asyncio.run(start_interactive_session(sys.argv[1]))